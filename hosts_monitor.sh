cat >/var/tmp/hosts_monitor.py <<-EOF
#!/usr/bin/env python3
"""
bypass.helloworld.com 域名 IP 监控与自动替换脚本

流程：
  1. 从 /etc/hosts 读取 TARGET_DOMAIN 当前绑定的 IP
  2. 发送 PING_COUNT 个快速 ping 包
  3. 若全部丢包 → 触发 IP 替换任务：
       a. 通过 Cloudflare DNS-over-HTTPS 获取域名最新 A 记录列表
       b. 随机打乱顺序
       c. 从列表 [0] 开始逐一 ping，第一个可达 IP 回写到 hosts
"""

import os
import re
import time
import random
import logging
import platform
import subprocess
from typing import List, Optional

import requests


# ─── 配置 ─────────────────────────────────────────────────────────────────────

TARGET_DOMAIN  = "bypass.aws"
AVAILABLE_DOMAINS = "available.773330.xyz"
HOSTS_FILE     = "/etc/hosts"
DOH_URL        = "https://cloudflare-dns.com/dns-query"

CHECK_INTERVAL = 30   # 监控主循环间隔（秒）
PING_COUNT     = 2    # 每次 ping 的包数
PING_TIMEOUT   = 1    # 单包等待超时（秒）
DOH_TIMEOUT    = 10   # Cloudflare DoH 请求超时（秒）

LOG_FILE       = "/var/log/hosts_monitor.log"

# ─── 日志 ─────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)


# ─── hosts 文件操作 ────────────────────────────────────────────────────────────

def get_ip_from_hosts(domain: str, hosts_file: str = HOSTS_FILE) -> Optional[str]:
    """从 hosts 文件中读取域名当前绑定的 IP，找不到返回 None。"""
    try:
        with open(hosts_file, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                parts = stripped.split()
                # parts[0] = IP, parts[1:] = 域名列表
                if len(parts) >= 2 and domain in parts[1:]:
                    return parts[0]
    except Exception as e:
        logger.error(f"读取 hosts 文件失败: {e}")
    return None


def replace_ip_in_hosts(domain: str, new_ip: str,
                         hosts_file: str = HOSTS_FILE) -> bool:
    """
    将 hosts 文件中 domain 对应的 IP 替换为 new_ip。
    若 domain 不存在则追加新行。
    """
    try:
        with open(hosts_file, "r", encoding="utf-8") as f:
            lines = f.readlines()

        new_lines: List[str] = []
        replaced = False
        # 匹配：可选缩进 + IP + 空白 + 域名（域名须单独出现，不能是前缀）
        pattern = re.compile(
            r"^(\s*)([\d\.a-fA-F:]+)(\s+)((?:\S+\s+)*?"
            + re.escape(domain)
            + r"(?:\s+\S+)*\s*)$"
        )

        for line in lines:
            m = pattern.match(line.rstrip("\n"))
            if m:
                # 保留原行其他域名，仅替换 IP 部分
                new_line = f"{new_ip}{m.group(3)}{m.group(4)}\n"
                new_lines.append(new_line)
                replaced = True
                logger.info(
                    f"hosts 替换: {m.group(2).strip()} -> {new_ip}  ({domain})"
                )
            else:
                new_lines.append(line)

        if not replaced:
            new_lines.append(f"{new_ip} {domain}\n")
            logger.info(f"hosts 新增条目: {new_ip}  ({domain})")

        with open(hosts_file, "w", encoding="utf-8") as f:
            f.writelines(new_lines)

        return True

    except PermissionError:
        logger.error("写入 hosts 文件失败：权限不足（需要 root / 管理员权限）")
    except Exception as e:
        logger.error(f"写入 hosts 文件失败: {e}")
    return False


# ─── Ping ──────────────────────────────────────────────────────────────────────

def ping(ip: str, count: int = PING_COUNT,
         timeout: int = PING_TIMEOUT) -> bool:
    """
    向 ip 发送 count 个 ICMP 包。
    返回 True 表示至少收到 1 个回包（可达），False 表示全部丢包。
    Linux 下使用 -i 0.2 加快发包速度。
    """
    system = platform.system().lower()

    if system == "windows":
        # -n count  -w timeout_ms
        cmd = ["ping", "-n", str(count), "-w", str(timeout * 1000), ip]
    else:
        # -c count  -W timeout_per_packet  -i interval(0.2s 快速模式)
        cmd = ["ping", "-c", str(count), "-W", str(timeout), "-i", "0.2", ip]

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout * count + 5,
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        logger.warning(f"ping {ip} 命令超时")
        return False
    except Exception as e:
        logger.error(f"ping {ip} 执行出错: {e}")
        return False


# ─── Cloudflare DNS-over-HTTPS ────────────────────────────────────────────────

def resolve_via_doh(domain: str) -> List[str]:
    """
    通过 Cloudflare DoH (dns-query JSON API) 查询 domain 的 A 记录。
    返回 IP 字符串列表；查询失败返回空列表。
    """
    try:
        resp = requests.get(
            DOH_URL,
            params={"name": domain, "type": "A"},
            headers={"Accept": "application/dns-json"},
            timeout=DOH_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()

        if data.get("Status") != 0:
            logger.error(
                f"DoH 查询返回异常状态 Status={data.get('Status')}: {domain}"
            )
            return []

        ip_list = [
            record["data"]
            for record in data.get("Answer", [])
            if record.get("type") == 1  # type=1 即 A 记录
        ]

        logger.info(f"DoH 解析 {domain} → {len(ip_list)} 条: {ip_list}")
        return ip_list

    except Exception as e:
        logger.error(f"DoH 请求失败: {e}")
        return []


# ─── IP 替换任务 ───────────────────────────────────────────────────────────────

def find_and_replace_ip(domain: str) -> bool:
    """
    IP 替换完整流程：
      1. DoH 查询最新 IP 列表
      2. 随机乱序
      3. 从 [0] 开始逐一 ping，首个可达 IP 写入 hosts
    成功返回 True，失败返回 False。
    """
    logger.info(f"[替换任务] 开始处理域名: {domain}")

    ip_list = resolve_via_doh(domain)
    if not ip_list:
        logger.error("[替换任务] DoH 未返回任何 IP，无法替换")
        return False

    random.shuffle(ip_list)
    logger.info(f"[替换任务] 乱序后候选列表: {ip_list}")

    for idx, ip in enumerate(ip_list):
        logger.info(f"[替换任务] 测试 [{idx}] {ip} ...")
        if ping(ip, count=PING_COUNT, timeout=PING_TIMEOUT):
            logger.info(f"[替换任务] {ip} 可达，回写 hosts")
            return replace_ip_in_hosts(TARGET_DOMAIN, ip)
        else:
            logger.warning(f"[替换任务] {ip} 不可达，尝试下一个")

    logger.error("[替换任务] 所有候选 IP 均不可达，本次替换失败")
    return False


# ─── 主监控循环 ────────────────────────────────────────────────────────────────

def monitor_loop() -> None:
    """
    持续监控循环：
      - 读取 hosts 中 TARGET_DOMAIN 的当前 IP
      - 发送 PING_COUNT 个快速 ping
      - 全部丢包 → 触发 find_and_replace_ip()
      - 每 CHECK_INTERVAL 秒执行一次
    """
    logger.info(
        f"监控启动 | 域名: {TARGET_DOMAIN} | "
        f"ping 包数: {PING_COUNT} | 检查间隔: {CHECK_INTERVAL}s"
    )

    while True:
        try:
            current_ip = get_ip_from_hosts(TARGET_DOMAIN)

            if not current_ip:
                logger.warning(
                    f"hosts 中未找到 {TARGET_DOMAIN} 的解析记录，跳过本次检查"
                )
            else:
                logger.info(f"检测 {TARGET_DOMAIN} → {current_ip}")
                if ping(current_ip, count=PING_COUNT, timeout=PING_TIMEOUT):
                    logger.info(f"ping {current_ip} 正常，无需替换")
                else:
                    logger.warning(
                        f"ping {current_ip} 全部丢包，触发 IP 替换任务"
                    )
                    success = find_and_replace_ip(AVAILABLE_DOMAINS)
                    if success:
                        logger.info("IP 替换完成")
                    else:
                        logger.error("IP 替换失败，将在下次循环重试")

        except Exception as e:
            logger.exception(f"监控循环发生未预期异常: {e}")

        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    monitor_loop()
EOF

nohup python3 /var/tmp/hosts_monitor.py >/dev/null 2>&1 &
cat >>/var/spool/cron/crontabs/root <<-EOF
@reboot nohup python3 /var/tmp/hosts_monitor.py >/dev/null 2>&1 &
EOF
