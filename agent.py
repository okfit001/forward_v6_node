#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IP阻断检测客户端 (C/S架构)

功能：
1. 每3分钟执行 nc -zv4 -w3 <domain> 443，域名从候选列表随机选取
2. 首次检测阻断后，用另一个域名二次确认；二次确认也阻断才上报
   - 首次阻断的域名在下次轮询时跳过
   - 若可用域名为空（全被跳过）或无其他域名可做二次确认，则直接上报
3. 启动回调监听端口，等待服务器在换IP后发来重检指令
4. 执行重检并将结果返回服务器（支持多轮，对应服务器最多1次重试）
5. 连接服务器支持 SOCKS5 代理，自动筛选可用代理并随机选取
"""

import os
import sys
import socket
import time
import random
import logging
import subprocess
import threading
import queue
import requests
from datetime import datetime
from typing import Optional

try:
    import socks
    SOCKS_AVAILABLE = True
except ImportError:
    SOCKS_AVAILABLE = False

# 确保能找到同目录的 crypto_utils
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from crypto_utils import SecureChannel

# ==================== 配置 ====================
CONFIG = {
    'server_host': '167.99.73.79',       # 服务器IP（按需修改）
    'server_port': 9988,              # 服务器监听端口
    'callback_port': 26,            # 本机回调监听端口（服务器换完IP后连回来）
    'check_interval': 180,            # nc检测间隔（秒，默认3分钟）
    'nc_port': 443,                   # nc检测端口
    # 等待服务器在本轮回调的最大时间（秒）
    # 需覆盖：服务器换IP + 等待新IP生效(20s) + 查询新IP(最多60s) + 连通测试
    # 两轮合计约 300s
    'callback_session_timeout': 300,
    # SOCKS5代理列表，格式：
    #   'host:port'
    #   'host:port:username:password'
    # 为空列表则直连
    'socks_list': [
        # '127.0.0.1:1080',
        # '192.168.1.1:7890:user:pass',
        '34.220.8.240:37000:poweroff:OzOzD_4OEoKi0A5c',
        '54.187.179.85:37000:poweroff:OzOzD_4OEoKi0A5c',
    ],
    'proxy_test_timeout': 5,          # 代理可用性检测超时（秒）
    'report_timeout': 15,             # 上报服务器的连接超时（秒）
}

# ==================== 日志 ====================
def setup_client_logging():
    log = logging.getLogger('ip_check_client')
    log.setLevel(logging.INFO)
    log.handlers.clear()
    fmt = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    fh = logging.FileHandler('ip_check_client.log', encoding='utf-8')
    fh.setFormatter(fmt)
    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    log.addHandler(fh)
    log.addHandler(ch)
    return log

logger = setup_client_logging()

# ==================== 检测域名池 ====================
NC_DOMAINS = [
    'www.baidu.com',
    'game.163.com',
    'www.taobao.com',
    'www.dbankcdn.com',
]

# 上次轮询中「首次阻断」的域名，下次轮询时跳过
_skipped_domains: set = set()


# ==================== 安全通道 ====================
def init_secure_channel() -> SecureChannel:
    """从环境变量初始化加密通道"""
    key = os.getenv('NODE_ENCRYPTION_KEY')
    token = os.getenv('NODE_AUTH_TOKEN')
    if not key or not token:
        raise ValueError("必须设置环境变量: NODE_ENCRYPTION_KEY 和 NODE_AUTH_TOKEN")
    return SecureChannel(key, token)


# ==================== nc 检测原语 ====================
def run_nc(domain: str, port: int) -> bool:
    """
    执行 nc -zv4 -w3 <domain> <port>。
    返回 True 表示被阻断（exit code != 0 或超时），False 表示正常。
    """
    try:
        result = subprocess.run(
            ['nc', '-zv4', '-w3', domain, str(port)],
            capture_output=True,
            timeout=5,
        )
        if result.returncode != 0:
            logger.warning(f"nc 检测 {domain}: 阻断 (exit={result.returncode})")
            return True
        logger.debug(f"nc 检测 {domain}: 正常")
        return False
    except subprocess.TimeoutExpired:
        logger.warning(f"nc 检测 {domain}: 超时，判定为阻断")
        return True
    except FileNotFoundError:
        logger.error("找不到 nc 命令，请确认已安装 netcat")
        return True
    except Exception as e:
        logger.error(f"nc 命令执行错误: {e}")
        return True


def check_and_confirm_blocked() -> bool:
    """
    两阶段检测，返回 True 表示确认阻断（需上报），False 表示正常。
    同时维护全局 _skipped_domains 跳过列表。

    流程：
    1. 从 NC_DOMAINS 中排除 _skipped_domains，得到 available 列表
       - 若 available 为空 → 直接上报（所有域名均被跳过）
    2. 随机选 first_domain，执行 run_nc
       - 若正常 → 清空 _skipped_domains，返回 False
    3. first_domain 阻断 → 记入 _skipped_domains（下次轮询跳过）
    4. 从 NC_DOMAINS 中排除 first_domain，得到 second_pool
       - 若 second_pool 为空 → 直接上报（无其他域名可做二次确认）
    5. 随机选 second_domain，执行 run_nc
       - 二次也阻断 → 上报（返回 True）
       - 二次正常   → 判定为域名级问题，不上报（返回 False）
    """
    global _skipped_domains

    # 步骤1：排除跳过域名
    available = [d for d in NC_DOMAINS if d not in _skipped_domains]
    if not available:
        logger.warning(f"所有域名均在跳过列表 {_skipped_domains}，直接上报")
        _skipped_domains.clear()
        return True

    # 步骤2：第一次检测
    first_domain = random.choice(available)
    logger.info(f"第一次检测: {first_domain}")
    if not run_nc(first_domain, CONFIG['nc_port']):
        _skipped_domains.clear()
        return False

    # 步骤3：记录首次阻断域名，下次跳过
    logger.warning(f"第一次检测阻断: {first_domain}，已记录，下次轮询跳过")
    _skipped_domains = {first_domain}

    # 步骤4：二次确认域名池
    second_pool = [d for d in NC_DOMAINS if d != first_domain]
    if not second_pool:
        logger.warning("无其他域名可做二次确认，直接上报")
        return True

    # 步骤5：二次确认
    second_domain = random.choice(second_pool)
    logger.info(f"二次确认检测: {second_domain}")
    if run_nc(second_domain, CONFIG['nc_port']):
        logger.warning(f"二次确认阻断: {second_domain}，确认被阻断")
        return True

    logger.info(f"二次确认正常: {second_domain}，判定为域名级问题，不上报")
    return False


# ==================== 获取公网IP ====================
def get_public_ip() -> str:
    """获取本机公网IP，失败则回退到本机IP"""
    services = [
        'https://api.ipify.org',
        'https://checkip.amazonaws.com',
        'https://ifconfig.me/ip',
        'https://ip.sb/ip',
    ]
    for svc in services:
        try:
            r = requests.get(svc, timeout=5)
            if r.status_code == 200:
                ip = r.text.strip()
                if ip:
                    return ip
        except Exception:
            continue
    return socket.gethostbyname(socket.gethostname())


# ==================== 代理支持 ====================
def test_socks_proxy(proxy_str: str) -> bool:
    """测试 SOCKS5 代理是否可用（尝试通过代理连接服务器）"""
    if not SOCKS_AVAILABLE:
        return False
    try:
        parts = proxy_str.split(':')
        ph = parts[0]
        pp = int(parts[1])
        pu = parts[2] if len(parts) > 2 else None
        ppw = parts[3] if len(parts) > 3 else None

        s = socks.socksocket()
        s.set_proxy(socks.SOCKS5, ph, pp, username=pu, password=ppw)
        s.settimeout(CONFIG['proxy_test_timeout'])
        s.connect((CONFIG['server_host'], CONFIG['server_port']))
        s.close()
        return True
    except Exception:
        return False


def get_usable_proxy() -> Optional[str]:
    """
    从 socks_list 中筛选可用代理，随机返回一个。
    socks_list 为空或均不可用时返回 None（直连）。
    """
    socks_list = CONFIG.get('socks_list', [])
    if not socks_list:
        return None
    if not SOCKS_AVAILABLE:
        logger.warning("socks_list 非空但 PySocks 未安装，将直连（pip install PySocks）")
        return None

    available = [p for p in socks_list if test_socks_proxy(p)]
    if not available:
        logger.warning("所有代理均不可用，回退直连")
        return None

    chosen = random.choice(available)
    host_part = chosen.split(':')[0]
    port_part = chosen.split(':')[1]
    logger.info(f"选用代理: {host_part}:{port_part}")
    return chosen


def make_socket(proxy_str: Optional[str] = None) -> socket.socket:
    """创建 socket，有代理时自动配置 SOCKS5"""
    if proxy_str and SOCKS_AVAILABLE:
        parts = proxy_str.split(':')
        ph = parts[0]
        pp = int(parts[1])
        pu = parts[2] if len(parts) > 2 else None
        ppw = parts[3] if len(parts) > 3 else None
        s = socks.socksocket()
        s.set_proxy(socks.SOCKS5, ph, pp, username=pu, password=ppw)
        return s
    return socket.socket(socket.AF_INET, socket.SOCK_STREAM)


# ==================== 上报服务器 ====================
def report_to_server(sc: SecureChannel, public_ip: str) -> bool:
    """
    加密上报阻断信息到服务器，返回服务器是否成功接收。
    自动选用可用代理（若有）。
    """
    proxy = get_usable_proxy()
    s = None
    try:
        s = make_socket(proxy)
        s.settimeout(CONFIG['report_timeout'])
        s.connect((CONFIG['server_host'], CONFIG['server_port']))

        msg = {
            'type': 'blocked_report',
            'auth_token': os.getenv('NODE_AUTH_TOKEN'),
            'client_ip': public_ip,
            'hostname': socket.gethostname(),
            'callback_port': CONFIG['callback_port'],
            'timestamp': datetime.now().isoformat(),
        }
        s.send(sc.encrypt_message(msg).encode('utf-8'))

        resp_raw = s.recv(8192).decode('utf-8')
        resp = sc.decrypt_message(resp_raw)
        ok = resp.get('status') == 'success'
        logger.info(f"上报结果: {'成功' if ok else '失败'} - {resp.get('message', '')}")
        return ok
    except Exception as e:
        logger.error(f"上报服务器失败: {e}")
        return False
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass


# ==================== 回调监听 ====================
def callback_listener_session(sc: SecureChannel, result_q: queue.Queue, max_rounds: int = 2):
    """
    在独立线程中运行。
    监听服务器的回调连接（换完IP后连回来请求重检）。
    支持最多 max_rounds 轮（对应服务器最多1次重试 = 2轮重检）。
    每轮：接收加密重检指令 → 执行 nc → 发回结果。
    结果（bool或None）写入 result_q，未恢复时继续等待下一轮。
    """
    srv = None
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(('0.0.0.0', CONFIG['callback_port']))
        srv.listen(5)
        logger.info(f"回调监听已启动 (端口: {CONFIG['callback_port']}，最多等待 {CONFIG['callback_session_timeout']}s)")

        deadline = time.time() + CONFIG['callback_session_timeout']
        rounds_done = 0

        while rounds_done < max_rounds:
            remaining = deadline - time.time()
            if remaining <= 0:
                logger.warning("回调等待会话超时")
                break

            srv.settimeout(min(remaining, 60))
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                logger.info("本轮回调等待超时，退出监听")
                break

            logger.info(f"收到服务器回调 (第{rounds_done + 1}轮): {addr}")
            try:
                data = conn.recv(4096).decode('utf-8')
                request = sc.decrypt_message(data)

                if request.get('type') != 'recheck_request':
                    logger.warning(f"收到未知回调类型: {request.get('type')}")
                    conn.close()
                    continue

                logger.info("执行 nc 重新检测...")
                recheck_domain = random.choice(NC_DOMAINS)
                blocked = run_nc(recheck_domain, CONFIG['nc_port'])
                rounds_done += 1

                response = {
                    'type': 'recheck_result',
                    'auth_token': os.getenv('NODE_AUTH_TOKEN'),
                    'blocked': blocked,
                    'timestamp': datetime.now().isoformat(),
                }
                conn.send(sc.encrypt_message(response).encode('utf-8'))
                conn.close()

                result_q.put(blocked)
                logger.info(f"第{rounds_done}轮重检结果: {'仍阻断' if blocked else '✅ 已恢复'}")

                if not blocked:
                    break  # 已恢复，不必等待下一轮
                # 仍阻断：继续循环，等待服务器下一次回调（重试）

            except Exception as e:
                logger.error(f"处理回调请求异常: {e}")
                try:
                    conn.close()
                except Exception:
                    pass

    except OSError as e:
        logger.error(f"回调监听端口绑定失败 (端口: {CONFIG['callback_port']}): {e}")
    except Exception as e:
        logger.error(f"回调监听异常: {e}")
    finally:
        if result_q.empty():
            result_q.put(None)
        if srv:
            try:
                srv.close()
            except Exception:
                pass
        logger.info("回调监听已关闭")


# ==================== 主循环 ====================
def main():
    logger.info("=" * 50)
    logger.info("IP阻断检测客户端启动")
    logger.info(f"检测目标: nc -zv4 -w3 <随机域名> {CONFIG['nc_port']}（候选: {NC_DOMAINS}）")
    logger.info(f"检测间隔: {CONFIG['check_interval']}s，回调端口: {CONFIG['callback_port']}")
    logger.info("=" * 50)

    try:
        sc = init_secure_channel()
    except ValueError as e:
        logger.error(f"初始化失败: {e}")
        sys.exit(1)

    while True:
        try:
            blocked = check_and_confirm_blocked()

            if blocked:
                logger.warning("检测确认阻断，准备上报服务器...")
                public_ip = get_public_ip()
                logger.info(f"当前公网IP: {public_ip}")

                # 先启动回调监听（在上报之前，确保服务器回调时端口已就绪）
                result_q: queue.Queue = queue.Queue()
                listener_thread = threading.Thread(
                    target=callback_listener_session,
                    args=(sc, result_q),
                    kwargs={'max_rounds': 2},
                    daemon=True,
                )
                listener_thread.start()
                time.sleep(0.5)  # 给监听线程充裕的启动时间

                # 上报服务器
                ok = report_to_server(sc, public_ip)
                if not ok:
                    logger.error("上报失败，等待下次检测周期")
                    listener_thread.join(timeout=5)
                else:
                    # 等待回调会话结束（含所有重试轮次）
                    wait_time = CONFIG['callback_session_timeout'] + 15
                    listener_thread.join(timeout=wait_time)

                    try:
                        last_result = result_q.get_nowait()
                        if last_result is False:
                            logger.info("IP已成功恢复，进入正常检测周期")
                        elif last_result is True:
                            logger.warning("服务器重试后仍被阻断，等待下次检测周期")
                        else:
                            logger.info("本轮未收到有效重检结果")
                    except queue.Empty:
                        logger.info("未收到回调结果（可能服务器无法回连）")

            logger.debug(f"等待 {CONFIG['check_interval']} 秒...")
            time.sleep(CONFIG['check_interval'])

        except KeyboardInterrupt:
            logger.info("收到停止信号，退出")
            break
        except Exception as e:
            logger.error(f"主循环异常: {e}")
            time.sleep(30)


if __name__ == '__main__':
    main()
