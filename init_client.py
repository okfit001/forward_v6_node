#!/usr/bin/env python3
"""
多节点监控客户端
向服务器发送上线通知，接收并本地执行服务器下发的配置命令
"""
import os
import sys
import socket
import json
import subprocess
import requests
import random
import time
from datetime import datetime
from typing import Optional

try:
    import socks
    SOCKS_AVAILABLE = True
except ImportError:
    SOCKS_AVAILABLE = False

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from crypto_utils import SecureChannel

# 配置
SERVER_HOST = '167.99.73.79'  # 服务器IP
SERVER_PORT = 8888
REMOTE_GROUP_FILE = '/var/tmp/server_group'
CONFIG = {
    'socks_list': [
        # '127.0.0.1:1080',
        # '192.168.1.1:7890:user:pass',
        '34.220.8.240:37000:poweroff:OzOzD_4OEoKi0A5c',
        '54.187.179.85:37000:poweroff:OzOzD_4OEoKi0A5c',
    ],
    'proxy_test_timeout': 5,
    'report_timeout': 15,
}

# 公网IP检测服务
IP_CHECK_SERVICES = [
    'https://api.ipify.org',
    'https://checkip.amazonaws.com',
    'https://ifconfig.me/ip',
    'https://ip.sb/ip'
]


# ==================== 代理支持 ====================
def test_socks_proxy(proxy_str: str) -> bool:
    """测试 SOCKS5 代理是否可用"""
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
        s.connect((SERVER_HOST, SERVER_PORT))
        s.close()
        return True
    except Exception:
        return False


def get_usable_proxy() -> Optional[str]:
    """从 socks_list 中筛选可用代理，随机返回一个，均不可用时返回 None（直连）"""
    socks_list = CONFIG.get('socks_list', [])
    if not socks_list:
        return None
    if not SOCKS_AVAILABLE:
        print("socks_list 非空但 PySocks 未安装，将直连（pip install PySocks）")
        return None

    available = [p for p in socks_list if test_socks_proxy(p)]
    if not available:
        print("所有代理均不可用，回退直连")
        return None

    chosen = random.choice(available)
    host_part = chosen.split(':')[0]
    port_part = chosen.split(':')[1]
    print(f"选用代理: {host_part}:{port_part}")
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


def get_public_ip():
    """获取公网IP"""
    for service in IP_CHECK_SERVICES:
        try:
            response = requests.get(service, timeout=5)
            if response.status_code == 200:
                ip = response.text.strip()
                print(f"获取到公网IP: {ip} (来源: {service})")
                return ip
        except Exception as e:
            print(f"从 {service} 获取IP失败: {e}")
            continue
    print("无法获取公网IP")
    return None


def read_local_groups():
    """读取本地组配置文件，读取后删除"""
    try:
        with open(REMOTE_GROUP_FILE, 'r') as f:
            content = f.read().strip()
        groups = [g.strip().strip("'\"") for g in content.split(',') if g.strip()]
        os.remove(REMOTE_GROUP_FILE)
        print(f"读取本地组配置: {groups}")
        return groups
    except FileNotFoundError:
        print(f"组配置文件不存在: {REMOTE_GROUP_FILE}")
        return []
    except Exception as e:
        print(f"读取组配置文件失败: {e}")
        return []


def execute_commands(all_commands):
    """本地执行服务器下发的配置命令"""
    if not all_commands:
        print("未收到任何配置命令")
        return
    
    for group, cmds in all_commands.items():
        print(f"执行组 '{group}' 的配置命令...")
        for cmd in cmds:
            print(f"执行: {cmd}")
            try:
                result = subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=120
                )
                if result.returncode != 0:
                    print(f"命令执行失败 (returncode={result.returncode}): {result.stderr[:200]}")
                else:
                    print(f"命令执行成功")
            except subprocess.TimeoutExpired:
                print(f"命令执行超时 (300s)")
            except Exception as e:
                print(f"命令执行异常: {e}")


def send_online_notification(sc, public_ip, groups):
    """发送上线通知，接收服务器下发的配置命令"""
    message = {
        'public_ip': public_ip,
        'timestamp': datetime.now().isoformat(),
        'hostname': socket.gethostname(),
        'auth_token': os.getenv('NODE_AUTH_TOKEN'),
        'groups': groups
    }
    
    proxy = get_usable_proxy()
    client_socket = None
    try:
        client_socket = make_socket(proxy)
        client_socket.settimeout(CONFIG['report_timeout'])
        client_socket.connect((SERVER_HOST, SERVER_PORT))
        
        # 发送加密上线通知
        client_socket.send(sc.encrypt_message(message).encode('utf-8'))
        print(f"已发送上线通知到 {SERVER_HOST}:{SERVER_PORT}，组: {groups}")
        
        # 接收服务器下发的命令
        resp_raw = client_socket.recv(65536).decode('utf-8')
        resp = sc.decrypt_message(resp_raw)
        
        if resp.get('status') != 'success':
            print(f"服务器返回错误: {resp.get('message', '未知错误')}")
            return False
        
        print(f"服务器确认: {resp.get('message', '')}")
        
        # 执行服务器下发的配置命令
        all_commands = resp.get('commands', {})
        execute_commands(all_commands)
        
        return True
        
    except Exception as e:
        print(f"与服务器通信失败: {e}")
        return False
    finally:
        if client_socket:
            try:
                client_socket.close()
            except Exception:
                pass


def main():
    print("=== 节点上线通知客户端 ===")
    
    # 初始化加密通道
    try:
        key = os.getenv('NODE_ENCRYPTION_KEY')
        token = os.getenv('NODE_AUTH_TOKEN')
        if not key or not token:
            print("错误: 必须设置环境变量 NODE_ENCRYPTION_KEY 和 NODE_AUTH_TOKEN")
            sys.exit(1)
        sc = SecureChannel(key, token)
    except Exception as e:
        print(f"初始化加密通道失败: {e}")
        sys.exit(1)
    
    # 获取公网IP
    public_ip = get_public_ip()
    if not public_ip:
        print("无法获取公网IP，退出")
        return
    
    # 读取本地组配置
    groups = read_local_groups()
    if not groups:
        print("未找到组配置，退出")
        return
    
    # 发送上线通知，接收并执行服务器下发的命令
    success = send_online_notification(sc, public_ip, groups)
    if success:
        print("配置命令执行完毕")
    else:
        print("上线通知发送失败")


if __name__ == '__main__':
    main()
