#!/bin/bash
echo "'Direct | Group | 1','Direct | Group | 2','Direct | Group | 3','HK | v6'" > /var/tmp/server_group
cat >/var/tmp/client.py <<-EOF
#!/usr/bin/env python3
import socket
import json
import requests
import time
import os
from datetime import datetime
from crypto_utils import create_secure_channel_from_env

# 配置
SERVER_HOST = os.getenv('NODE_SERVER_HOST', 'YOUR_SERVER_IP')  # 从环境变量获取
SERVER_PORT = int(os.getenv('NODE_SERVER_PORT', '8888'))

# 公网IP检测服务
IP_CHECK_SERVICES = [
    'https://api.ipify.org',
    'https://checkip.amazonaws.com',
    'https://ifconfig.me/ip',
    'https://ip.sb/ip'
]


def get_public_ip():
    """获取公网IP"""
    for service in IP_CHECK_SERVICES:
        try:
            response = requests.get(service, timeout=5)
            if response.status_code == 200:
                ip = response.text.strip()
                print(f"✓ 获取到公网IP: {ip} (来源: {service})")
                return ip
        except Exception as e:
            print(f"✗ 从 {service} 获取IP失败: {e}")
            continue
    
    print("✗ 无法获取公网IP")
    return None


def send_online_notification(public_ip, secure_channel):
    """发送加密的上线通知到服务器"""
    # 从环境变量获取身份令牌
    auth_token = os.getenv('NODE_AUTH_TOKEN')
    if not auth_token:
        print("✗ 环境变量 NODE_AUTH_TOKEN 未设置")
        return False
    
    # 准备消息
    message = {
        'public_ip': public_ip,
        'timestamp': datetime.now().isoformat(),
        'hostname': socket.gethostname(),
        'auth_token': auth_token  # 身份验证令牌
    }
    
    try:
        # 加密消息
        encrypted_message = secure_channel.encrypt_message(message)
        print(f"✓ 消息已加密 (长度: {len(encrypted_message)} 字节)")
        
        # 连接服务器
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(15)
        client_socket.connect((SERVER_HOST, SERVER_PORT))
        print(f"✓ 已连接到服务器 {SERVER_HOST}:{SERVER_PORT}")
        
        # 发送加密消息
        client_socket.send(encrypted_message.encode('utf-8'))
        print(f"✓ 已发送加密的上线通知")
        
        # 接收加密响应
        encrypted_response = client_socket.recv(8192).decode('utf-8')
        
        # 解密响应
        try:
            response_data = secure_channel.decrypt_message(encrypted_response)
            print(f"✓ 服务器响应: {response_data}")
            
            if response_data.get('status') == 'success':
                print(f"✓ 上线通知成功")
                return True
            else:
                print(f"✗ 服务器返回错误: {response_data.get('message')}")
                return False
                
        except Exception as e:
            print(f"✗ 解密服务器响应失败: {e}")
            return False
        
    except socket.timeout:
        print(f"✗ 连接超时")
        return False
    except ConnectionRefusedError:
        print(f"✗ 连接被拒绝，请检查服务器是否运行")
        return False
    except Exception as e:
        print(f"✗ 发送上线通知失败: {e}")
        return False
    finally:
        try:
            client_socket.close()
        except:
            pass


def main():
    print("=" * 50)
    print("节点上线通知客户端 (加密通信)")
    print("=" * 50)
    
    # 检查环境变量
    required_env_vars = ['NODE_ENCRYPTION_KEY', 'NODE_AUTH_TOKEN']
    missing_vars = [var for var in required_env_vars if not os.getenv(var)]
    
    if missing_vars:
        print(f"✗ 缺少必需的环境变量: {', '.join(missing_vars)}")
        print("\n请设置以下环境变量:")
        print("  export NODE_ENCRYPTION_KEY='your-32-char-encryption-key'")
        print("  export NODE_AUTH_TOKEN='your-auth-token'")
        print("  export NODE_SERVER_HOST='server-ip'  # 可选")
        print("  export NODE_SERVER_PORT='9999'       # 可选")
        return
    
    # 初始化加密通道
    try:
        secure_channel = create_secure_channel_from_env()
        print("✓ 安全通道初始化成功")
    except Exception as e:
        print(f"✗ 安全通道初始化失败: {e}")
        return
    
    # 获取公网IP
    public_ip = get_public_ip()
    if not public_ip:
        print("✗ 无法获取公网IP，退出")
        return
    
    # 发送上线通知
    success = send_online_notification(public_ip, secure_channel)
    
    print("=" * 50)
    if success:
        print("✓ 任务完成")
    else:
        print("✗ 任务失败")
    print("=" * 50)


if __name__ == '__main__':
    main()
EOF
python3 /var/tmp/client.py
rm -f /var/tmp/client.py
