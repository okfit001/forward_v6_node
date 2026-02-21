echo "'Direct | Group | 1','Direct | Group | 2','Direct | Group | 3','HK | v6'" > /var/tmp/server_group
cat >/var/tmp/client.py <<-EOF
#!/usr/bin/env python3
import socket
import json
import requests
import time
from datetime import datetime

SERVER_HOST = '148.135.207.42'
SERVER_PORT = 8888

# 公网IP检测服务
IP_CHECK_SERVICES = [
    'https://api.ipify.org',
    'https://checkip.amazonaws.com',
    'https://ifconfig.me/ip',
    'https://ip.sb/ip'
]


def get_public_ip():
    for service in IP_CHECK_SERVICES:
        try:
            response = requests.get(service, timeout=5)
            if response.status_code == 200:
                ip = response.text.strip()
                return ip
        except Exception as e:
            continue
    
    return None


def send_online_notification(public_ip):
    message = {
        'public_ip': public_ip,
        'timestamp': datetime.now().isoformat(),
        'hostname': socket.gethostname()
    }
    
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(10)
        client_socket.connect((SERVER_HOST, SERVER_PORT))
        
        client_socket.send(json.dumps(message).encode('utf-8'))
        
        response = client_socket.recv(4096).decode('utf-8')
        response_data = json.loads(response)
        
        client_socket.close()
        return True
        
    except Exception as e:
        return False


def main():
    
    public_ip = get_public_ip()
    if not public_ip:
        return
    
    success = send_online_notification(public_ip)


if __name__ == '__main__':
    main()
EOF
python3 /var/tmp/client.py
rm -f /var/tmp/client.py
