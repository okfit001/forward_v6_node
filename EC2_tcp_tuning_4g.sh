#!/bin/bash

apt-get -y update
apt-get -y install cron python3-socks netcat-openbsd
systemctl stop cloud-*

cat >/var/spool/cron/crontabs/root <<-EOF
@reboot /etc/init.d/agent.sh
EOF

curl -fsSL https://raw.githubusercontent.com/uk0/lotspeed/ml-tcp/install.sh | sudo bash
lotspeed preset aggressive
lotspeed set lotserver_turbo 1
lotspeed set lotserver_brave_enable 1
lotspeed set lotserver_safe_mode 1
lotspeed set lotserver_min_cwnd 80
lotspeed set lotserver_max_cwnd 20000
lotspeed set lotserver_fast_alpha 20
lotspeed set lotserver_fast_gamma 45
lotspeed set lotserver_fast_ss_exit 45
lotspeed set lotserver_brave_rtt_pct 35

cat > /etc/sysctl.conf << EOF
vm.min_free_kbytes = 1048576
net.core.rmem_max = 196608000
net.core.wmem_max = 196608000
net.ipv4.tcp_rmem = 8192 190054 196608000
net.ipv4.tcp_wmem = 8192 190054 196608000
net.ipv4.ip_forward=1
net.ipv4.conf.all.route_localnet=1
net.ipv4.conf.all.forwarding=1
net.ipv4.conf.default.forwarding=1
EOF
sysctl -p && sysctl --system
