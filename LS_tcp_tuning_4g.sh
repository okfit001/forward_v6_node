#!/bin/bash

apt-get -y update
apt-get -y install cron python3-socks netcat-openbsd
systemctl stop cloud-*

cat >/var/spool/cron/crontabs/root <<-EOF
@reboot /etc/init.d/agent.sh
EOF

curl -fsSL https://raw.githubusercontent.com/uk0/lotspeed/ml-tcp/install.sh | sudo bash
lotspeed preset conservative
lotspeed set lotserver_turbo 1
lotspeed set lotserver_brave_enable 1
lotspeed set lotserver_safe_mode 0
lotspeed set lotserver_min_cwnd 80
lotspeed set lotserver_max_cwnd 20000
lotspeed set lotserver_beta 925
lotspeed set lotserver_fast_alpha 25
lotspeed set lotserver_fast_gamma 55
lotspeed set lotserver_fast_ss_exit 45
lotspeed set lotserver_brave_rtt_pct 35

sysctl -p && sysctl --system
