#!/bin/bash

apt-get -y update
apt-get -y install cron python3-socks netcat-openbsd
systemctl stop cloud-*

curl -fsSL https://raw.githubusercontent.com/uk0/lotspeed/main/install.sh | sudo bash
lotspeed preset bbr-like
lotspeed set lotserver_turbo 1
lotspeed set lotserver_beta 921
