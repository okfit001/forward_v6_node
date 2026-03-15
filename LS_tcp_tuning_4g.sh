#!/bin/bash

curl -fsSL https://raw.githubusercontent.com/uk0/lotspeed/main/install.sh | sudo bash
lotspeed preset bbr-like

apt-get -y update
apt-get -y install cron
systemctl stop cloud-*
