#!/bin/bash

curl -fsSL https://raw.githubusercontent.com/uk0/lotspeed/main/install.sh | sudo bash
lotspeed preset balanced
lotspeed set lotserver_turbo 1

apt-get -y update
apt-get -y install cron
systemctl stop cloud-*
