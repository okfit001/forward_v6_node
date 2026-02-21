#!/bin/bash
sudo cp /etc/sysctl.conf /etc/sysctl.conf.bk_$(date +%Y%m%d_%H%M%S) && sudo sh -c 'echo "kernel.pid_max = 65535
kernel.panic = 1
kernel.sysrq = 1
kernel.core_pattern = core_%e
kernel.printk = 3 4 1 3
kernel.numa_balancing = 0
kernel.sched_autogroup_enabled = 0

vm.swappiness = 10
vm.dirty_ratio = 10
vm.dirty_background_ratio = 5
vm.panic_on_oom = 1
vm.overcommit_memory = 1
vm.min_free_kbytes = 1048576

net.core.default_qdisc = fq
net.core.netdev_max_backlog = 4000
net.core.rmem_max = 268435456
net.core.wmem_max = 268435456
net.core.rmem_default = 87380
net.core.wmem_default = 65536
net.core.somaxconn = 2048
net.core.optmem_max = 65536

net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_max_tw_buckets = 32768
net.ipv4.tcp_sack = 1
net.ipv4.tcp_fack = 0
net.ipv4.tcp_rmem = 8192 87380 268435456
net.ipv4.tcp_wmem = 8192 65536 268435456
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_notsent_lowat = 4096
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_adv_win_scale = 6
net.ipv4.tcp_moderate_rcvbuf = 1
net.ipv4.tcp_no_metrics_save = 0
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.tcp_max_orphans = 65536
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 3
net.ipv4.tcp_abort_on_overflow = 0
net.ipv4.tcp_stdurg = 0
net.ipv4.tcp_rfc1337 = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.ip_no_pmtu_disc = 0
net.ipv4.route.gc_timeout = 100
net.ipv4.neigh.default.gc_stale_time = 120
net.ipv4.neigh.default.gc_thresh3 = 8192
net.ipv4.neigh.default.gc_thresh2 = 4096
net.ipv4.neigh.default.gc_thresh1 = 1024
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.arp_announce = 2
net.ipv4.conf.default.arp_announce = 2
net.ipv4.conf.all.arp_ignore = 1
net.ipv4.conf.default.arp_ignore = 1

# IPv6参数（仅包含实际存在的参数）
net.ipv6.route.gc_timeout = 100
net.ipv6.neigh.default.gc_stale_time = 120
net.ipv6.neigh.default.gc_thresh3 = 8192
net.ipv6.neigh.default.gc_thresh2 = 4096
net.ipv6.neigh.default.gc_thresh1 = 1024
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.autoconf = 0
net.ipv6.conf.default.autoconf = 0
net.ipv6.conf.all.dad_transmits = 0
net.ipv6.conf.default.dad_transmits = 0
net.ipv6.conf.all.max_addresses = 64
net.ipv6.conf.default.max_addresses = 64
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv6.conf.all.disable_ipv6 = 0
net.ipv6.conf.default.disable_ipv6 = 0
net.ipv6.bindv6only = 0
net.ipv6.route.max_size = 32768
net.ipv6.route.gc_min_interval = 50
net.ipv6.route.gc_interval = 30
net.ipv6.route.gc_elasticity = 9
net.ipv6.route.mtu_expires = 600
net.ipv6.route.min_adv_mss = 1220
net.ipv6.neigh.default.gc_interval = 30
net.ipv6.neigh.default.base_reachable_time_ms = 30000
net.ipv6.neigh.default.retrans_time_ms = 1000
net.ipv6.neigh.default.unres_qlen = 31
net.ipv6.neigh.default.proxy_qlen = 64
net.ipv6.icmp.ratelimit = 1000
net.ipv6.icmp.ratemask = 0
net.ipv6.icmp.echo_ignore_all = 0" > /etc/sysctl.conf' && sudo sysctl -p

apt-get -y update
apt-get -y install cron

S=Direct_Group_1 bash <(curl -fLSs https://dl.nyafw.com/download/nyanpass-install.sh) rel_nodeclient "-t 75d95698-d7fd-4374-8bab-6d7ccb3ae5fc -u https://forward.nett.to"
S=Direct_Group_2 bash <(curl -fLSs https://dl.nyafw.com/download/nyanpass-install.sh) rel_nodeclient "-t 961c1fff-191c-49c6-b6d2-8014eaa2c38f -u https://forward.nett.to"
S=Direct_Group_3 bash <(curl -fLSs https://dl.nyafw.com/download/nyanpass-install.sh) rel_nodeclient "-t b7e6d48e-12d3-40e5-9d30-8c5d442b44b2 -u https://forward.nett.to"
S=HK_v6 bash <(curl -fLSs https://dl.nyafw.com/download/nyanpass-install.sh) rel_nodeclient "-t e2b3592d-44a3-4055-be7a-d94356e26676 -u https://forward.nett.to"
systemctl stop cloud-*
