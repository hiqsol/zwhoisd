#!/bin/sh

killall zwhoisd
sleep 1
./zwhoisd -t /home/whois/tpl -w /data/whois/ -l /home/whois/log/zwhoisd.log -p /var/run/zwhoisd-4.pid -u whois -d -a 2.2.2.2
./zwhoisd -t /home/whois/tpl -w /data/whois/ -l /home/whois/log/zwhoisd.log -p /var/run/zwhoisd-6.pid -u whois -d -a 2:2:2:2:0:0:0:2
