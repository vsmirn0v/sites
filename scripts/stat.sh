#!/usr/bin/bash

egrep_pattern=$(hostname -I | tr ' ' '\n' | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | awk '{print $0 ":443"}' | paste -sd'|' -)

if [[ $(cat /tmp/vpnlog.txt |wc -l) -gt 4000 ]]; then
  tail -2000 /tmp/vpnlog.txt > /tmp/vpnlog.txt.new
  mv /tmp/vpnlog.txt.new /tmp/vpnlog.txt
fi

netstat -antplu|egrep "($egrep_pattern)"|grep -v '46.39.254.20'|grep EST | while IFS= read -r line; do echo "$(TZ=Etc/GMT-3 date '+[%Y-%m-%d %H:%M:%S]') $line"; done >> /tmp/vpnlog.txt
