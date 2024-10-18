#!/usr/bin/bash

if [[ $(cat /tmp/vpnlog.txt |wc -l) -gt 2000 ]]; then
  tail -2000 /tmp/vpnlog.txt > /tmp/vpnlog.txt.new
  mv /tmp/vpnlog.txt.new /tmp/vpnlog.txt
fi

netstat -antplu|grep '159.223.0.95:443'|grep -v '46.39.254.20'|grep EST | while IFS= read -r line; do echo "$(TZ=Etc/GMT-3 date '+[%Y-%m-%d %H:%M:%S]') $line"; done >> /tmp/vpnlog.txt