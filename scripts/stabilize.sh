#!/bin/bash

# Thresholds
LOAD_THRESHOLD=0.9
MEMORY_THRESHOLD=90

# Get load average for the last 5 minutes
load_avg=$(awk '{print $2}' /proc/loadavg)

# Get total and free memory in kilobytes
total_mem=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
free_mem=$(awk '/MemAvailable/ {print $2}' /proc/meminfo)

# Calculate memory utilization as a percentage
memory_utilization=$(( (total_mem - free_mem) * 100 / total_mem ))

# Get current timestamp
timestamp=$(date "+%Y-%m-%d %H:%M:%S")

# Check conditions and restart xray if either threshold is exceeded
if (( $(echo "$load_avg > $LOAD_THRESHOLD" | bc -l) )) || (( memory_utilization > MEMORY_THRESHOLD )); then
    echo "$timestamp - Load or memory utilization threshold exceeded. Restarting xray..." >> /tmp/stabilize.log
    systemctl restart xray
else
    echo "$timestamp - System load and memory utilization are within safe limits." # >> /tmp/stabilize.log
fi

if [[ $(cat /tmp/stabilize.log |wc -l) -gt 2000 ]]; then
  tail -2000 /tmp/stabilize.log > /tmp/stabilize.log.new
  mv /tmp/stabilize.log.new /tmp/stabilize.log
fi