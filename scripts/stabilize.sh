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

# Check conditions and restart xray if either threshold is exceeded
if (( $(echo "$load_avg > $LOAD_THRESHOLD" | bc -l) )) || (( memory_utilization > MEMORY_THRESHOLD )); then
    echo "Load or memory utilization threshold exceeded. Restarting xray..."
    systemctl restart xray
else
    echo "System load and memory utilization are within safe limits."
fi
