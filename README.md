# Network Throttle Control

A **GUI application** for simulating various **network conditions** on **Linux** systems. Used for testing applications under poor network conditions, simulating high latency connections, or reproducing network-related bugs.

## Configurable Network Parameters

* Latency/Delay (0-2000ms)
* Jitter (0-500ms)
* Packet Loss (0-100%)
* Bandwidth Limiting (1-1000 Mbit/s)
* Packet Duplication (0-100%)
* Packet Corruption (0-100%)
* Packet Reordering (0-100%)

## Requirements

* **Linux** (uses `tc` - Traffic Control)
* **Python 3.x**
* **Root/sudo privileges**
* **tkinter**

## Installation

```bash
git clone git@github.com:NisharnSP/network_throttler.git && cd network-throttler

sudo python3 network_throttle.py

# Or if made executable
sudo ./network_throttle.py
```
---
### Usage
1. Enter the target IP address you want to throttle.
2. Click "Apply IP" to configure the target.
3. Adjust sliders to set network conditions.
    -  Changes apply automatically after 300ms of inactivity.

4. Click "Remove Throttling" or close the app to restore normal network behavior.

## How It Works
The application uses Linux's tc (traffic control) with HTB (Hierarchical Token Bucket) and netem (Network Emulator) to shape outgoing traffic to specified IP addresses. Rules are automatically cleaned up when the application closes.

## Warnings
- Requires root privileges - This tool modifies system network settings.
- Affects real network traffic - Use responsibly and only on networks you control.
- Linux only - Uses Linux-specific traffic control utilities.
