# DNSWatchdog

**Simple DNS Resolver Monitor**

## Description:
DNSWatchdog is a lightweight Lua based tool designed to passively monitor DNS queries made by your system. It logs and flags suspicious or unknown domain lookups in real-time. Ideal for spotting potential malware beaconing, misconfigurations, or unusual network activity.

## Features:
- Monitors DNS queries in real-time
- Flags suspicious or unrecognized domains
- Easy to configure with customizable rules
- Optionally integrates with `tshark` for packet capture

## Installation:
1. Install Lua on your system.
2. Clone this repo.
3. Set up `tshark` or `libpcap` to capture DNS traffic.
4. Run the `dnswatchdog.lua` script.

## Usage:
```bash
lua dnswatchdog.lua
