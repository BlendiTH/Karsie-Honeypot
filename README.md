
![Logo](https://i.imgur.com/g6Plmon.png)

# 🐶 Karsie — SSH Honeypot

A lightweight SSH honeypot project created for my Linux Servers course.

## ⚠️ Disclaimer
**Karsie is an educational school project created by a beginner/intermediate developer** to learn about Linux servers. **It is not an enterprise-grade security tool.**

*By using this script, you acknowledge that the author is not responsible for any damage, data loss, or legal issues that may arise from its use. Because this script automatically modifies firewall (UFW) rules, there is a risk of blocking legitimate traffic.*

**Deploy this only on systems you own. Do not use this in a critical production environment. Use entirely at your own risk!**

## How It Works

Karsie poses as an OpenSSH server to detect, log and block unauthorized connection attempts, with real-time Discord alerts. It listens on a configurable port (default `2222`) using `netcat` and presents a fake SSH banner to incoming connections. When someone connects, the script:

- **Logs** the connection with a timestamp
- **Extracts** the attacker's IP address
- **Geolocates** the IP (city, country, ISP) via [ipinfo.io](https://ipinfo.io)
- **Sends a Discord alert** with full details through a webhook
- **Blocks the IP** using UFW 
- **Detects repeat attempts** — if a blocked IP reconnects, a separate warning is sent

## Requirements

- **OS:** Linux (Tested on an Ubuntu Server **(Ubuntu 24.04 LTS)**)
- **Privileges:** Root (`sudo`)
- **Dependencies:**
  - `netcat` → `sudo apt install netcat-traditional`
  - `jq` → `sudo apt install jq`
  - `curl` → `sudo apt install curl`
  - `ufw` → normally pre-installed on Ubuntu

## Quick Start

1. Clone or copy the script, and give it the proper permissions:
`chmod +x karsiehoneypot.sh`

3. Edit the configuration at the top of the script:
- `WEBHOOK_URL`  → your Discord webhook URL
- `PING`         → your Discord user/role ID for mentions
- `PORT`         → listening port (default: 2222)

3. Run it:
`sudo ./karsiehoneypot.sh`


## Configuration

All settings are defined at the top of the script and can be configured to whatever is best for your use case:

| Variable | Default | Description |
|---|---|---|
| `PORT` | `2222` | Port the honeypot listens on |
| `LOG` | `/var/log/honeypot.log` | Path to the log file |
| `BLOCKED` | `/var/log/honeypot_blocked.txt` | List of blocked IPs |
| `WEBHOOK_URL` | *(set yours)* | Discord webhook URL |
| `PING` | *(set yours)* | Discord user/role ID to mention |
| `SSH_BANNER` | `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6` | Fake SSH banner shown to attackers |
| `WHITELIST` | `("0.0.0.0")` | IPs that should never be blocked |

## Discord Alerts

Karsie sends three types of messages:

- 🚨 **New intrusion** — IP, geolocation, ISP, SSH client tool, and timestamp
- ⚠️ **Repeated attempt** — a previously blocked IP tried again **[Only if you configure the UFW firewall to not place blocked IPs at the top of the list!]**
- 🐾 **IP blocked** — confirmation that UFW blocked the attacker

## Logs

All events are logged to `/var/log/honeypot.log`, including raw connection data and parsed IP info.

Blocked IPs are tracked in `/var/log/honeypot_blocked.txt` (one per line).

## Stopping the Honeypot

Press `Ctrl + C` (or `Ctrl + Z`) to stop the script.

