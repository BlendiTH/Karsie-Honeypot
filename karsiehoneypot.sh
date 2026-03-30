#!/bin/bash
# SETTINGS
PORT=2222                                    # Which port the honeypot listens on
LOG="/var/log/honeypot.log"                  # Log file (all events)
BLOCKED="/var/log/honeypot_blocked.txt"      # List of blocked IP addresses
WEBHOOK_URL="URL HERE"                       # Webhook URL here
PING="ID HERE"                               # Discord user ID to ping (<@UserID>) (can also ping a role: <@&RoleID>)
SSH_BANNER="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"  # Fake SSH banner name

# UFW (uncomplicated firewall) requires root privileges to work.
# IF YOU DON'T USE sudo, THE SCRIPT WILL STOP HERE!
if [[ $EUID -ne 0 ]]; then
    echo "❌ You do not have root privileges. (Missing sudo?)"
    exit 1
fi

# Create log and blocked IPs files
# Also enable the firewall just in case, if it's not already on. (Verify with: sudo ufw status)
# Make sure the required programs are installed (netcat, jq, curl)
command -v nc >/dev/null 2>&1 || { echo >&2 "Netcat (nc) is missing. Install: sudo apt install netcat-traditional"; exit 1; }
command -v jq >/dev/null 2>&1 || { echo >&2 "jq is missing. Install: sudo apt install jq"; exit 1; }
command -v curl >/dev/null 2>&1 || { echo >&2 "curl is missing. Install: sudo apt install curl"; exit 1; }

touch "$LOG" "$BLOCKED"
ufw --force enable >/dev/null 2>&1

# IP addresses that should NOT be blocked.
WHITELIST=("0.0.0.0")

# STARTUP MESSAGE
echo "🐶 Karsie: the honeypot has been set in the port $PORT!"

# Sends a message to Discord via webhook
# $1 = message to send
send_discord() {
    curl -s -o /dev/null \
        -H "Content-Type: application/json" \
        -X POST \
        -d "$(jq -n --arg c "$1" '{"content":$c}')" \
        "$WEBHOOK_URL"
}

#  MAIN LOOP (this runs forever and waits for connections)
while true; do

    # Create temporary files for data and connection info.
    # FIFO is a "pipe" through which the fake SSH banner is sent.
    TMPDATA=$(mktemp)    # Data sent by the attacker
    TMPCONN=$(mktemp)    # Netcat's connection info (IP etc.)
    FIFO=$(mktemp -u)    # Temporary pipe for the banner
    mkfifo "$FIFO"

    # When someone connects, they see this banner and think they've connected to a real SSH server.
    # sleep 10 = keep the connection open for 10 seconds.
    { printf '%s\r\n' "$SSH_BANNER"; sleep 10; } > "$FIFO" &
    BG=$!

    # nc = netcat, listens on the port and accepts connections.
    # -v = verbose (shows IP info to stderr → TMPCONN)
    # -l = listen
    # -4 = IPv4 only
    # timeout 15 = don't wait forever, max 15 seconds
    timeout 15 nc -v -l -4 "$PORT" < "$FIFO" > "$TMPDATA" 2> "$TMPCONN"
    EXIT=$?

    # Clean up background process
    kill "$BG" 2>/dev/null
    wait "$BG" 2>/dev/null
    rm -f "$FIFO"

    # Timestamp for logging
    TS=$(date '+%Y-%m-%d %H:%M:%S')

    # If timeout fired (exit 124) and nobody connected, start over and listen again.
    if [[ $EXIT -eq 124 ]] && ! grep -qi "connection" "$TMPCONN"; then
        rm -f "$TMPDATA" "$TMPCONN"
        continue   # ← jump back to the start of the while loop
    fi

    # Save the connection details to the log file.
    {
        echo "[$TS] === Connection (exit: $EXIT) ==="
        cat "$TMPCONN"
        cat "$TMPDATA"
        echo
    } >> "$LOG"

    # Find the attacker's IP address from netcat's output.
    # First look for a "from 1.2.3.4" style line, if not found, try to find any IP.
    IP=$(grep -oE 'from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$TMPCONN" \
        | grep -oE '[0-9]+(\.[0-9]+){3}' | tail -1)

    if [[ -z "$IP" ]]; then
        IP=$(grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$TMPCONN" \
            | grep -v '^0\.0\.0\.0$' | tail -1)
    fi

    # Clean up temporary files
    rm -f "$TMPDATA" "$TMPCONN"

    # Skip empty IP, invalid IP, and whitelisted IPs.
    [[ -z "$IP" ]] && continue
    [[ ! $IP =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && continue

    # Check whitelist
    SKIP=false
    for w in "${WHITELIST[@]}"; do
        [[ "$IP" == "$w" ]] && SKIP=true
    done
    [[ "$SKIP" == true ]] && continue

    # If this IP is already blocked, it means the same attacker is trying AGAIN.
    # → Send a warning to Discord and ensure the block is in place.
    if grep -qxF "$IP" "$BLOCKED" 2>/dev/null; then

        echo "[$TS] ⚠️ RETRY: $IP" >> "$LOG"

        # Make sure the UFW rule still exists
        if ! ufw status | grep -q "$IP"; then
            ufw insert 1 deny from "$IP" to any >/dev/null
        fi

        send_discord "⚠️ **BARK! I blocked the _same IP_ again!**
**IP:** \`$IP\`
**Time:** $TS"

        continue   # ← no need to do anything else, IP is already blocked
    fi

    # Use the ipinfo.io service to look up the location.
    # Private network IPs (10.x, 192.168.x etc.) are not looked up.
    if [[ "$IP" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.) ]]; then
        GEO="Local network (LAN)"
        ISP="Local"
    else
        GEO_JSON=$(curl -s --max-time 5 "https://ipinfo.io/${IP}/json" 2>/dev/null)
        CITY=$(echo "$GEO_JSON" | jq -r '.city // "?"')
        COUNTRY=$(echo "$GEO_JSON" | jq -r '.country // "?"')
        ISP=$(echo "$GEO_JSON" | jq -r '.org // "?"')
        GEO="$CITY, $COUNTRY"
    fi

    echo "[$TS] NEW: $IP | $GEO | $ISP" >> "$LOG"

    # SEND ALERT TO DISCORD
    ALERT="$PING 🚨 **BARK! Someone is trying to break in!**
**IP:** \`$IP\`
**Location:** $GEO
**ISP:** $ISP
**Time:** $TS"

    send_discord "$ALERT"

    # "ufw insert 1 deny" = add the block as the FIRST rule.
    # A regular "ufw deny" would go to the end of the list, and allow rules would override it. Which is why we use "ufw insert 1 deny" in this script
    # But, using the regular "ufw deny" will allow for the "⚠️ **BARK! I blocked the _same IP_ again!**" message to be sent.
    ufw insert 1 deny from "$IP" to any >/dev/null

    if [[ $? -eq 0 ]]; then
        # Save IP to the blocked list
        echo "$IP" >> "$BLOCKED"
        send_discord "**◤•͈ᴥ•͈◥ ୭** \`$IP\` blocked!"
    else
        send_discord "❌ Blocking failed: \`$IP\`"
    fi

done
