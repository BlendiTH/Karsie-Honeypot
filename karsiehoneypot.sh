#!/bin/bash

# SETTINGS
PORT=2222                                    # Which port the honeypot listens on
LOG="/var/log/honeypot.log"                  # Log file (all events)
BLOCKED="/var/log/honeypot_blocked.txt"      # List of blocked IP addresses
WEBHOOK_URL="URL HERE"                       # Discord Webhook URL here
PING="ID HERE"                               # Discord user ID to ping (<@UserID>) (can also ping a role: <@&RoleID>)
SSH_BANNER="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"  # Fake SSH banner

# uncomplicated firewall (ufw) requires root privileges to work
if [[ $EUID -ne 0 ]]; then
    echo "❌ You do not have root privileges. (Missing sudo?)"
    exit 1
fi

command -v nc >/dev/null 2>&1 || { echo >&2 "Netcat (nc) is missing. Install: sudo apt install netcat-traditional"; exit 1; }
command -v jq >/dev/null 2>&1 || { echo >&2 "jq is missing. Install: sudo apt install jq"; exit 1; }
command -v curl >/dev/null 2>&1 || { echo >&2 "curl is missing. Install: sudo apt install curl"; exit 1; }

touch "$LOG" "$BLOCKED"
ufw --force enable >/dev/null 2>&1

# IP addresses that should NOT be blocked
WHITELIST=("0.0.0.0")

# startup message
echo "🐶 Karsie: the honeypot has been set in the port $PORT!"

# sends a message to Discord via webhook
send_discord() {
    curl -s -o /dev/null \
        -H "Content-Type: application/json" \
        -X POST \
        -d "$(jq -n --arg c "$1" '{"content":$c}')" \
        "$WEBHOOK_URL"
}

#  main loop
while true; do

    TMPDATA=$(mktemp)    # Data sent by the client
    TMPCONN=$(mktemp)    # nc -v output (which contains the client ip)
    FIFO=$(mktemp -u)    
    mkfifo "$FIFO"

    # feeds the fake banner to nc through the FIFO, and holds the connection open for 10s
    { printf '%s\r\n' "$SSH_BANNER"; sleep 10; } > "$FIFO" &
    BG=$!

    timeout 15 nc -v -l -4 "$PORT" < "$FIFO" > "$TMPDATA" 2> "$TMPCONN"
    EXIT=$?

    # clean up background process
    kill "$BG" 2>/dev/null
    wait "$BG" 2>/dev/null
    rm -f "$FIFO"

    TS=$(date '+%Y-%m-%d %H:%M:%S')

    # exit 124 = timeout without a connection, try listening again
    if [[ $EXIT -eq 124 ]] && ! grep -qi "connection" "$TMPCONN"; then
        rm -f "$TMPDATA" "$TMPCONN"
        continue  
    fi

    {
        echo "[$TS] === Connection (exit: $EXIT) ==="
        cat "$TMPCONN"
        cat "$TMPDATA"
        echo
    } >> "$LOG"

    # parse the attackers IP from nc output: prefems "from x.x.x.x", falls back to any non-0.0.0.0 IP
    IP=$(grep -oE 'from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$TMPCONN" \
        | grep -oE '[0-9]+(\.[0-9]+){3}' | tail -1)

    if [[ -z "$IP" ]]; then
        IP=$(grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$TMPCONN" \
            | grep -v '^0\.0\.0\.0$' | tail -1)
    fi

    rm -f "$TMPDATA" "$TMPCONN"

    # skip empty/invalid/whitelisted IPs
    [[ -z "$IP" ]] && continue
    [[ ! $IP =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && continue

    SKIP=false
    for w in "${WHITELIST[@]}"; do
        [[ "$IP" == "$w" ]] && SKIP=true
    done
    [[ "$SKIP" == true ]] && continue

    # if this IP is already blocked: alert and make sure the rule still works
    if grep -qxF "$IP" "$BLOCKED" 2>/dev/null; then

        echo "[$TS] ⚠️ RETRY: $IP" >> "$LOG"

        if ! ufw status | grep -q "$IP"; then
            ufw insert 1 deny from "$IP" to any >/dev/null
        fi

        send_discord "⚠️ **BARK! I blocked the _same IP_ again!**
**IP:** \`$IP\`
**Time:** $TS"

        continue
    fi

    # use the ipinfo.io service to look up the location, skip geolocation for private/loopback ranges
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

    # send alert to Discord
    ALERT="$PING 🚨 **BARK! Someone is trying to break in!**
**IP:** \`$IP\`
**Location:** $GEO
**ISP:** $ISP
**Time:** $TS"

    send_discord "$ALERT"

    # "ufw insert 1 deny" puts the deny rule above any allow rules, otherwise allows would "win"
    ufw insert 1 deny from "$IP" to any >/dev/null

    if [[ $? -eq 0 ]]; then
        # Save IP to the blocked list
        echo "$IP" >> "$BLOCKED"
        send_discord "**◤•͈ᴥ•͈◥ ୭** \`$IP\` blocked!"
    else
        send_discord "❌ Blocking failed: \`$IP\`"
    fi

done
