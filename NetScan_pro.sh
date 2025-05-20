#!/usr/bin/env bash

# NetScan Pro - Shell Edition
# A simpler network scanner using common shell utilities.

# --- Default Configuration ---
DEFAULT_TIMEOUT_SEC=1
DEFAULT_BANNER_TIMEOUT_SEC=2
DEFAULT_THREADS=10
# For TCP Connect scan, nc/ncat is used.
# For SYN scan, we'd ideally use nmap -sS, but this script focuses on nc.

# --- Global Variables ---
TARGETS_RAW=""
TARGET_FILE=""
PORTS_STR="1-1024" # Default ports
SCAN_TYPE="CONNECT" # CONNECT, SYN (will use nmap), PING, ARP
SERVICE_VERSION=false
VERBOSE=false
OUTPUT_FILE="" # Simple text output

# --- Helper Functions ---
print_usage() {
    echo "NetScan Pro - Shell Edition"
    echo "Usage: $0 [OPTIONS] -t <targets>"
    echo ""
    echo "Targets:"
    echo "  -t, --targets <targets>   Comma-separated IPs, hostnames, CIDR (e.g., 192.168.1.1,192.168.1.0/24,host.com)"
    echo "  --target-file <file>    File containing targets, one per line."
    echo ""
    echo "Scan Types:"
    echo "  -sn                       Ping scan only (host discovery)."
    echo "  --arp-scan <network_cidr> ARP scan for local network (e.g., 192.168.1.0/24, requires sudo & arp-scan)."
    echo "  -sT                       TCP Connect scan (default port scan)."
    # echo "  -sS                       TCP SYN scan (uses nmap -sS, requires sudo & nmap)." # Placeholder
    echo ""
    echo "Port Specification (for -sT, -sS):"
    echo "  -p, --ports <ports>       Ports to scan (e.g., 22,80,443 or 1-1024 or 'all'). Default: 1-1024."
    # echo "  --top-ports <N>           Scan top N common TCP ports (requires a predefined list)." # Simpler to use -p
    echo ""
    echo "Service & Performance:"
    echo "  -sV                       Attempt basic banner grabbing for open ports."
    echo "  --timeout <sec>           Timeout for probes in seconds (default: $DEFAULT_TIMEOUT_SEC)."
    echo "  --threads <N>             Number of concurrent tasks (default: $DEFAULT_THREADS)."
    echo ""
    echo "Output:"
    echo "  -oN <file>                Output results to a plain text file."
    echo "  -v, --verbose             Verbose output (show closed/filtered ports attempts)."
    echo "  -h, --help                Show this help message."
    echo ""
    echo "Examples:"
    echo "  $0 -t 192.168.1.1 -p 22,80,443 -sT -sV"
    echo "  sudo $0 --arp-scan 192.168.1.0/24 -sn"
    echo "  $0 -t scanme.nmap.org -p 1-100 -sT -v -oN results.txt"
    echo "  sudo $0 -t 192.168.1.5 -p 1-1000 # (will use nmap for -sS if implemented and chosen)"
    exit 1
}

log() {
    echo "[*] $1"
}

log_verbose() {
    if [ "$VERBOSE" = true ]; then
        echo "    [-] $1"
    fi
}

log_error() {
    echo "[!] ERROR: $1" >&2
}

check_command() {
    if ! command -v "$1" &> /dev/null; then
        log_error "$1 command not found. Please install it."
        return 1
    fi
    return 0
}

resolve_host() {
    local host_input="$1"
    local ip_addr
    # Check if it's already an IP
    if [[ "$host_input" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "$host_input"
        return 0
    fi
    # Try to resolve hostname
    if command -v dig &> /dev/null; then
        ip_addr=$(dig +short "$host_input" A | head -n1)
    elif command -v getent &> /dev/null; then
        ip_addr=$(getent hosts "$host_input" | awk '{print $1}' | head -n1)
    else
        log_error "Cannot resolve hostname '$host_input'. 'dig' or 'getent' not found."
        return 1
    fi

    if [ -z "$ip_addr" ]; then
        log_error "Could not resolve hostname: $host_input"
        return 1
    else
        echo "$ip_addr"
        return 0
    fi
}

# Function to expand CIDR to a list of IPs
# Uses nmap -sL or prips if available
expand_cidr() {
    local cidr="$1"
    if command -v nmap &> /dev/null; then
        nmap -sL -n "$cidr" | grep "Nmap scan report for" | awk '{print $NF}' | sed 's/[()]//g'
    elif command -v prips &> /dev/null; then
        prips "$cidr"
    else
        log_error "Cannot expand CIDR '$cidr'. 'nmap' or 'prips' not found. Skipping this target."
        return 1
    fi
}

# Function to parse port string (e.g., "22,80", "1-100", "all")
parse_ports_to_scan() {
    local port_spec="$1"
    local final_ports=()

    if [[ "$port_spec" == "all" ]]; then
        port_spec="1-65535"
    fi

    IFS=',' read -ra ADDR <<< "$port_spec"
    for item in "${ADDR[@]}"; do
        if [[ "$item" == *-* ]]; then
            local start_port=$(echo "$item" | cut -d'-' -f1)
            local end_port=$(echo "$item" | cut -d'-' -f2)
            if ! [[ "$start_port" =~ ^[0-9]+$ ]] || ! [[ "$end_port" =~ ^[0-9]+$ ]]; then
                log_error "Invalid port range: $item"
                continue
            fi
            if (( start_port < 1 || end_port > 65535 || start_port > end_port )); then
                 log_error "Invalid port range values: $item"
                 continue
            fi
            # shellcheck disable=SC2003 # seq is fine here
            final_ports+=($(seq "$start_port" "$end_port"))
        elif [[ "$item" =~ ^[0-9]+$ ]]; then
            if (( item < 1 || item > 65535 )); then
                log_error "Invalid port number: $item"
                continue
            fi
            final_ports+=("$item")
        else
            log_error "Invalid port format: $item"
        fi
    done
    # Unique sorted ports
    # shellcheck disable=SC2207
    PORTS_TO_SCAN_ARRAY=($(echo "${final_ports[@]}" | tr ' ' '\n' | sort -un))
}


# --- Argument Parsing (Simplified using getopts) ---
# More robust parsing would use getopt (the external command) or more complex getopts loop

# Handle long options manually for getopts
for arg in "$@"; do
  shift
  case "$arg" in
    "--targets")       set -- "$@" "-t" ;;
    "--target-file")   set -- "$@" "-F" ;; # Using -F for file internally
    "--ports")         set -- "$@" "-p" ;;
    "--arp-scan")      set -- "$@" "-A" ;; # Using -A for arp-scan network
    "--timeout")       set -- "$@" "-T" ;; # Using -T for timeout
    "--threads")       set -- "$@" "-N" ;; # Using -N for threads
    "--help")          set -- "$@" "-h" ;;
    *)                 set -- "$@" "$arg"
  esac
done


while getopts ":t:F:p:A:sTnsVhvT:N:o:" opt; do
    case ${opt} in
        t) TARGETS_RAW="$OPTARG" ;;
        F) TARGET_FILE="$OPTARG" ;;
        p) PORTS_STR="$OPTARG" ;;
        A) ARP_NETWORK_CIDR="$OPTARG"; SCAN_TYPE="ARP" ;;
        s) # Handle combined short options like -sT, -sV
           # This basic getopts doesn't do it as elegantly as Python's argparse
           # Assuming single char options after -s for now
           sub_opt="${OPTARG:0:1}"
           # For -sT, -sS, -sV
           if [[ "$sub_opt" == "T" ]]; then SCAN_TYPE="CONNECT"; fi
           if [[ "$sub_opt" == "S" ]]; then SCAN_TYPE="SYN"; log_error "-sS (SYN scan) via nmap is preferred. This script primarily uses TCP Connect."; fi # Mark as to-do
           if [[ "$sub_opt" == "V" ]]; then SERVICE_VERSION=true; fi
           # If OPTARG has more chars, it's an error for this simple parser or needs more logic
           ;;
        T) DEFAULT_TIMEOUT_SEC="$OPTARG" ;;
        N) DEFAULT_THREADS="$OPTARG" ;;
        o) # -oN <file>
           if [[ "$OPTARG" == "N" ]]; then
                # Next argument should be the filename
                # This is a hack because getopts isn't great with options taking args that look like other options
                # A more robust parser is needed for complex cases.
                # For simplicity, assume next arg is filename if -oN
                # This requires -oN and filename to be separate arguments.
                # A better way: -o type:filename, then parse
                # For now, we'll assume -oN <filename>
                OUTPUT_FILE_FLAG_VALUE_NEXT=true # This is a bit of a hack
           else # Assume it's -o<type><filename> if not -oN, but we only support -oN <file>
                if [ "$OUTPUT_FILE_FLAG_VALUE_NEXT" = true ]; then
                    OUTPUT_FILE="$OPTARG"
                    OUTPUT_FILE_FLAG_VALUE_NEXT=false
                else
                    log_error "Unsupported output option or format for -o: $OPTARG. Use -oN <filename>."
                fi
           fi
           ;;
        n) # -sn (ping scan)
           SCAN_TYPE="PING" ;;
        V) SERVICE_VERSION=true ;; # For -sV if passed separately
        v) VERBOSE=true ;;
        h) print_usage ;;
        \?) log_error "Invalid option: -$OPTARG" >&2; print_usage ;;
        :) log_error "Option -$OPTARG requires an argument." >&2; print_usage ;;
    esac
done
shift $((OPTIND -1))

# If -oN was used, the filename might be in $1 now if it was the next arg
if [ "$OUTPUT_FILE_FLAG_VALUE_NEXT" = true ] && [ -n "$1" ]; then
    OUTPUT_FILE="$1"
    shift
fi


# --- Validate Inputs and Prepare Targets ---
ALL_TARGET_IPS=()

if [ -n "$TARGET_FILE" ]; then
    if [ -f "$TARGET_FILE" ]; then
        while IFS= read -r line || [[ -n "$line" ]]; do
            # Skip empty lines and comments
            [[ -z "$line" || "$line" == \#* ]] && continue
            TARGETS_RAW="${TARGETS_RAW}${TARGETS_RAW:+,}$line" # Append with comma
        done < "$TARGET_FILE"
    else
        log_error "Target file not found: $TARGET_FILE"
        exit 1
    fi
fi

if [ -z "$TARGETS_RAW" ] && [ "$SCAN_TYPE" != "ARP" ]; then
    log_error "No targets specified. Use -t, --target-file, or --arp-scan."
    print_usage
fi

# Expand targets
if [ -n "$TARGETS_RAW" ]; then
    IFS=',' read -ra RAW_TARGET_ITEMS <<< "$TARGETS_RAW"
    for item in "${RAW_TARGET_ITEMS[@]}"; do
        item=$(echo "$item" | xargs) # Trim whitespace
        if [[ "$item" == *"/"* ]]; then # CIDR
            expanded_cidr_ips=($(expand_cidr "$item"))
            if [ $? -eq 0 ]; then
                ALL_TARGET_IPS+=("${expanded_cidr_ips[@]}")
            fi
        else # Single IP or hostname
            resolved_ip=$(resolve_host "$item")
            if [ $? -eq 0 ] && [ -n "$resolved_ip" ]; then
                ALL_TARGET_IPS+=("$resolved_ip")
            fi
        fi
    done
fi

# Unique sorted IPs
# shellcheck disable=SC2207
ALL_TARGET_IPS=($(echo "${ALL_TARGET_IPS[@]}" | tr ' ' '\n' | sort -u))


if [ "$SCAN_TYPE" != "PING" ] && [ "$SCAN_TYPE" != "ARP" ]; then
    parse_ports_to_scan "$PORTS_STR"
    if [ ${#PORTS_TO_SCAN_ARRAY[@]} -eq 0 ]; then
        log_error "No valid ports to scan. Check your -p argument."
        exit 1
    fi
fi

# --- Redirect output if -oN is used ---
if [ -n "$OUTPUT_FILE" ]; then
    exec > >(tee -a "$OUTPUT_FILE") 2>&1
    log "Output is being tee'd to $OUTPUT_FILE"
fi

# --- Check for required commands based on scan type ---
check_command "ping" || exit 1
if [[ "$SCAN_TYPE" == "CONNECT" || "$SERVICE_VERSION" = true ]]; then
    if ! check_command "nc" && ! check_command "ncat"; then
        log_error "TCP Connect scan or banner grabbing requires 'nc' or 'ncat'."
        exit 1
    fi
    NC_COMMAND=$(command -v nc || command -v ncat)
fi
if [ "$SCAN_TYPE" == "ARP" ]; then
    check_command "arp-scan" || exit 1
    if [[ $EUID -ne 0 ]]; then
        log "ARP scan (-arp-scan) usually requires root privileges. Attempting anyway..."
    fi
fi
if [ "$SCAN_TYPE" == "SYN" ]; then
    check_command "nmap" || exit 1
     if [[ $EUID -ne 0 ]]; then
        log "SYN scan (-sS using nmap) usually requires root privileges. Attempting anyway..."
    fi
fi


# --- Scan Logic ---
LIVE_HOSTS=()
SCAN_START_TIME=$(date +%s)
log "NetScan Pro (Shell Edition) starting at $(date)"

# Host Discovery
if [ "$SCAN_TYPE" == "ARP" ]; then
    log "Performing ARP scan on $ARP_NETWORK_CIDR..."
    # shellcheck disable=SC2207
    LIVE_HOSTS=($(sudo arp-scan --numeric --quiet --ignoredups "$ARP_NETWORK_CIDR" | awk '{print $1}'))
    if [ ${#LIVE_HOSTS[@]} -gt 0 ]; then
        log "ARP Scan Results: ${#LIVE_HOSTS[@]} host(s) found."
        for host in "${LIVE_HOSTS[@]}"; do echo "  [+] Host up: $host (ARP)"; done
    else
        log "No hosts found via ARP scan on $ARP_NETWORK_CIDR."
    fi
    # If only ARP scan and no other targets, we might stop here or merge with -t targets.
    # For now, if --arp-scan is given, its results are the live hosts for subsequent port scans.
    ALL_TARGET_IPS=("${LIVE_HOSTS[@]}") # Override -t targets if ARP scan is done

elif [ ${#ALL_TARGET_IPS[@]} -gt 0 ]; then # ICMP Ping for targets from -t or --target-file
    log "Performing ICMP Ping scan for ${#ALL_TARGET_IPS[@]} target(s)..."
    for host_ip in "${ALL_TARGET_IPS[@]}"; do
        # Adjust ping command for macOS compatibility (timeout option)
        local PING_CMD
        if [[ "$(uname)" == "Darwin" ]]; then # macOS
            PING_CMD="ping -c 1 -t $DEFAULT_TIMEOUT_SEC $host_ip"
        else # Linux
            PING_CMD="ping -c 1 -W $DEFAULT_TIMEOUT_SEC $host_ip"
        fi

        if $PING_CMD &> /dev/null; then
            echo "  [+] Host up: $host_ip (ICMP)"
            LIVE_HOSTS+=("$host_ip")
        else
            log_verbose "Host down or unresponsive: $host_ip (ICMP)"
        fi
    done
    log "ICMP Ping scan complete. Found ${#LIVE_HOSTS[@]} live host(s)."
    ALL_TARGET_IPS=("${LIVE_HOSTS[@]}") # Update ALL_TARGET_IPS to only live ones
fi


if [ "$SCAN_TYPE" == "PING" ] || [ "$SCAN_TYPE" == "ARP" && -z "$PORTS_STR" ]; then # If only host discovery
    log "Host discovery finished."
    SCAN_END_TIME=$(date +%s)
    log "Scan completed in $((SCAN_END_TIME - SCAN_START_TIME)) seconds."
    exit 0
fi

if [ ${#ALL_TARGET_IPS[@]} -eq 0 ]; then
    log "No live hosts found. Aborting port scan."
    exit 0
fi

# Port Scanning
log "\nInitiating port scan on ${#ALL_TARGET_IPS[@]} live host(s) for ${#PORTS_TO_SCAN_ARRAY[@]} port(s) each."

for host in "${ALL_TARGET_IPS[@]}"; do
    echo -e "\nScanning host: $host"
    open_ports_found_on_host=false

    # Prepare list of commands for xargs
    # Each line will be: <host> <port>
    task_list=""
    for port in "${PORTS_TO_SCAN_ARRAY[@]}"; do
        task_list+="$host $port\n"
    done

    # Define the scanning function to be used by xargs
    # This function will be executed for each host/port pair by xargs
    perform_port_scan_task() {
        local current_host="$1"
        local current_port="$2"
        local status="closed"
        local banner=""

        # TCP Connect Scan using nc/ncat
        # The -v option in some nc versions prints to stderr.
        # -z for zero-I/O mode (just check if listening)
        if $NC_COMMAND -z -w "$DEFAULT_TIMEOUT_SEC" "$current_host" "$current_port" 2>/dev/null; then
            status="open"
            echo "  [+] $current_host:$current_port/tcp OPEN"
            open_ports_found_on_host_flag_file="/tmp/netscan_pro_open_${current_host//./_}" # Create a flag file per host
            touch "$open_ports_found_on_host_flag_file"


            if [ "$SERVICE_VERSION" = true ]; then
                # Basic banner grabbing
                # Send a newline for some services, or a specific probe for HTTP
                local probe=""
                if [[ "$current_port" == "80" || "$current_port" == "8080" ]]; then
                    probe="HEAD / HTTP/1.0\r\n\r\n"
                fi
                # Using timeout command to prevent hanging
                # Capture first line of banner, clean non-printable
                banner_raw=$(echo -e "$probe" | timeout "$DEFAULT_BANNER_TIMEOUT_SEC" "$NC_COMMAND" "$current_host" "$current_port" 2>/dev/null)
                if [ $? -eq 0 ] && [ -n "$banner_raw" ]; then
                    banner=$(echo "$banner_raw" | head -n1 | tr -dc '[:print:]\n' | sed 's/\r//g' | cut -c1-60)
                    echo "      Service: $banner"
                else
                    log_verbose "$current_host:$current_port - Banner grab failed or timed out."
                fi
            fi
        else
            log_verbose "$current_host:$current_port/tcp CLOSED/FILTERED"
        fi
    }
    export -f perform_port_scan_task # Export function for xargs
    export NC_COMMAND DEFAULT_TIMEOUT_SEC SERVICE_VERSION DEFAULT_BANNER_TIMEOUT_SEC VERBOSE # Export variables

    # Use xargs for concurrency
    echo -e "$task_list" | xargs -P "$DEFAULT_THREADS" -n 2 bash -c 'perform_port_scan_task "$@"' _

    # Check if any open ports were found for this host using the flag file
    open_ports_flag_file="/tmp/netscan_pro_open_${host//./_}"
    if [ ! -f "$open_ports_flag_file" ]; then
         echo "    No open ports found on $host (or verbose mode is off)."
    fi
    rm -f "$open_ports_flag_file" # Clean up flag file

done

SCAN_END_TIME=$(date +%s)
log "\nNetScan Pro (Shell Edition) finished at $(date)"
log "Scan completed in $((SCAN_END_TIME - SCAN_START_TIME)) seconds."

if [ -n "$OUTPUT_FILE" ]; then
    log "Full results also saved to $OUTPUT_FILE"
fi

exit 0