#!/bin/bash

# ==========================================
# Initialization and Paths
# ==========================================
SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
CONFIG_DIR="$HOME/.config/icheck"
HELP_FILE="$CONFIG_DIR/help.txt"
CONFIG_FILE="$CONFIG_DIR/config.conf"
DB_FILE="$CONFIG_DIR/database.txt"

# Default Settings
TIMEOUT=5
CHECK_ALL=0
SHOW_TIME=0
IP_VER=""
PING_VER="ping"

# Default Run Mode
RUN_MODE="fast"

# Specific Output Flags
SHOW_LOCAL=0
SHOW_PUBLIC=0
SHOW_DNS=0
SHOW_PROC=0
SHOW_BL=0
TARGET_PROC=""
CUSTOM_TARGET=""
TARGET_IP=""
MODE=""

# Colors
GREEN="\033[1;32m"
RED="\033[1;31m"
YELLOW="\033[1;33m"
CYAN="\033[1;36m"
NC="\033[0m"

# ==========================================
# Update Function
# ==========================================
function do_update {
    echo -e "\n${CYAN}--- [ Updating icheck ] ---${NC}"
    local update_url="https://raw.githubusercontent.com/balloffur/small_things/refs/heads/main/linux/icheck/icheck.sh"
    local tmp_file="/tmp/icheck_update_tmp.sh"

    echo -n "Fetching latest version from GitHub... "
    if curl -s -f -o "$tmp_file" "$update_url"; then
        if grep -q "#!/bin/bash" "$tmp_file"; then
            cat "$tmp_file" > "$SCRIPT_PATH"
            chmod +x "$SCRIPT_PATH"
            rm -f "$tmp_file"
            echo -e "${GREEN}SUCCESS${NC}"
            echo -e "icheck has been successfully updated."
        else
            echo -e "${RED}FAILED${NC}"
            echo -e "Error: Downloaded file is invalid (missing bash shebang)."
            rm -f "$tmp_file"
            exit 1
        fi
    else
        echo -e "${RED}FAILED${NC}"
        echo -e "Error: Could not reach the repository or file not found."
        rm -f "$tmp_file"
        exit 1
    fi
}

# ==========================================
# WHOIS Function
# ==========================================
function do_whois {
    local ip=$1
    local mode=$2

    if [[ -z "$ip" ]]; then
        echo -e "${RED}Error: Provide an IP address.${NC}"
        return 1
    fi

    if [[ "$mode" == "-s" ]]; then
        echo -e "${CYAN}--- [ Summary for $ip ] ---${NC}"
        local country=$(whois -r "$ip" | grep -i "^country:" | head -n 1 | awk '{print $2}')
        local netname=$(whois -r "$ip" | grep -i "^netname:" | head -n 1 | cut -d':' -f2- | xargs)
        
        echo -e "Country:  ${YELLOW}$country${NC}"
        echo -e "Net/Host: ${YELLOW}$netname${NC}"
        
        if [[ "$netname" =~ (host|vps|server|cloud|novoserve|vmheaven|datacenter|data|web|net) ]]; then
            echo -e "Type:     ${RED}Likely VPS/DataCenter${NC}"
        else
            echo -e "Type:     ${GREEN}Unknown/Residential${NC}"
        fi
    else
        echo -e "${CYAN}--- [ Full details for $ip ] ---${NC}"
        whois -r "$ip" | grep -iE "^(inetnum|netname|country|org-name|descr):" | head -n 10
    fi
}

# ==========================================
# Argument Parser
# ==========================================
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        update) 
            RUN_MODE="update"
            shift 
            ;;
        whois) 
            RUN_MODE="whois"
            TARGET_IP="$2"
            MODE="$3"
            if [[ "$MODE" == "-s" ]]; then
                shift 3
            elif [[ -n "$TARGET_IP" ]]; then
                shift 2
            else
                shift 1
            fi
            ;;
        -f|-fast) RUN_MODE="fast"; shift ;;
        -m|-more) RUN_MODE="standard"; shift ;;
        -a|-all) RUN_MODE="all"; CHECK_ALL=1; shift ;;
        -l|-local) RUN_MODE="custom"; SHOW_LOCAL=1; shift ;;
        -p|-public|-publick) RUN_MODE="custom"; SHOW_PUBLIC=1; shift ;;
        -d|-dns) RUN_MODE="custom"; SHOW_DNS=1; shift ;;
        -bl|-blacklist) RUN_MODE="custom"; SHOW_BL=1; shift ;;
        -proc) 
            RUN_MODE="custom"
            SHOW_PROC=1
            TARGET_PROC="$2"
            [[ -n "$2" ]] && shift 2 || shift 1
            ;;
        -t|-time) SHOW_TIME=1; shift ;;
        -timeout) 
            TIMEOUT="$2"
            [[ -n "$2" ]] && shift 2 || shift 1
            ;;
        -4|-ipv4) IP_VER="-4"; PING_VER="ping"; shift ;;
        -6|-ipv6) IP_VER="-6"; PING_VER="ping6"; shift ;;
        -h|-help|--help) 
            cat "$HELP_FILE" 2>/dev/null || echo "Help file not found."
            exit 0 
            ;;
        -*) 
            echo -e "${RED}Unknown argument: $1${NC}"
            exit 1 
            ;;
        *) 
            RUN_MODE="target"
            CUSTOM_TARGET="$1"
            shift 
            ;;
    esac
done

# Mode Logic
if [ "$RUN_MODE" = "standard" ]; then
    SHOW_LOCAL=1; SHOW_PUBLIC=1; SHOW_DNS=1
elif [ "$RUN_MODE" = "all" ]; then
    SHOW_LOCAL=1; SHOW_PUBLIC=1; SHOW_DNS=1; SHOW_BL=1
fi

# HTTP/Ping Targets Setup
if [ $CHECK_ALL -eq 1 ]; then
    DEFAULT_PING_TARGETS=("1.1.1.1" "8.8.8.8" "9.9.9.9" "ya.ru" "vk.com" "amazon.com" "github.com")
    DEFAULT_HTTP_TARGETS=("youtube.com" "twitter.com" "instagram.com" "facebook.com" "dzen.ru" "mail.ru" "wikipedia.org")
else
    DEFAULT_PING_TARGETS=("1.1.1.1" "ya.ru")
    DEFAULT_HTTP_TARGETS=("youtube.com" "twitter.com")
fi

# Load User Config
CUSTOM_PING_TARGETS=""
CUSTOM_HTTP_TARGETS=""
if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
fi

# ==========================================
# Helper Functions
# ==========================================

function require_tool {
    local cmd="$1"
    local apt_pkg="$2"
    if ! command -v "$cmd" &> /dev/null; then
        echo -e "${RED}Error: Utility '$cmd' is not installed.${NC}"
        echo -e "To install, run: ${YELLOW}sudo apt update && sudo apt install $apt_pkg -y${NC}"
        exit 1
    fi
}

function lookup_db {
    local query="$1"
    if [ -f "$DB_FILE" ]; then
        local result=$(awk -F'|' -v q="$query" '$1 == q {print $2; exit}' "$DB_FILE")
        result=$(echo "$result" | tr -d '\r')
        if [ -n "$result" ]; then
            echo "$result"
            return
        fi
    fi
    echo "Unknown"
}

# ==========================================
# Fast Check Mode
# ==========================================
function check_fast {
    echo -e "\n${CYAN}⚡ [ Fast Status ] ⚡${NC}"
    
    local lip=$(hostname -I | awk '{print $1}')
    echo -e "Local IP: ${GREEN}${lip:-None}${NC}"

    local trace_data=$(curl -s $IP_VER --max-time 2 https://cloudflare.com/cdn-cgi/trace)
    local ip=$(echo "$trace_data" | grep -E "^ip=" | cut -d= -f2)
    local iso=$(echo "$trace_data" | grep -E "^loc=" | cut -d= -f2)

    if [ -n "$ip" ]; then
        local city=$(curl -s $IP_VER --max-time 1 "wttr.in/?format=%l" | sed 's/+/ /g' | awk '{for(i=1;i<=NF;i++) $i=toupper(substr($i,1,1)) tolower(substr($i,2)); print}')
        echo -e "Public IP: ${GREEN}$ip${NC} (Location: ${YELLOW}${city:-Country code: $iso}${NC})"
    else
        echo -e "Public IP: ${RED}Connection Error${NC}"
    fi

    echo -n "Ping google.com: "
    local ping_out=$($PING_VER -c 1 -W 2 google.com 2>&1)
    if [ $? -eq 0 ]; then
        local p_time=$(echo "$ping_out" | awk -F'time=' '/time=/{print $2}' | awk '{print $1" "$2}')
        local t_str=""; [ $SHOW_TIME -eq 1 ] && t_str=" (${CYAN}${p_time}${NC})"
        echo -e "${GREEN}OK${NC}$t_str"
    else
        echo -e "${RED}UNREACHABLE${NC}"
    fi
    echo ""
}

# ==========================================
# Main Functions
# ==========================================

function check_custom_target {
    local clean_target=$(echo "$CUSTOM_TARGET" | sed -E 's|https?://||; s|/.*||')
    echo -e "\n${CYAN}--- [ Target Analysis: $clean_target ] ---${NC}"
    
    local desc=$(lookup_db "$clean_target")
    if [ "$desc" != "Unknown" ]; then
        echo -e "Database: ${YELLOW}$desc${NC}"
    fi

    echo -n "ICMP (Ping): "
    local ping_out=$($PING_VER -c 1 -W "$TIMEOUT" "$clean_target" 2>&1)
    if [ $? -eq 0 ]; then
        local p_time=$(echo "$ping_out" | awk -F'time=' '/time=/{print $2}' | awk '{print $1" "$2}')
        local t_str=""; [ $SHOW_TIME -eq 1 ] && t_str=" (${CYAN}${p_time}${NC})"
        echo -e "${GREEN}REACHABLE${NC}$t_str"
    else
        echo -e "${RED}UNREACHABLE${NC}"
    fi

    echo -n "HTTPS:       "
    local curl_out=$(curl -s $IP_VER -o /dev/null -w "%{http_code}|%{time_total}" --max-time "$TIMEOUT" "https://$clean_target")
    local http_code=$(echo "$curl_out" | cut -d'|' -f1)
    local h_time=$(echo "$curl_out" | cut -d'|' -f2)
    
    if [ "$http_code" != "000" ]; then
        local t_str=""; [ $SHOW_TIME -eq 1 ] && t_str=" (${CYAN}${h_time}s${NC})"
        echo -e "${GREEN}OPEN${NC} [HTTP $http_code]$t_str"
    else
        echo -e "${RED}TIMEOUT / BLOCKED${NC}"
        echo -n "HTTP (80):   "
        local curl_http=$(curl -s $IP_VER -o /dev/null -w "%{http_code}|%{time_total}" --max-time "$TIMEOUT" "http://$clean_target")
        local http_code_80=$(echo "$curl_http" | cut -d'|' -f1)
        if [ "$http_code_80" != "000" ]; then
            echo -e "${YELLOW}OPEN (Unencrypted)${NC} [HTTP $http_code_80]"
        else
            echo -e "${RED}TIMEOUT / BLOCKED${NC}"
        fi
    fi
    echo ""
}

function check_ping {
    local targets=($CUSTOM_PING_TARGETS "${DEFAULT_PING_TARGETS[@]}")
    echo -e "\n${CYAN}--- [ Internet Reachability (ICMP) ] ---${NC}"
    
    for target in "${targets[@]}"; do
        echo -n "Ping $target... "
        local ping_out=$($PING_VER -c 1 -W "$TIMEOUT" "$target" 2>&1)
        if [ $? -eq 0 ]; then
            local p_time=$(echo "$ping_out" | awk -F'time=' '/time=/{print $2}' | awk '{print $1" "$2}')
            local t_str=""; [ $SHOW_TIME -eq 1 ] && t_str=" (${CYAN}${p_time}${NC})"
            echo -e "${GREEN}OK${NC}$t_str"
        else
            echo -e "${RED}Failed${NC}"
        fi
    done
}

function check_http {
    local targets=($CUSTOM_HTTP_TARGETS "${DEFAULT_HTTP_TARGETS[@]}")
    echo -e "\n${CYAN}--- [ Website Reachability (HTTPS) ] ---${NC}"
    
    for target in "${targets[@]}"; do
        echo -n "Request $target... "
        local curl_out=$(curl -s $IP_VER -o /dev/null -w "%{http_code}|%{time_total}" --max-time "$TIMEOUT" "https://$target")
        local http_code=$(echo "$curl_out" | cut -d'|' -f1)
        local h_time=$(echo "$curl_out" | cut -d'|' -f2)
        
        if [ "$http_code" != "000" ]; then
             local t_str=""; [ $SHOW_TIME -eq 1 ] && t_str=" (${CYAN}${h_time}s${NC})"
             echo -e "${GREEN}OPEN${NC}$t_str"
        else
             echo -e "${RED}BLOCKED / TIMEOUT${NC}"
        fi
    done
}

function get_local_ip {
    echo -e "\n${CYAN}--- [ Local Network ] ---${NC}"
    local ip=$(hostname -I | awk '{print $1}')
    if [ -n "$ip" ]; then
        local desc=$(lookup_db "$ip")
        echo -e "Local IP: ${GREEN}$ip${NC} ($desc)"
    else
        echo -e "${RED}No local IP found${NC}"
    fi
}

function get_public_info {
    echo -e "\n${CYAN}--- [ Public Network ] ---${NC}"
    
    local trace_data=$(curl -s $IP_VER --max-time "$TIMEOUT" https://cloudflare.com/cdn-cgi/trace)
    local ip=$(echo "$trace_data" | grep -E "^ip=" | cut -d= -f2)
    local iso=$(echo "$trace_data" | grep -E "^loc=" | cut -d= -f2)

    if [ -n "$ip" ]; then
        local loc_name="Country code: $iso"
        local raw_loc=$(curl -s $IP_VER --max-time "$TIMEOUT" "wttr.in/?format=%l" | sed 's/+/ /g')
        if [ -n "$raw_loc" ]; then
            loc_name=$(echo "$raw_loc" | awk '{for(i=1;i<=NF;i++) $i=toupper(substr($i,1,1)) tolower(substr($i,2)); print}')
        fi
        
        echo -e "Public IP: ${GREEN}$ip${NC}"
        echo -e "Location:  ${YELLOW}$loc_name${NC}"
    else
        echo -e "${RED}Timeout detecting public IP${NC}"
    fi
}

function get_dns {
    echo -e "\n${CYAN}--- [ DNS Servers ] ---${NC}"
    local dns_list=""
    
    if command -v resolvectl &> /dev/null; then
        dns_list=$(resolvectl dns | awk '{for(i=4;i<=NF;i++) print $i}')
    else
        dns_list=$(grep nameserver /etc/resolv.conf | awk '{print $2}')
    fi

    if [ -n "$dns_list" ]; then
        for dns in $dns_list; do
            local desc=$(lookup_db "$dns")
            echo -e "DNS: ${GREEN}$dns${NC} [${YELLOW}$desc${NC}]"
        done
    else
        echo -e "${RED}No DNS servers found${NC}"
    fi
}

function check_proc {
    echo -e "\n${CYAN}--- [ Process Monitoring: $TARGET_PROC ] ---${NC}"
    local pid=$(pgrep -f "$TARGET_PROC" | head -n 1)
    
    if [ -n "$pid" ]; then
        echo -e "Status: ${GREEN}RUNNING${NC} (PID: $pid)"
        local stats=$(ps -p "$pid" -o %cpu,%mem,etime --no-headers)
        local cpu=$(echo $stats | awk '{print $1}')
        local mem=$(echo $stats | awk '{print $2}')
        local time=$(echo $stats | awk '{print $3}')
        
        echo -e "CPU:    ${YELLOW}$cpu%${NC}"
        echo -e "RAM:    ${YELLOW}$mem%${NC}"
        echo -e "Time:   ${YELLOW}$time${NC}"
    else
        echo -e "Status: ${RED}NOT FOUND${NC}"
    fi
}

function check_blacklist {
    local ip=$(curl -s -4 --max-time "$TIMEOUT" https://cloudflare.com/cdn-cgi/trace | grep -E "^ip=" | cut -d= -f2)
    
    if [ -z "$ip" ]; then
        echo -e "\n${RED}Failed to get IP for DNSBL check.${NC}"
        return
    fi

    echo -e "\n${CYAN}--- [ Anti-Spam Databases (DNSBL): $ip ] ---${NC}"
    local rev_ip=$(echo "$ip" | awk -F. '{print $4"."$3"."$2"."$1}')
    
    local bl_servers=("zen.spamhaus.org" "bl.spamcop.net" "b.barracudacentral.org" "cbl.abuseat.org" "dnsbl.sorbs.net")

    for bl in "${bl_servers[@]}"; do
        echo -n "Checking $bl... "
        if host -t A "$rev_ip.$bl" &>/dev/null; then
            echo -e "${RED}⚠️ BLACKLISTED${NC}"
        else
            echo -e "${GREEN}CLEAN${NC}"
        fi
    done
}

# ==========================================
# Program Execution
# ==========================================

# 1. Dependencies
require_tool "curl" "curl"
require_tool "awk" "gawk"
require_tool "$PING_VER" "iputils-ping"
require_tool "host" "dnsutils"

# 2. Scenario Selection
if [ "$RUN_MODE" = "update" ]; then
    do_update
    exit 0
elif [ "$RUN_MODE" = "whois" ]; then
    require_tool "whois" "whois"
    do_whois "$TARGET_IP" "$MODE"
    exit 0
elif [ "$RUN_MODE" = "fast" ]; then
    check_fast
    exit 0
elif [ "$RUN_MODE" = "target" ]; then
    check_custom_target
    exit 0
fi

# 3. Full and Custom Checks
[ $SHOW_LOCAL -eq 1 ] && get_local_ip
[ $SHOW_PUBLIC -eq 1 ] && get_public_info
if [ $SHOW_PUBLIC -eq 1 ] || [ "$RUN_MODE" = "standard" ] || [ "$RUN_MODE" = "all" ]; then
    check_ping
    check_http
fi
[ $SHOW_DNS -eq 1 ] && get_dns
[ $SHOW_BL -eq 1 ] && check_blacklist
[ $SHOW_PROC -eq 1 ] && check_proc

echo ""
