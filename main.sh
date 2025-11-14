#!/bin/bash

# ======================== Init log file ========================
INSTALL_LOG_FILE="/tmp/install_status.log"
: > "$INSTALL_LOG_FILE"

LOG_FILE="/tmp/install_status.log"
: > "$LOG_FILE"

SUCCESS_LIST=()
FAIL_LIST=()

log_and_run() {
    local desc="$1"
    shift
    echo "--- [$desc] ---" | tee -a "$INSTALL_LOG_FILE"
    if "$@" 2>&1 | tee -a "$INSTALL_LOG_FILE"; then
        echo "SUCCESS: $desc" | tee -a "$INSTALL_LOG_FILE"
        SUCCESS_LIST+=("$desc")
    else
        echo "FAIL: $desc" | tee -a "$INSTALL_LOG_FILE"
        FAIL_LIST+=("$desc")
    fi
}
# ======================== helper functions ========================
RED='\033[0;31m'
NC='\033[0m' # No Color

# Run APT update, upgrade, and autoremove
function apt_cycle(){
    apt-get update
    apt-get upgrade
    apt-get autoremove
}

# Installs specified packages and enables optional service
# Arguments:
#   $1 - Space-separated list of packages to install
#   $2 - (Optional) Service name to enable
# example: install_packages "auditd audispd-plugins" "auditd"
function install_packages(){
    local to_install=$1
    local to_enable=$2

    log_and_run "Installing: $to_install" apt-get install $to_install

    if [ "$to_enable" ]; then
        log_and_run "Enabling service: $to_enable" systemctl enable $to_enable
    fi
}

# Removes specified packages using apt
# Arguments:
#   $1 - Space-separated list of packages to purge
purge_packages(){
    local to_purge=$1
    log_and_run "Purging: $to_purge" apt-get purge $to_purge
}

# Comments out lines in a file that match a given regex
# Arguments:
#   $1 - Regex pattern to match
#   $2 - File to modify
#   $3 - (Optional) Comment mark, default is '#'
function comment() {
    local regex="${1:?}"
    local file="${2:?}"
    local comment_mark="${3:-#}"
    sed -ri "s:^([ ]*)($regex):\\1$comment_mark\\2:" "$file"
}

# Uncomments lines in a file that match a given regex
# Arguments:
#   $1 - Regex pattern to match
#   $2 - File to modify
#   $3 - (Optional) Comment mark, default is '#'
function uncomment() {
    local regex="${1:?}"
    local file="${2:?}"
    local comment_mark="${3:-#}"
    sed -ri "s:^([ ]*)[$comment_mark]+[ ]?([ ]*$regex):\\1\\2:" "$file"
}

# Checks if a file (source) is already fully contained in another file (target)
# Arguments:
#   $1 - Source file
#   $2 - Target file
function check_skip_appand_file(){
    local source=$1
    local target=$2
    # check if the file which will be appended already is in target and return true or false
    grep -Fxq -x -f "$source" "$target"
}

# Checks if a single line exists in a target file
# Arguments:
#   $1 - Line to search for
#   $2 - Target file
function check_skip_appand_line(){
    local line=$1
    local target=$2
    grep -q "$line" "$target"
}


# Prompts the user with a yes/no question
# Arguments:
#   $1 - Prompt message
# Returns:
#   0 for yes, 1 for no
function yes_no_query(){
    local output_str=$1
    while true; do
        read -p "$output_str" yn
        case $yn in
            [Yy]* | "" ) return 0;;
            [Nn]* ) return 1;;
            * ) echo "Please answer yes or no.";;
        esac
    done


}

# Allows user to choose options from a list (interfaces, IPs, or users)
# Arguments:
#   $1 - Mode: "interface", "ip", or "user"
# Sets:
#   global variable: selected_options array
function choose_from_list(){
    # get interfaces/IPs
    local operation=$1
    local len=0
    local option_array=()
    case $operation in
        "interface")
            while read -r line; do
                option_array+=("$line")
                ((len+=1))
            done < <(ip a | grep -oP '^\d+: \K\w+');;
        "ip")
            while read -r line; do
                option_array+=("$line")
                ((len+=1))
            done < <(ip -o -4 addr show | awk '{print $4}' | cut -d/ -f1);;
        "user")
            while read -r line; do
                option_array+=("$line")
                ((len+=1))
            done < <(cut -d: -f1,3 /etc/passwd | grep -E ':[0-9]{4}$' | cut -d: -f1);;
        * ) echo "Internel parse error line 57";;
    esac

    # Display options
    printf "\n======Options======\n"
    for (( c=0; c<len; c++ ))
    do
        echo "$c) ${option_array[$c]}"
    done

    # Choose Option, only accept number that are 0 < num < len
    while true; do
        if [[ $operation == "user" ]]; then
            read -p "Select one option: " options
        else
            read -p "Choose option (multiple choices with space): " options
        fi
        local valid=false
        if [[ "$options" =~ ^(0|[1-9][0-9]*)( (0|[1-9][0-9]*))*$ ]]; then
            valid=true

            # Prüfe ob bei "user" nur eine Option angegeben wurde
            if [[ "$operation" == "user" && "$options" =~ \  ]]; then
                echo "Only one option is aloowed for 'user'!"
                valid=false
            fi

            for num in $options; do
                if (( num >= len )); then
                    valid=false
                fi
            done
        fi
        if $valid; then
            break
        fi
    done

    # write the selected interfaces/IPs into a array
    selected_options=()
    for i in $options
    do
        selected_options+=("${option_array[$i]}")
    done
}
# ======================== end ========================

# Sets a proxy for APT if not already set
function packet_cache(){

    if ! test -f /etc/apt/apt.conf.d/02proxy; then
        touch /etc/apt/apt.conf.d/02proxy
        echo 'Acquire::http::Proxy "XXXX";' > /etc/apt/apt.conf.d/02proxy

        echo "SUCCESS: Setting APT proxy to  XXXX" | tee -a "$LOG_FILE"
        SUCCESS_LIST+=("Setting APT proxy to  XXXX")


    else
        echo "FAIL: 02proxy file already exists. Please verify the content is correct: Acquire::http::Proxy XXXX"| tee -a "$LOG_FILE"
        FAIL_LIST+=("02proxy file already exists. Please verify the content is correct: Acquire::http::Proxy XXXX")
fi
}


# Configures nftables firewall using template and user input
function config_nftables(){
    echo -e "\nConfiguring nftables firewall\n" | tee -a "$LOG_FILE"
    local filePath="/etc/nftables.conf"
    local incoming_rule1
    local incoming_rule2

    local outgoing_rule1
    local outgoing_rule2
    # overwrite nftables.conf with new conf
    cp contents/nftables/nftables_conf $filePath

    # enable ipv6
    if (yes_no_query 'Enable IPv6 [y/n]? '); then
        # append file to file
        cat contents/nftables/enable_ipv6 >> $filePath
    else
        cat contents/nftables/disable_ipv6 >> $filePath
    fi

    echo "Configuring firewall nftables: Please select the network interfaces which will allow incoming and outgoing traffic."

    choose_from_list "interface"

    echo "You selected following interfaces: " "${selected_options[@]}"
iifname ${iface} ip saddr XXXX ct state new tcp dport 22 accept
    # adds line to incoming rule
    for iface in "${selected_options[@]}"; do
        incoming_rule1="                iifname ${iface} ip saddr XXXX ct state new tcp dport 22 accept"
        incoming_rule2="                iifname ${iface} ip saddr XXXX ct state new tcp dport 22 accept"
sed -i "/# input releas flag/a\\
$incoming_rule1\\
$incoming_rule2" "$filePath"
    done


    # adds line to outgoing rule
    for iface in "${selected_options[@]}"; do
        outgoing_rule1="                oifname ${iface} ip daddr XXXX ct state new accept"
        outgoing_rule2="                oifname ${iface} ip daddr XXXX ct state new accept"
sed -i "/# output releas flag/a\\
$outgoing_rule1\\
$outgoing_rule2" "$filePath"
    done

    
    nft -f /etc/nftables.conf

    echo -e '\nFirewall configuration loaded. To view blocked entries, use "journalctl -kf".\n'
    echo 'To enable logging, uncomment the "#log" lines in "/etc/nftables.conf".'

    # Check if nftables service is active
    if systemctl is-enabled --quiet nftables.service; then
        echo -e '\nFirewall configuration loaded. To view blocked entries, use "journalctl -kf".\nTo enable logging, uncomment the "#log" lines in "/etc/nftables.conf".\n' | tee -a "$LOG_FILE"
        SUCCESS_LIST+=("nFirewall configuration loaded and running")
    else
        echo "WARNING: Firewall config loaded but nftables service is NOT running!" | tee -a "$LOG_FILE"
        FAIL_LIST+=("Firewall config loaded but nftables service is NOT running")
    fi
}

# Appends IPv6 blocking lines to /etc/sysctl.conf if not present
function prevent_ipv6_traffic(){
    echo -e "\nBlocking IPv6 traffic\n" | tee -a "$LOG_FILE"
    local filePath="contents/prevent_ipv6_traffic"
    if ! check_skip_appand_file $filePath /etc/sysctl.conf; then
        if cat  "$filePath" >> /etc/sysctl.conf; then
            echo "SUCCESS: IPv6 blocking rules appended to /etc/sysctl.conf" | tee -a "$LOG_FILE"
            SUCCESS_LIST+=("IPv6 blocking rules")
        else
            echo "FAIL: Could not append IPv6 blocking rules to /etc/sysctl.conf" | tee -a "$LOG_FILE"
            FAIL_LIST+=("Could not append IPv6 blocking")
        fi
    else
        echo "SKIP: IPv6 blocking rules already present in /etc/sysctl.conf" | tee -a "$LOG_FILE"
        # You can count skip as success or neutral, up to you
        SUCCESS_LIST+=("IPv6 blocking rules (already present)")
    fi
}

# Prompts user to input the full hostname and updates /etc/hosts
function config_fqdn(){
    echo -e "\nSetting Fully Qualified Domain Name (FQDN)\n" | tee -a "$LOG_FILE"

    local file="/etc/hosts"
    local hostname
    local sec_line_hosts
    local full_hostname

    hostname="$(hostname)"
    sec_line_hosts=$(sed '2!d' $file)

    echo "Please provide the FQDN for this Server. Current hostname is $hostname."

    read -p 'Full Hostname: '  full_hostname

    sed -i "/$sec_line_hosts/s/$/ $full_hostname/" $file

    if grep -q "$full_hostname" "$file"; then
        echo "SUCCESS: FQDN '$full_hostname' has been set in $file." | tee -a "$LOG_FILE"
        SUCCESS_LIST+=("FQDN set")
        echo "FQDN has been set."
    else
        echo "FAIL: Could not set FQDN '$full_hostname' in $file." | tee -a "$LOG_FILE"
        FAIL_LIST+=("Could not set FQDN")
    fi
}


# Adds auditd rules and enables syslog plugin based on Debian version
function config_auditd(){
    echo -e "\nConfiguring Auditd\n" | tee -a "$LOG_FILE"

    local audit_rules_file="/etc/audit/rules.d/audit.rules"
    local version
    local syslog_conf_old

    # Append audit rules if not already present
    if ! check_skip_appand_file contents/auditd "$audit_rules_file"; then
        if cat contents/auditd >> "$audit_rules_file"; then
            echo "SUCCESS: Audit rules appended to $audit_rules_file." | tee -a "$LOG_FILE"
            SUCCESS_LIST+=("Audit rules append")
        else
            echo "FAIL: Could not append audit rules to $audit_rules_file." | tee -a "$LOG_FILE"
            FAIL_LIST+=("Could not append audit rules")
            return 1
        fi
    else
        echo "SKIP: Audit rules already present in $audit_rules_file." | tee -a "$LOG_FILE"
        SUCCESS_LIST+=("Audit rules (already present)")
    fi

    # get debian version and ask user if it is correct. It musst be a number
    version="$(cat /etc/issue)"
    version="$(echo "$version" | sed -E 's/[^0-9]*([0-9]+).*/\1/')"

    if [[ $version -gt 10 ]]; then
        syslog_conf_old="/etc/audit/plugins.d/syslog.conf"
        # Enable active=yes
        if sed -i 's/active = no/active = yes/' "$syslog_conf_old"; then
            echo "SUCCESS: Enabled syslog plugin in $syslog_conf_old (Debian > 10)." | tee -a "$LOG_FILE"
            SUCCESS_LIST+=("Audit syslog plugin enable")
        else
            echo "FAIL: Could not enable syslog plugin in $syslog_conf_old." | tee -a "$LOG_FILE"
            FAIL_LIST+=("Could not enable syslog plugin in Audit")
        fi
    else
        syslog_conf_old="/etc/audisp/plugins.d/syslog.conf"
        if sed -i 's/active = no/active = yes/' "$syslog_conf_old"; then
            echo "SUCCESS: Enabled syslog plugin in $syslog_conf_old (Debian <= 10)." | tee -a "$LOG_FILE"
            SUCCESS_LIST+=("Audit syslog plugin enable")
        else
            echo "FAIL: Could not enable syslog plugin in $syslog_conf_old." | tee -a "$LOG_FILE"
            FAIL_LIST+=("Could not enable syslog plugin in Audit")
        fi
    fi

    echo "Auditd configuration complete."
}


# Configures NTP daemon using a predefined gateway and edits ntp.conf
function config_ntpd() {
    echo -e "\nConfiguring NTP daemon\n" | tee -a "$LOG_FILE"
    # Setze Zeitzone auf Europe/Berlin
    timedatectl set-timezone Europe/Berlin

    gateway=$(ip route | grep default | awk '{print $3}')
    local file="/etc/ntpsec/ntp.conf"

    # Comand adds lines if a line beginns with pool and the next line is empty
    sed -i "0,/^pool/ {
    /^pool/ a\server $gateway iburst\nrestrict default ignore\nrestrict XXXX\nrestrict ::1\nrestrict $gateway\n
    }" $file

    # delete all lines that beginn with pool
    sed -i '/^pool/d' $file

    # comment everything out after "restrict gateway"
    sed -i "/restrict $gateway/ {n; :loop; s/^\([^#]\)/# \1/; n; /\n\$/!b loop;}" $file


    service ntp stop >> "$LOG_FILE" 2>&1
    echo "Stopped ntp service." | tee -a "$LOG_FILE"

    echo "Attempting to synchronize NTP with ntpd -gq. Process will be killed after 60 seconds." | tee -a "$LOG_FILE"
    echo "If killed, manual fix may be needed." | tee -a "$LOG_FILE"

    ntpd -gq >> "$LOG_FILE" 2>&1 &

    # Setze den Timeout mit KILL-Signal
    timeout -s KILL 60 ntpd -gq
    # Überprüfen, ob der Befehl mit einem Exit-Code 137 beendet wurde (was auf das KILL-Signal hindeutet)
    if [ $? -eq 137 ]; then
        echo -e "${RED}NTP daemon timed out. Attempting to kill the process if it still exists.${NC}" | tee -a "$LOG_FILE"
        pid_ntpd=$(ps aux | grep '[n]tpd' | awk 'NR==1 {print $2}')
        if ! [ "$pid_ntpd" == "" ]; then
            kill "$pid_ntpd"
            echo -e "${RED}Killed process with pid $pid_ntpd${NC}" | tee -a "$LOG_FILE"
            FAIL_LIST+=("NTP synchronization timed out and process killed")
        else
            FAIL_LIST+=("NTP synchronization timed out but no process found to kill")
        fi
    fi
    service ntp start >> "$LOG_FILE" 2>&1
    echo "Started ntp service." | tee -a "$LOG_FILE"
}

# Sets up daily virus scan cron job and updates ClamAV mirror
function config_clamav(){
    echo -e "\nConfiguring ClamAV\n" | tee -a "$LOG_FILE"

    if cp contents/clamscan_daily /etc/cron.daily && chmod a+x /etc/cron.daily/clamscan_daily; then
        echo "Installed ClamAV daily scan script." | tee -a "$LOG_FILE"
        SUCCESS_LIST+=("Installed ClamAV daily scan script")
    else
        echo "ERROR: Failed to install ClamAV daily scan script." | tee -a "$LOG_FILE"
        FAIL_LIST+=("Failed to install ClamAV daily scan script")
    fi

    # Delete all Mirror entries and add new one
    sed -i '/DatabaseMirror/d' /etc/clamav/freshclam.conf

    if ! check_skip_appand_line 'DatabaseMirror XXXX' /etc/clamav/freshclam.conf; then
        echo 'DatabaseMirror XXXX' >> /etc/clamav/freshclam.conf
        echo "Updated freshclam.conf with new DatabaseMirror." | tee -a "$LOG_FILE"
        SUCCESS_LIST+=("Updated freshclam.conf with new DatabaseMirror")
    else
        echo "DatabaseMirror entry already present in freshclam.conf." | tee -a "$LOG_FILE"
        FAIL_LIST+=("DatabaseMirror entry already present in freshclam.conf")
    fi

    echo "Generated daily ClamAV virus scan cron job and updated mirror in freshclam.conf." | tee -a "$LOG_FILE"
}

# Copies update_check script to cron.daily and makes it executable
function config_update_logging(){
    echo -e "\nSetting up update logging script\n" | tee -a "$LOG_FILE"

    if cp contents/update_check /etc/cron.daily && chmod u+x /etc/cron.daily/update_check; then
        echo "Installed update logging daily cron job." | tee -a "$LOG_FILE"
        SUCCESS_LIST+=("Installed update logging daily cron job")
    else
        echo "ERROR: Failed to install update logging cron job." | tee -a "$LOG_FILE"
        FAIL_LIST+=("Failed to install update logging cron job")
    fi

    echo "Generated daily update check cron job." | tee -a "$LOG_FILE"
}

# Configures SSH access and prompts for ListenAddress IPs and checks if SSH keys are set
function config_ssh(){
    echo -e "\nSetting up SSH configuration\n" | tee -a "$LOG_FILE"

    local ssh_dir="/etc/ssh/ssh_config.d"
    local filePath="$ssh_dir/some_ssh.conf"

    # Check if the directory exists; create it if missing (instead of just warning)
    if ! [ -d "$ssh_dir" ]; then
        echo -e "${RED}Warning: $ssh_dir does not exist. Attempting to create it...${NC}" | tee -a "$LOG_FILE"
        FAIL_LIST+=("Warning: $ssh_dir does not exist. Attempting to create it")
        if mkdir -p "$ssh_dir"; then
            echo "Created directory $ssh_dir." | tee -a "$LOG_FILE"
            SUCCESS_LIST+=("Created directory $ssh_dir.")
        else
            echo -e "${RED}Error: Failed to create $ssh_dir. SSH login might not be possible.${NC}" | tee -a "$LOG_FILE"
            FAIL_LIST+=("Failed to create $ssh_dir. SSH login might not be possible")
            return
        fi
    fi

    cp contents/some_ssh.conf $ssh_dir

    echo -e "\nConfiguring SSH: Please choose the IPs which should be added to ListenAddress in /some_ssh.conf"

    choose_from_list "ip"

    for (( idx=${#selected_options[@]}-1 ; idx>=0 ; idx-- )); do
        local opt="${selected_options[idx]}"
        local insert_line="ListenAddress $opt"
        if sed -i "/Port 22/a\\$insert_line\\" "$filePath"; then
            echo "Added '$insert_line' to $filePath." | tee -a "$LOG_FILE"
        else
            echo -e "${RED}Failed to add '$insert_line' to $filePath.${NC}" | tee -a "$LOG_FILE"
        fi
    done

    echo -e "${RED}Warning: Be sure that your ssh key is in the authorized_keys file. SSH login may not be possible.${NC}" | tee -a "$LOG_FILE"
}

function remove_sudo(){
    local remove_sudo_user
    remove_sudo_user=($(cut -d: -f1,3 /etc/passwd | grep -E ':[0-9]{4}$' | cut -d: -f1))
    user_count=${#remove_sudo_user[@]}
    if [ "$user_count" -eq 1 ]; then 
        if yes_no_query "The sudo rights will be removed from user $remove_sudo_user. Are you sure [y/n]? "; then
            if deluser "$remove_sudo_user" sudo >> "$LOG_FILE" 2>&1; then
                echo "SUCCESS: Removed sudo rights from user $remove_sudo_user." | tee -a "$LOG_FILE"
                SUCCESS_LIST+=("Removed sudo rights from user $remove_sudo_user")
            else
                echo "FAIL: Failed to remove sudo rights from user $remove_sudo_user. (Maybe it never had sudo)" | tee -a "$LOG_FILE"
                FAIL_LIST+=("Failed to remove sudo rights from user $remove_sudo_user")
            fi
        fi
    else
        if yes_no_query "More then one user detected do you want to remove sudo rights from one [y/n]? "; then
            choose_from_list "user"
            remove_sudo_user=${selected_options[0]}
            if deluser "$remove_sudo_user" sudo >> "$LOG_FILE" 2>&1; then
                echo "SUCCESS: Removed sudo rights from user $remove_sudo_user." | tee -a "$LOG_FILE"
                SUCCESS_LIST+=("Removed sudo rights from user $remove_sudo_user")
            else
                echo "FAIL: Failed to remove sudo rights from user $remove_sudo_user. (Maybe it never had sudo)" | tee -a "$LOG_FILE"
                FAIL_LIST+=("Failed to remove sudo rights from user $remove_sudo_user")
            fi
        else
            echo -e "${RED}It is possible that all users have sudo rights.${NC}" | tee -a "$LOG_FILE"
            FAIL_LIST+=("No sudo rights removed; all users may still have sudo")
        fi
    fi
}

# Sets postix config
function config_postfix(){
    echo -e "\nSetting up Postfix configuration\n" | tee -a "$LOG_FILE"

    if cp contents/postfix_main.cf /etc/postfix/main.cf >> "$LOG_FILE" 2>&1; then
        echo "SUCCESS: Postfix main configuration file copied to /etc/postfix/main.cf." | tee -a "$LOG_FILE"
        SUCCESS_LIST+=("Postfix configuration applied")
    else
        echo "FAIL: Could not copy Postfix main configuration file." | tee -a "$LOG_FILE"
        FAIL_LIST+=("Postfix configuration failed")
    fi
}

function installation_summary(){
    echo -e "\n\n${RED}Installation Summary:${NC}"

    printf "%-8s | %s\n" "STATUS" "TASK"
    printf -- "---------+--------------------------------\n"

    GREEN='\033[0;32m'
    RED='\033[0;31m'
    NC='\033[0m' # no color

    for task in "${SUCCESS_LIST[@]}"; do
        printf "${GREEN}SUCCESS  ${NC}| %s\n" "$task"
    done

    for task in "${FAIL_LIST[@]}"; do
        printf "${RED}FAIL     ${NC}| %s\n" "$task"
    done
}

function show_log_file() {
    if [ -f "$LOG_FILE" ]; then
        echo -e "\n--- Log file contents ---\n"
        cat "$LOG_FILE"
        echo -e "\n--- End of log file ---\n"
    else
        echo "Log file $LOG_FILE does not exist."
    fi
}

function show_inst_log_file() {
    if [ -f "$INSTALL_LOG_FILE" ]; then
        echo -e "\n--- Log file contents ---\n"
        cat "$INSTALL_LOG_FILE"
        echo -e "\n--- End of log file ---\n"
    else
        echo "Log file $INSTALL_LOG_FILE does not exist."
    fi
}

function full_installation(){
    # Installation of packages
    apt_cycle

    install_packages "nftables" "nftables"
    install_packages "auditd audispd-plugins" "auditd"
    install_packages "ntp" "ntpsec"
    install_packages "openssh-server"
    install_packages "clamav clamav-freshclam clamav-daemon uuid-runtime" "clamav-freshclam"

    # Postfix silent install
    echo "postfix postfix/mailname string example.com" | debconf-set-selections
    echo "postfix postfix/main_mailer_type string 'Internet Site'" | debconf-set-selections
    install_packages "postfix libsasl2-modules bsd-mailx"

    purge_packages "avahi-deamon"
    purge_packages "cups"

    apt_cycle
    installation_summary

    if yes_no_query "Do you want to use the internal Packet-Cache as Repository [y/n]? "; then
        packet_cache
    fi

    # Configurations
    config_ssh
    config_nftables
    prevent_ipv6_traffic
    config_fqdn
    config_auditd
    config_ntpd
    config_clamav
    config_postfix
    config_update_logging
    remove_sudo
    installation_summary
}

function user_installation(){
    echo -e "\n\e[1m=========== RUN SPECIFIC CONFIGURATIONS ===========\e[0m\n\n"
    echo -e "\e[1mAvailable options:\e[0m"
    echo -e "  \e[32m 1)\e[0m Configure nftables firewall"
    echo -e "  \e[32m 2)\e[0m Prevent IPv6 traffic"
    echo -e "  \e[32m 3)\e[0m Configure FQDN (hostname)"
    echo -e "  \e[32m 4)\e[0m Configure auditd"
    echo -e "  \e[32m 5)\e[0m Configure NTP daemon (ntpd)"
    echo -e "  \e[32m 6)\e[0m Configure ClamAV antivirus"
    echo -e "  \e[32m 7)\e[0m Configure SSH server"
    echo -e "  \e[32m 8)\e[0m Configure Postfix (mail)"
    echo -e "  \e[32m 9)\e[0m Update logging configuration"
    echo -e "  \e[32m10)\e[0m Remove passwordless sudo"
    echo -e "  \e[33mx)\e[0m Go back to main menu"
    echo

    read -rp "Enter the number(s) of the configurations you want to run (e.g., 1 4 7): " config
    echo

    for i in $config
    do
        case $i in

            1)
                config_nftables
                ;;
            2)
                prevent_ipv6_traffic
                ;;
            3)
                config_fqdn
                ;;
            4)
                config_auditd
                ;;
            5)
                config_ntpd
                ;;
            6)
                config_clamav
                ;;
            7)
                config_ssh
                ;;
            8)
                config_postfix
                ;;
            9)
                config_update_logging
                ;;
            10)
                remove_sudo
                ;;
            [xX])
                echo -e "\e[32mReturning to main menu...\e[0m"
                return
                ;;
            *)
                echo -e "\e[31m'$i' is not a valid option.\e[0m"
                ;;
        esac
    done
}

function help(){
    echo -e "\n\e[1m========== SERVER SETUP HELP MENU ==========\e[0m"
    echo -e "\e[1m1)\e[0m Run the entire script"
    echo -e "   → Executes all installations and configurations."
    echo -e "   → Can be re-run, but may cause errors. No guarantees.\n"

    echo -e "\e[1m2)\e[0m Run specific configurations"
    echo -e "   → Choose one or more setup functions to re-run specific configs."
    echo -e "   → Logging is limited in this mode.\n"

    echo -e "\e[1m3)\e[0m Check cron jobs"
    echo -e "   → Displays all cron jobs for verification.\n"

    echo -e "\e[1m4)\e[0m Check running services"
    echo -e "   → Lists currently running services for status checking.\n"

    echo -e "\e[1m5)\e[0m Show configuration log file"
    echo -e "   → Displays logs from configuration steps.\n"

    echo -e "\e[1m6)\e[0m Show installation log file"
    echo -e "   → Displays logs from package installations.\n"

    echo -e "\e[1m============================================\e[0m"
}

function main() {
    # Ensure script is run as root
    if [[ $(/usr/bin/id -u) -ne 0 ]]; then
        echo -e "\e[31m[ERROR]\e[0m This script must be run as root."
        exit 1
    fi

    local SCRIPT_DIR
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    CURRENT_DIR="$PWD"
    if [[ "$CURRENT_DIR" != "$SCRIPT_DIR" ]]; then
        echo -e "\e[31m[ERROR]\e[0m Please run this script from its own directory:"
        echo "  cd $(dirname "$0") && ./$(basename "$0")"
        exit 1
    fi

    while true; do
        echo -e "\n\e[1m=============== SERVER INSTALLATION SETUP ===============\e[0m\n\n"
        echo -e "\e[1mPlease choose an option:\e[0m"
        echo -e "  \e[32m1)\e[0m Run the entire script"
        echo -e "  \e[32m2)\e[0m Run specific configuration(s)"
        echo -e "  \e[32m3)\e[0m Check cron jobs"
        echo -e "  \e[32m4)\e[0m Check running services"
        echo -e "  \e[32m5)\e[0m Show configuration log file"
        echo -e "  \e[32m6)\e[0m Show installation log file"
        echo -e "  \e[32mh)\e[0m Help"
        echo -e "  \e[31mx)\e[0m Exit"
        echo

        read -rp "Enter your choice: " option
        echo

        case "$option" in
            1)
                full_installation
                ;;
            2)
                user_installation
                ;;
            3)
                echo -e "\e[1mCron Jobs:\e[0m"
                ls -l /etc/cron.daily/
                ;;
            4)
                echo -e "\e[1mRunning Services:\e[0m"
                systemctl --type=service --state=running
                ;;
            5)
                show_log_file
                ;;
            6)
                show_inst_log_file
                ;;
            [hH])
                help
                ;;
            [xX])
                echo -e "\e[32mExiting. Goodbye!\e[0m"
                break
                ;;
            *)
                echo -e "\e[31mInvalid option. Type 'h' for help.\e[0m"
                ;;
        esac
    done
}


main

