#!/bin/bash
# Author: Infinition
# Script to manage Wi-Fi connections using NetworkManager

# Log file path
LOG_FILE="/var/log/wifi-manager.log"

# Array to track failed operations
declare -a failed_operations

# Logging function to write messages to the log file with timestamps
log() {
    local level="$1"
    local message="$2"
    printf "[%s] [%s] %s\n" "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$message" >> "$LOG_FILE"
}

# Function to manage Wi-Fi connections
manage_wifi_connections() {
    log "INFO" "Starting Wi-Fi connection management..."

    local preconfig_file="/etc/NetworkManager/system-connections/preconfigured.nmconnection"

    # Check if the preconfigured file exists
    if [ -f "$preconfig_file" ]; then
        log "INFO" "Preconfigured Wi-Fi file found. Extracting data..."

        # Extract SSID and PSK from the file
        local ssid psk
        ssid=$(grep '^ssid=' "$preconfig_file" | cut -d'=' -f2)
        psk=$(grep '^psk=' "$preconfig_file" | cut -d'=' -f2)

        if [ -z "$ssid" ]; then
            log "ERROR" "SSID not found in the preconfigured file."
            printf "%bSSID not found in the preconfigured Wi-Fi file. Check the log for details.%b\n" "\e[31m" "\e[0m"
            failed_operations+=("SSID extraction")
            return 1
        fi

        # Create a new Wi-Fi connection with the extracted SSID and PSK
        log "INFO" "Creating new Wi-Fi connection for SSID: $ssid with priority 5"
        if nmcli connection add type wifi ifname wlan0 con-name "$ssid" ssid "$ssid" \
            wifi-sec.key-mgmt wpa-psk wifi-sec.psk "$psk" connection.autoconnect yes \
            connection.autoconnect-priority 5 >> "$LOG_FILE" 2>&1; then
            log "SUCCESS" "Successfully created Wi-Fi connection for SSID: $ssid"
        else
            log "ERROR" "Failed to create Wi-Fi connection for SSID: $ssid"
            printf "%bFailed to create Wi-Fi connection for SSID: $ssid. Check the log for details.%b\n" "\e[31m" "\e[0m"
            failed_operations+=("Wi-Fi connection for SSID: $ssid")
            return 1
        fi

        # Remove the preconfigured file only after a successful connection creation
        if rm "$preconfig_file"; then
            log "SUCCESS" "Removed preconfigured Wi-Fi connection file."
        else
            log "WARNING" "Failed to remove preconfigured Wi-Fi connection file."
        fi
    else
        log "WARNING" "No preconfigured Wi-Fi connection file found."
    fi
}

# Main execution
manage_wifi_connections

# Report failed operations, if any
if [ ${#failed_operations[@]} -ne 0 ]; then
    printf "The following operations failed:\n"
    for operation in "${failed_operations[@]}"; do
        printf "- %s\n" "$operation"
    done
    exit 1
else
    printf "Wi-Fi connection management completed successfully.\n"
    exit 0
fi
