#!/bin/bash

##
## Configuration section
##

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
VPN_DIR="${DIR}"
NETNS_SCRIPT="${DIR}"/netns-script

##
## End Configuration section
##


isRunning() {
    pgrep -A -n -u root -f "${1}" >/dev/null 2>&1
    return $?
}


COMMAND="${1}"
VPN="${2}"
PROVIDER="${VPN%%:*}"
VPN_CONF="${VPN#*:}"
CONFIG_FILE="${VPN_DIR}"/config/"${PROVIDER}"/config/"${VPN_CONF}"

shift 2

case "${COMMAND}" in
    list)
        ip netns list
    ;;
    start)
        if [ ! -f "${CONFIG_FILE}" ]; then
            echo Unable to load config file
            echo "${CONFIG_FILE}"
            exit
        fi
        
        isRunning "${VPN}" && exit
        sudo openvpn --script-security 2 --ifconfig-noexec --route-noexec --up "'${NETNS_SCRIPT}' ${VPN}" --route-up "'${NETNS_SCRIPT}' ${VPN}" --down "'${NETNS_SCRIPT}' ${VPN}" --config "${CONFIG_FILE}" &
        
        # wait for vpn to become active
        while ! sudo ip netns exec "${VPN}" echo >/dev/null 2>&1; do
            sleep 1
        done
    ;;
    exec)
        # need to check if VPN exists
        isRunning "${VPN}" || "${BASH_SOURCE[0]}" start "${VPN}"
        sudo ip netns exec "${VPN}" su $(whoami) -c "${*}"
    ;;
    stop)
        while isRunning "${VPN}"; do
            sudo pkill -A -n -u root -f "${VPN}"
            echo -n .
            sleep 1
        done
    ;;
    *)
        echo Invalid Arguments
        echo Usage: $0 \[command\] \[PROVIDER:VPN\] \<args\>
        echo Valid commands are: list start exec stop
    ;;
esac

