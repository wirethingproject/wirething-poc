#!/usr/bin/env bash

# params
    
OS="$(uname -s)"

WT_HOST_START_DELAY="${WT_HOST_START_DELAY:-10}"
WT_HOST_INTERVAL="${WT_HOST_INTERVAL:-900}" # 15 minutes
WT_PEER_START_DELAY="${WT_PEER_START_DELAY:-1}"
WT_PEER_INTERVAL="${WT_PEER_INTERVAL:-1}" # 1 second

WT_TOPIC_TAG="${WT_TOPIC_TAG:-wirething}"
WT_PUSH_TIMEOUT="${WT_PUSH_TIMEOUT:-10}"
WT_PULL_TIMEOUT="${WT_PULL_TIMEOUT:-60}"

WT_ALLOWED_IPS="${WT_ALLOWED_IPS:-100.64.0.0/24}"
WT_PERSISTENT_KEEPALIVE="${WT_PERSISTENT_KEEPALIVE:-25}"

WT_INTERFACE="${WT_INTERFACE:-wg}"
case "${WT_INTERFACE}" in
    wg)
        WG_INTERFACE="${WG_INTERFACE:-}"
        if [ "${WG_INTERFACE}" == "" ]
        then
            WG_HOST_PRIVATE_KEY_FILE="${WG_HOST_PRIVATE_KEY_FILE?Variable not set}"
            WG_PEER_PUBLIC_KEY_FILE_LIST="${WG_PEER_PUBLIC_KEY_FILE_LIST?Variable not set}"

            WG_USERSPACE="${WG_USERSPACE:-wireguard-go}"
            WG_LOG_LEVEL="${WG_LOG_LEVEL:-info}"
        fi
        ;;
    *)
        echo "ERROR: Invalid interface type *${WT_INTERFACE}*, options: wg" \
            && exit 1
esac

WT_PUNCH="${WT_PUNCH:-udphole}"
case "${WT_PUNCH}" in
    udphole)
        UDPHOLE_HOST="${UDPHOLE_HOST:-udphole.fly.dev}"
        UDPHOLE_PORT="${UDPHOLE_PORT:-53000}"
        ;;
    *)
        echo "ERROR: Invalid punch type *${WT_PUNCH}*, options: udphole" \
            && exit 1
esac

WT_PUBSUB="${WT_PUBSUB:-ntfy}"
case "${WT_PUBSUB}" in
    ntfy)
        NTFY_URL="${NTFY_URL:-https://ntfy.sh}"
        ;;
    *)
        echo "ERROR: Invalid punch type *${WT_PUBSUB}*, options: ntfy" \
            && exit 1
esac

[ "$(id -u)" != "0" ] \
    && echo "ERROR: Not a root user" \
    && exit 1

umask 077

case "${WT_INTERFACE}" in
    wg)
        if [ "${WG_INTERFACE}" == "" ]
        then
            WG_TUN_NAME_FILE="/var/run/wireguard/$(uuidgen).wirething"
            case "${OS}" in
                Darwin)
                    WG_TUN_NAME="utun"
                    ;;
                Linux)
                    WG_TUN_NAME="wt0$(basename "${WG_TUN_NAME_FILE}" | cut -f 1 -d -)"
                    echo "${WG_TUN_NAME}" > "${WG_TUN_NAME_FILE}"
                    ;;
                *)
                    echo "ERROR: OS not supported *${OS}*" \
                    exit 1
            esac
        fi
        ;;
    *)
        echo "ERROR: Invalid interface type *${WT_INTERFACE}*, options: wg" \
            && exit 1
esac

# hacks

shopt -s expand_aliases

alias sha256sum='sha256sum | cut -f 1 -d " "'

[ "${WG_USERSPACE}" != "" ] \
    && alias wireguard-us="${WG_USERSPACE}"

alias interface="${WT_INTERFACE}_interface"
alias punch="${WT_PUNCH}_punch"
alias pubsub="${WT_PUBSUB}_pubsub"

# wireguard

function wg_open_host() {
    [ ! -f "${WG_HOST_PRIVATE_KEY_FILE}" ] \
        && echo "ERROR: File not found *${WG_HOST_PRIVATE_KEY_FILE}*" \
        && exit 1

    wg set "${WG_INTERFACE}" private-key "${WG_HOST_PRIVATE_KEY_FILE}"
}

function wg_open_peers() {
    for wg_peer_public_key_file in ${WG_PEER_PUBLIC_KEY_FILE_LIST}
    do
        [ ! -f "${wg_peer_public_key_file}" ] \
            && echo "ERROR: File not found *${wg_peer_public_key_file}*" \
            && exit 1

        peer_public_key="$(cat "${wg_peer_public_key_file}")"
        wg set "${WG_INTERFACE}" \
            peer "${peer_public_key}" \
            persistent-keepalive "${WT_PERSISTENT_KEEPALIVE}" \
            allowed-ips "${WT_ALLOWED_IPS}"
    done
}

function wg_interface() {
    action="${1}" && shift
    case "${action}" in
        open)
            [ "${WG_INTERFACE}" != "" ] && return 0

            LOG_LEVEL="${WG_LOG_LEVEL}" WG_TUN_NAME_FILE="${WG_TUN_NAME_FILE}" \
                wireguard-us ${WG_TUN_NAME}

            WG_INTERFACE="$(cat "${WG_TUN_NAME_FILE}")"

            wg_open_host
            wg_open_peers
            ;;
        close)
            rm -vf "${WG_TUN_NAME_FILE}"
            ;;
        get)
            param="${1}" && shift
            case "${param}" in
                host_id)
                    wg show "${WG_INTERFACE}" public-key
                    ;;
                peers_id_list)
                    wg show "${WG_INTERFACE}" peers
            esac
            ;;
        set)
            param="${1}" && shift
            case "${param}" in
                host_port)
                    port="${1}" && shift
                    wg set "${WG_INTERFACE}" listen-port "${port}"
                    ;;
                peer_endpoint)
                    peer="${1}" && shift
                    endpoint="${1}" && shift
                    wg set "${WG_INTERFACE}" peer "${peer}" endpoint "${endpoint}"
                    ;;
            esac
            ;;
        status)
            wg show "${WG_INTERFACE}"
            ;;
    esac
}

# udphole

function udphole_punch() {
    action="${1}" && shift
    case "${action}" in
        open)
            exec 100<>/dev/udp/${UDPHOLE_HOST}/${UDPHOLE_PORT}
            echo "" >&100
            ;;
        port)
            lsof -R -P -n -i "udp@${UDPHOLE_HOST}:${UDPHOLE_PORT}" \
                | grep " $$ " | head -n 1 \
                | tr -s " " | sed "s,->, ," | cut -f 10 -d " " \
                | sed "s,.*:,,"
            ;;
        endpoint)
            head -n 1 <&100
            ;;
        close)
            exec 100<&-
            exec 100>&-
            ;;
    esac
}

# ntfy

function ntfy_pull_filter() {
    while read peer_endpoint
    do
        if [ "${peer_endpoint}" != "" ]
        then
            echo "${peer_endpoint}"
        fi
    done
}

function ntfy_pubsub() {
    action="${1}" && shift
    case "${action}" in
        push)
            topic="${1}" && shift
            host_endpoint="${1}" && shift
            curl -Ns --max-time "${WT_PUSH_TIMEOUT}" "${NTFY_URL}/${topic}" -d "${host_endpoint}" \
                > /dev/null
            ;;
        pull)
            topic="${1}" && shift
            curl -Ns --max-time "${WT_PULL_TIMEOUT}" "${NTFY_URL}/${topic}/raw" \
                | ntfy_pull_filter
            ;;
    esac
}

# wirething log

function log_date() {
    date -Iseconds
}

function log_punch() {
    echo "$(log_date) punch: ${host_endpoint} -> ${host_port}"
}

function log_set_host_port() {
    echo "$(log_date) set_host_port ${host_id::4}...: ${host_port}" > /dev/stderr
}

function log_set_peer_endpoint() {
    echo "$(log_date) set_peer_endpoint ${peer_id::4}...: ${peer_endpoint}" > /dev/stderr
}

function log_push_host_endpoint() {
    echo "$(log_date) push_host_endpoint ${host_id::4}... -> ${topic::4}...: ${host_endpoint}" > /dev/stderr
}

function log_pull_peer_endpoint() {
    while read peer_endpoint
    do
        echo "$(log_date) pull_peer_endpoint ${topic::4}... -> ${peer_id::4}...: ${peer_endpoint}" > /dev/stderr
        echo "${peer_endpoint}"
    done
}

# wirething topic

function wt_topic_timestamp() {
    epoch="$(date -u "+%s")"
    echo -n "$((${epoch} / 60 / 60))"
}

function wt_topic() {
    action="${1}" && shift
    
    tag_hash="$(echo -n ${WT_TOPIC_TAG} | sha256sum)"
    timestamp_hash="$(wt_topic_timestamp | sha256sum)"

    host_id_hash="$(echo -n "${host_id}" | sha256sum)"
    peer_id_hash="$(echo -n "${peer_id}" | sha256sum)"
    
    case "${action}" in
        push)
            echo -n "${tag_hash}:${timestamp_hash}:${host_id_hash}:${peer_id_hash}" | sha256sum
            ;;
        pull)
            echo -n "${tag_hash}:${timestamp_hash}:${peer_id_hash}:${host_id_hash}" | sha256sum
            ;;
    esac
}

# wirething host

function wt_punch() {
    punch open
    
    host_port="$(punch port)"
    host_endpoint="$(punch endpoint)"
    log_punch
    
    punch close
}

function wt_set_host() {
    log_set_host_port
    interface set host_port "${host_port}"
}

function wt_host_loop() {
    sleep "${WT_HOST_START_DELAY}"

    host_id="$(interface get host_id)"
    peer_id_list="$(interface get peers_id_list)"

    while true
    do
        wt_punch 
        wt_set_host

        for peer_id in ${peer_id_list}
        do
            topic="$(wt_topic push)"
            log_push_host_endpoint
            pubsub push "${topic}" "${host_endpoint}"
        done

        sleep "${WT_HOST_INTERVAL}"
    done
}

function wt_host_start() {
    wt_host_loop &
}

# wirething peer

function wt_set_peer() {
    while read peer_endpoint
    do
        log_set_peer_endpoint
        interface set peer_endpoint "${peer_id}" "${peer_endpoint}"
    done
}

function wt_pull_peer() {
    topic="$(wt_topic pull)"
    pubsub pull "${topic}" | log_pull_peer_endpoint
}

function wt_peer_loop() {
    sleep "${WT_PEER_START_DELAY}"
    while true
    do
        wt_pull_peer | wt_set_peer
        sleep "${WT_PEER_INTERVAL}"
    done
}

function wt_peer_start() {
    host_id="$(interface get host_id)"
    peer_id_list="$(interface get peers_id_list)"

    for peer_id in ${peer_id_list}
    do
        wt_peer_loop &
    done
}

# wirething main

#function start_wg() {
#    while true
#    do
#        sleep 15
#        interface status \
#            | grep "listening\|endpoint\|handshake\|transfer"
#    done
#}

function wt_open() {
    trap wt_close EXIT
    interface open
}

function wt_close() {
    echo
    interface close
    kill 0
}

# main

function main() {
    #start_wg &
    wt_open
    wt_peer_start
    wt_host_start

    wait $(jobs -p)
}

main
