#!/usr/bin/env bash

# log

function log_date() {
    date -Iseconds
}

function info() {
    echo "$(log_date) INFO ${@}" > /dev/stderr
}

function error() {
    echo "$(log_date) ERROR ${@}" > /dev/stderr
}

function die() {
    error "${@}" && exit 1
}

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

WT_INTERFACE_TYPE="${WT_INTERFACE_TYPE:-wg}"
case "${WT_INTERFACE_TYPE}" in
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
        die "Invalid WT_INTERFACE_TYPE *${WT_INTERFACE_TYPE}*, options: wg"
esac

WT_PUNCH_TYPE="${WT_PUNCH_TYPE:-udphole}"
case "${WT_PUNCH_TYPE}" in
    udphole)
        UDPHOLE_HOST="${UDPHOLE_HOST:-udphole.fly.dev}"
        UDPHOLE_PORT="${UDPHOLE_PORT:-53000}"
        ;;
    *)
        die "Invalid WT_PUNCH_TYPE *${WT_PUNCH_TYPE}*, options: udphole"
esac

WT_PUBSUB_TYPE="${WT_PUBSUB_TYPE:-ntfy}"
case "${WT_PUBSUB_TYPE}" in
    ntfy)
        NTFY_URL="${NTFY_URL:-https://ntfy.sh}"
        ;;
    *)
        die "Invalid WT_PUBSUB_TYPE *${WT_PUBSUB_TYPE}*, options: ntfy"
esac

[ "$(id -u)" != "0" ] \
    && die "Not a root user"

umask 077

case "${WT_INTERFACE_TYPE}" in
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
                    die "OS not supported *${OS}*"
            esac
        fi
        ;;
    *)
        die "Invalid WT_INTERFACE_TYPE *${WT_INTERFACE_TYPE}*, options: wg"
esac

# hacks

shopt -s expand_aliases

alias sha256sum='sha256sum | cut -f 1 -d " "'

[ "${WG_USERSPACE}" != "" ] \
    && alias wireguard-us="${WG_USERSPACE}"

alias interface="${WT_INTERFACE_TYPE}_interface"
alias punch="${WT_PUNCH_TYPE}_punch"
alias pubsub="${WT_PUBSUB_TYPE}_pubsub"

# wireguard

function wg_open_host() {
    [ ! -f "${WG_HOST_PRIVATE_KEY_FILE}" ] \
        && die "File WG_HOST_PRIVATE_KEY_FILE not found *${WG_HOST_PRIVATE_KEY_FILE}*"

    wg set "${WG_INTERFACE}" private-key "${WG_HOST_PRIVATE_KEY_FILE}"
}

function wg_open_peers() {
    for wg_peer_public_key_file in ${WG_PEER_PUBLIC_KEY_FILE_LIST}
    do
        [ ! -f "${wg_peer_public_key_file}" ] \
            && die "File in WG_PEER_PUBLIC_KEY_FILE_LIST not found *${wg_peer_public_key_file}*"

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
        protocol)
            echo "udp"
            ;;
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
    protocol="udp"
    case "${action}" in
        protocol)
            echo "${protocol}"
            ;;
        open)
            exec 100<>/dev/${protocol}/${UDPHOLE_HOST}/${UDPHOLE_PORT}
            echo "" >&100
            ;;
        port)
            lsof -R -P -n -i "${protocol}@${UDPHOLE_HOST}:${UDPHOLE_PORT}" \
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
    info "punch: ${host_endpoint} -> ${host_port}"
}

function log_set_host_port() {
    info "set_host_port ${host_id::4}...: ${host_port}"
}

function log_set_peer_endpoint() {
    info "set_peer_endpoint ${peer_id::4}...: ${peer_endpoint}"
}

function log_push_host_endpoint() {
    info "push_host_endpoint ${host_id::4}... -> ${topic::4}...: ${host_endpoint}"
}

function log_pull_peer_endpoint() {
    while read peer_endpoint
    do
        info "pull_peer_endpoint ${topic::4}... -> ${peer_id::4}...: ${peer_endpoint}"
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

function wt_open() {
    trap wt_close EXIT

    [ "$(punch protocol)" != "$(interface protocol)" ] \
        && die "Punch *${WT_PUNCH_TYPE}=$(punch protocol)* and interface *${WT_INTERFACE_TYPE}=$(interface protocol)* protocol differ"

    interface open
}

function wt_close() {
    echo
    interface close
    kill 0
}

# main

function main() {
    wt_open
    wt_peer_start
    wt_host_start

    wait $(jobs -p)
}

main
