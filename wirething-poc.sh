#!/usr/bin/env bash

# set: http://redsymbol.net/articles/unofficial-bash-strict-mode/
set -euo pipefail

shopt -s expand_aliases
alias sha256sum='sha256sum | cut -f 1 -d " "'

export LC_ALL=C

umask 077

# auto_su: https://github.com/WireGuard/wireguard-tools/blob/master/src/wg-quick/linux.bash#L84

auto_su() {
    self="$(readlink -f "${BASH_SOURCE[0]}")"

    su_prompt="*${self##*/}* must be run as *root*. Please enter the password for *%u* to continue: "

	[[ ${UID} == 0 ]] \
        || exec sudo --preserve-env --prompt "${su_prompt}" -- "${BASH}" -- "${self}"
}

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

# wireguard

function wg_up_interface() {
    case "${OS}" in
        Darwin)
            WG_TUN_NAME_FILE="$(mktemp -t wirething)"
            LOG_LEVEL="${WG_LOG_LEVEL}" WG_TUN_NAME_FILE="${WG_TUN_NAME_FILE}" \
                "${WG_USERSPACE}" "utun"
            WG_TUN_NAME="$(cat "${WG_TUN_NAME_FILE}")"
            rm -f "${WG_TUN_NAME_FILE}"
            ;;
        Linux)
            WG_TUN_NAME="wt0$(basename "$(uuidgen)" | cut -f 1 -d "-")"
            LOG_LEVEL="${WG_LOG_LEVEL}" "${WG_USERSPACE}" "${WG_TUN_NAME}"
            ;;
        *)
            die "OS not supported *${OS}*"
    esac

    WG_INTERFACE="${WG_TUN_NAME}"
}

function wg_up_host() {
    [ ! -f "${WG_HOST_PRIVATE_KEY_FILE}" ] \
        && die "File WG_HOST_PRIVATE_KEY_FILE not found *${WG_HOST_PRIVATE_KEY_FILE}*"

    wg set "${WG_INTERFACE}" private-key "${WG_HOST_PRIVATE_KEY_FILE}"
}

function wg_up_peers() {
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
        init)
            WG_INTERFACE="${WG_INTERFACE:-}"
            [ "${WG_INTERFACE}" != "" ] && return 0

            WG_HOST_PRIVATE_KEY_FILE="${WG_HOST_PRIVATE_KEY_FILE:?Variable not set}"
            WG_PEER_PUBLIC_KEY_FILE_LIST="${WG_PEER_PUBLIC_KEY_FILE_LIST:?Variable not set}"

            WG_LOG_LEVEL="${WG_LOG_LEVEL:-info}"
            WG_USERSPACE="${WG_USERSPACE:-wireguard-go}"
            ;;
        up)
            [ "${WG_INTERFACE}" != "" ] && return 0

            wg_up_interface
            wg_up_host
            wg_up_peers
            ;;
        down)
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
        init)
            UDPHOLE_HOST="${UDPHOLE_HOST:-udphole.fly.dev}"
            UDPHOLE_PORT="${UDPHOLE_PORT:-53000}"
            ;;
        up)
            # https://www.xmodulo.com/tcp-udp-socket-bash-shell.html
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
        down)
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
        init)
            NTFY_URL="${NTFY_URL:-https://ntfy.sh}"
            ;;
        push)
            topic="${1}" && shift
            host_endpoint="${1}" && shift
            { curl -Ns --max-time "${WT_PUSH_TIMEOUT}" "${NTFY_URL}/${topic}" -d "${host_endpoint}" || true; } \
                > /dev/null
            ;;
        pull)
            topic="${1}" && shift
            { curl -Ns --max-time "${WT_PULL_TIMEOUT}" "${NTFY_URL}/${topic}/raw" || true; } \
                | ntfy_pull_filter
            ;;
    esac
}

# basic topic

function default_topic_timestamp() {
    epoch="$(date -u "+%s")"
    echo -n "$((${epoch} / 60 / 60))"
}

function default_topic_generate_values() {
    tag_hash="$(echo -n ${WT_DEFAULT_TOPIC_TAG} | sha256sum)"
    timestamp_hash="$(default_topic_timestamp | sha256sum)"

    host_id_hash="$(echo -n "${host_id}" | sha256sum)"
    peer_id_hash="$(echo -n "${peer_id}" | sha256sum)"
}

function default_topic() {
    action="${1}" && shift
    case "${action}" in
        init)
            WT_DEFAULT_TOPIC_TAG="${WT_DEFAULT_TOPIC_TAG:-wirething}"
            ;;
        push)
            default_topic_generate_values
            echo -n "${tag_hash}:${timestamp_hash}:${host_id_hash}:${peer_id_hash}" | sha256sum
            ;;
        pull)
            default_topic_generate_values
            echo -n "${tag_hash}:${timestamp_hash}:${peer_id_hash}:${host_id_hash}" | sha256sum
            ;;
    esac
}

# wirething hacks

WT_INTERFACE_TYPE="${WT_INTERFACE_TYPE:-wg}"
WT_PUNCH_TYPE="${WT_PUNCH_TYPE:-udphole}"
WT_PUBSUB_TYPE="${WT_PUBSUB_TYPE:-ntfy}"
WT_TOPIC_TYPE="${WT_TOPIC_TYPE:-default}"

alias interface="${WT_INTERFACE_TYPE}_interface"
alias punch="${WT_PUNCH_TYPE}_punch"
alias pubsub="${WT_PUBSUB_TYPE}_pubsub"
alias topic="${WT_TOPIC_TYPE}_topic"

interface "" || die "Invalid WT_INTERFACE_TYPE *${WT_INTERFACE_TYPE}*, options: wg"
punch ""     || die "Invalid WT_PUNCH_TYPE *${WT_PUNCH_TYPE}*, options: udphole"
pubsub ""    || die "Invalid WT_PUBSUB_TYPE *${WT_PUBSUB_TYPE}*, options: ntfy"
topic ""     || die "Invalid WT_TOPIC_TYPE *${WT_TOPIC_TYPE}*, options: default"

# wirething host

function default_host_punch() {
    punch up

    host_port="$(punch port)"
    host_endpoint="$(punch endpoint)"
    info "${short_host_id} punch ${host_port} <- ${host_endpoint}"

    punch down
}

function default_host_set_port() {
    info "${short_host_id} set_host_port ${host_port}"
    interface set host_port "${host_port}"
}

function default_host_push_endpoint() {
    topic="$(topic push)"
    short_topic="push:${topic::8}"

    info "${short_host_id} push_host_endpoint ${host_endpoint} -> ${short_topic}"
    pubsub push "${topic}" "${host_endpoint}"
}

function default_host_loop() {
    short_host_id="host:${host_id::8}"

    sleep "${WT_HOST_START_DELAY}"

    info "${short_host_id} host_loop started"
    while true
    do
        default_host_punch
        default_host_set_port

        for peer_id in ${peer_id_list}
        do
            short_peer_id="peer:${peer_id::8}"
            default_host_push_endpoint
        done

        sleep "${WT_HOST_INTERVAL}"
    done
    info "${short_host_id} host_loop stopped"
}

# wirething peer

function default_peer_set_endpoint() {
    while read peer_endpoint
    do
        info "${short_peer_id} set_peer_endpoint ${peer_endpoint}"
        interface set peer_endpoint "${peer_id}" "${peer_endpoint}"
    done
}

function default_peer_pull() {
    topic="$(topic pull)"
    short_topic="pull:${topic::8}"

    pubsub pull "${topic}" | while read peer_endpoint
    do
        info "${short_peer_id} pull_peer_endpoint ${peer_endpoint} <- ${short_topic}"
        echo "${peer_endpoint}"
    done
}

function default_peer_loop() {
    short_host_id="host:${host_id::8}"
    short_peer_id="peer:${peer_id::8}"

    sleep "${WT_PEER_START_DELAY}"

    info "${short_peer_id} peer_loop started"
    while true
    do
        default_peer_pull | default_peer_set_endpoint
        sleep "${WT_PEER_INTERVAL}"
    done
    info "${short_peer_id} peer_loop stopped"
}

# wirething main

function wirething() {
    action="${1}" && shift
    case "${action}" in
        init)
            OS="$(uname -s)"

            WT_HOST_START_DELAY="${WT_HOST_START_DELAY:-10}"
            WT_HOST_INTERVAL="${WT_HOST_INTERVAL:-900}" # 15 minutes
            WT_PEER_START_DELAY="${WT_PEER_START_DELAY:-1}"
            WT_PEER_INTERVAL="${WT_PEER_INTERVAL:-1}" # 1 second

            WT_PUSH_TIMEOUT="${WT_PUSH_TIMEOUT:-10}"
            WT_PULL_TIMEOUT="${WT_PULL_TIMEOUT:-60}"

            WT_ALLOWED_IPS="${WT_ALLOWED_IPS:-100.64.0.0/24}"
            WT_PERSISTENT_KEEPALIVE="${WT_PERSISTENT_KEEPALIVE:-25}"

            [ "$(punch protocol)" != "$(interface protocol)" ] \
                && die "Punch *${WT_PUNCH_TYPE}=$(punch protocol)* and interface *${WT_INTERFACE_TYPE}=$(interface protocol)* protocol differ"

            interface init
            punch init
            pubsub init
            topic init

            info "init done"
            ;;
        up)
            trap "wirething down" EXIT
            interface up

            info "up done"
            ;;
        down)
            echo
            interface down
            info "down done"
            kill 0
            ;;
        start)
            param="${1}" && shift
            host_id="$(interface get host_id)"
            peer_id_list="$(interface get peers_id_list)"

            case "${param}" in
                host)
                    default_host_loop &
                    ;;
                peers)
                    for peer_id in ${peer_id_list}
                    do
                        default_peer_loop &
                    done
                    ;;
            esac
            ;;
        wait)
            wait $(jobs -p)
            ;;
    esac
}

# main

function main() {
    wirething init

    auto_su
    wirething up

    wirething start host
    wirething start peers

    wirething wait
}

main
