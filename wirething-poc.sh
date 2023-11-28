#!/usr/bin/env bash

# set: http://redsymbol.net/articles/unofficial-bash-strict-mode/
set -euo pipefail

shopt -s expand_aliases
alias sha256sum='sha256sum | cut -f 1 -d " "'

umask 077

export LC_ALL=C
export OS="$(uname -s)"

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

function debug() {
    [ "${WT_LOG_LEVEL}" != "debug" ] && return 0
    echo "$(log_date) DEBUG ${@}" > /dev/stderr
}

function error() {
    echo "$(log_date) ERROR ${@}" > /dev/stderr
}

function die() {
    error "${@}" && exit 1
}

function short() {
    echo "${1::8}"
}

# wireguard

function wg_interface() {
    action="${1}" && shift
    case "${action}" in
        protocol)
            echo "udp"
            ;;
        init)
            debug "wg_interface init"
            WG_INTERFACE="${WG_INTERFACE:?Variable not set}"
            ;;
        up)
            debug "wg_interface up"
            [ "$(wg_interface status)" == "down" ] \
                && die "Wireguard interface *${WG_INTERFACE}* not found." \
                || true
            ;;
        get)
            param="${1}" && shift
            case "${param}" in
                host_id)
                    wg show "${WG_INTERFACE}" public-key | {
                        read host_id
                        info "wg_interface get host_id $(short ${host_id})"
                        echo "${host_id}"
                    }
                    ;;
                peers_id_list)
                    wg show "${WG_INTERFACE}" peers | {
                        while read peer_id
                        do
                            info "wg_interface get peer_id $(short ${peer_id})"
                            echo "${peer_id}"
                        done
                    }
            esac
            ;;
        set)
            param="${1}" && shift
            case "${param}" in
                host_port)
                    port="${1}" && shift

                    info "wg_interface set host_port ${port}"
                    wg set "${WG_INTERFACE}" listen-port "${port}"
                    ;;
                peer_endpoint)
                    peer="${1}" && shift
                    endpoint="${1}" && shift

                    info "wg_interface set peer_endpoint $(short ${peer}) ${endpoint}"
                    wg set "${WG_INTERFACE}" peer "${peer}" endpoint "${endpoint}"
                    ;;
            esac
            ;;
        status)
            wg show interfaces \
                | grep "${WG_INTERFACE}" > /dev/null \
                && echo "up" \
                || echo "down"
            ;;
    esac
}

# wireguard quick

function wg_quick_validate_files() {
    [ ! -f "${WGQ_HOST_PRIVATE_KEY_FILE}" ] \
        && die "File WGQ_HOST_PRIVATE_KEY_FILE not found *${WGQ_HOST_PRIVATE_KEY_FILE}*"

    for peer_pub_file in ${WGQ_PEER_PUBLIC_KEY_FILE_LIST}
    do
        [ ! -f "${peer_pub_file}" ] \
            && die "File in WGQ_PEER_PUBLIC_KEY_FILE_LIST not found *${peer_pub_file}*"
    done
    return 0
}

function wg_quick_generate_config_file() {
    cat <<EOF
[Interface]
PrivateKey = $(cat "${WGQ_HOST_PRIVATE_KEY_FILE}")
Address = ${WGQ_HOST_ADDRESS}

EOF

    for peer_pub_file in ${WGQ_PEER_PUBLIC_KEY_FILE_LIST}
    do
    cat <<EOF
[Peer]
PublicKey = $(cat "${peer_pub_file}")
AllowedIPs = ${WGQ_PEER_ALLOWED_IPS}
PersistentKeepalive = ${WGQ_PEER_PERSISTENT_KEEPALIVE}

EOF
    done
}

function wg_quick_interface() {
    action="${1}" && shift
    case "${action}" in
        protocol)
            echo "udp"
            ;;
        init)
            debug "wg_quick_interface init"

            WGQ_HOST_PRIVATE_KEY_FILE="${WGQ_HOST_PRIVATE_KEY_FILE:?Variable not set}"
            WGQ_PEER_PUBLIC_KEY_FILE_LIST="${WGQ_PEER_PUBLIC_KEY_FILE_LIST:?Variable not set}"

            WGQ_HOST_ADDRESS="${WGQ_HOST_ADDRESS:-100.64.0.$(($RANDOM%254 + 1))}"

            WGQ_PEER_ALLOWED_IPS="${WGQ_PEER_ALLOWED_IPS:-100.64.0.0/24}"
            WGQ_PEER_PERSISTENT_KEEPALIVE="${WGQ_PEER_PERSISTENT_KEEPALIVE:-25}"

            WGQ_LOG_LEVEL="${WGQ_LOG_LEVEL:-}"
            WGQ_USERSPACE="${WGQ_USERSPACE:-}"

            WGQ_INTERFACE="wirething-$(uuidgen | cut -c 1-5)"

            case "${OS}" in
                Darwin)
                    WGQ_CONFIG_PATH="${WGQ_CONFIG_PATH:-/usr/local/etc/wireguard}"
                    ;;
                Linux)
                    WGQ_CONFIG_PATH="${WGQ_CONFIG_PATH:-/etc/wireguard}"
                    ;;
                *)
                    die "OS not supported *${OS}*"
            esac

            WGQ_CONFIG_FILE="${WGQ_CONFIG_PATH}/${WGQ_INTERFACE}.conf"

            wg_quick_validate_files
            ;;
        up)
            debug "wg_quick_interface up"

            mkdir -p "${WGQ_CONFIG_PATH}"
            wg_quick_generate_config_file > "${WGQ_CONFIG_FILE}"

            export WG_QUICK_USERSPACE_IMPLEMENTATION="${WGQ_USERSPACE}"
            export LOG_LEVEL="${WGQ_LOG_LEVEL}"

            wg-quick up "${WGQ_CONFIG_FILE}"

            case "${OS}" in
                Darwin)
                    WG_INTERFACE="$(cat "/var/run/wireguard/${WGQ_INTERFACE}.name")"
                    ;;
                Linux)
                    WG_INTERFACE="${WGQ_INTERFACE}"
                    ;;
                *)
                    die "OS not supported *${OS}*"
            esac
            ;;
        down)
            debug "wg_quick_interface down"

            [ "$(wg_interface status)" == "up" ] \
                && wg-quick down "${WGQ_CONFIG_FILE}"

            rm "${WGQ_CONFIG_FILE}" && debug "wg_quick_interface ${WGQ_CONFIG_FILE} was deleted"
            ;;
        get|set)
            wg_interface ${action} ${@}
            ;;
    esac
}

# udphole

function udphole_punch() {
    action="${1}" && shift
    case "${action}" in
        protocol)
            echo "udp"
            ;;
        init)
            debug "udphole_punch init"
            UDPHOLE_HOST="${UDPHOLE_HOST:-udphole.fly.dev}"
            UDPHOLE_PORT="${UDPHOLE_PORT:-53000}"
            ;;
        run)
            debug "udphole_punch run"
            udphole_punch open
            {
                udphole_punch get port
                udphole_punch get endpoint
            } | {
                read port
                read endpoint

                udphole_punch close

                echo "${port}"
                echo "${endpoint}"
            }
            ;;
        open)
            debug "udphole_punch open"
            # https://www.xmodulo.com/tcp-udp-socket-bash-shell.html
            exec 100<>/dev/udp/${UDPHOLE_HOST}/${UDPHOLE_PORT}
            echo "" >&100
            UDPHOLE_OPEN_PID="${BASHPID}"
            ;;
        get)
            param="${1}" && shift
            case "${param}" in
                port)
                    { lsof -P -n -i "udp@${UDPHOLE_HOST}:${UDPHOLE_PORT}" -a -p "${UDPHOLE_OPEN_PID}" \
                        || echo " ${UDPHOLE_OPEN_PID} UDP :0->"; } \
                        | grep -m 1 " ${UDPHOLE_OPEN_PID} " \
                        | sed "s,.* UDP .*:\(.*\)->.*,\1," | {
                        read port
                        info "udphole_punch get port ${port}"
                        echo "${port}"
                    }
                    ;;
                endpoint)
                    head -n 1 <&100 | {
                        read endpoint
                        info "udphole_punch get endpoint ${endpoint}"
                        echo "${endpoint}"
                    }
                    ;;
            esac
            ;;
        close)
            debug "udphole_punch close"
            exec 100<&-
            exec 100>&-
            unset UDPHOLE_OPEN_PID
            ;;
    esac
}

# ntfy

function ntfy_pubsub() {
    action="${1}" && shift
    case "${action}" in
        init)
            debug "ntfy_pubsub init"
            NTFY_URL="${NTFY_URL:-https://ntfy.sh}"
            NTFY_PUBLISH_TIMEOUT="${NTFY_PUBLISH_TIMEOUT:-10}"
            NTFY_SUBSCRIBE_TIMEOUT="${NTFY_SUBSCRIBE_TIMEOUT:-60}"
            ;;
        publish)
            topic="${1}" && shift
            host_endpoint="${1}" && shift
            info "ntfy_pubsub publish $(short ${topic}) ${host_endpoint}"
            { curl -Ns --max-time "${NTFY_PUBLISH_TIMEOUT}" "${NTFY_URL}/${topic}" -d "${host_endpoint}" || true; } \
                > /dev/null
            ;;
        subscribe)
            topic="${1}" && shift
            { curl -Ns --max-time "${NTFY_SUBSCRIBE_TIMEOUT}" "${NTFY_URL}/${topic}/raw" || true; } \
                | while read peer_endpoint
                do
                    if [ "${peer_endpoint}" != "" ]
                    then
                        info "ntfy_pubsub subscribe $(short ${topic}) ${peer_endpoint}"
                        echo "${peer_endpoint}"
                    fi
                done
            ;;
    esac
}

# basic topic

function wirething_topic_timestamp() {
    epoch="$(date -u "+%s")"
    echo -n "$((${epoch} / ${WT_TOPIC_TIMESTAMP_OFFSET}))"
}

function wirething_topic_hash_values() {
    tag_hash="$(echo -n ${WT_TOPIC_TAG} | sha256sum)"
    timestamp_hash="$(wirething_topic_timestamp | sha256sum)"
    host_id_hash="$(echo -n "${host_id}" | sha256sum)"
    peer_id_hash="$(echo -n "${peer_id}" | sha256sum)"
}

function wirething_topic() {
    action="${1}" && shift
    case "${action}" in
        init)
            debug "wirething_topic init"
            WT_TOPIC_TAG="${WT_TOPIC_TAG:-wirething}"
            WT_TOPIC_TIMESTAMP_OFFSET="${WT_TOPIC_TIMESTAMP_OFFSET:-3600}" # 60 minutes
            ;;
        publish)
            wirething_topic_hash_values
            echo -n "${tag_hash}:${timestamp_hash}:${host_id_hash}:${peer_id_hash}" | sha256sum
            ;;
        subscribe)
            wirething_topic_hash_values
            echo -n "${tag_hash}:${timestamp_hash}:${peer_id_hash}:${host_id_hash}" | sha256sum
            ;;
    esac
}

# wirething hacks

function options() {
    set | grep "_${1} ()" | sed "s,_${1} (),," | tr -d "\n"
}

WT_INTERFACE_TYPE="${WT_INTERFACE_TYPE:-wg_quick}"
WT_PUNCH_TYPE="${WT_PUNCH_TYPE:-udphole}"
WT_PUBSUB_TYPE="${WT_PUBSUB_TYPE:-ntfy}"
WT_TOPIC_TYPE="${WT_TOPIC_TYPE:-wirething}"

alias interface="${WT_INTERFACE_TYPE}_interface"
alias punch="${WT_PUNCH_TYPE}_punch"
alias pubsub="${WT_PUBSUB_TYPE}_pubsub"
alias topic="${WT_TOPIC_TYPE}_topic"

interface "" || die "Invalid WT_INTERFACE_TYPE *${WT_INTERFACE_TYPE}*, options: $(options interface)"
punch ""     || die "Invalid WT_PUNCH_TYPE *${WT_PUNCH_TYPE}*, options: $(options punch)"
pubsub ""    || die "Invalid WT_PUBSUB_TYPE *${WT_PUBSUB_TYPE}*, options: $(options pubsub)"
topic ""     || die "Invalid WT_TOPIC_TYPE *${WT_TOPIC_TYPE}*, options: $(options topic)"

# wirething host

function wirething_host_loop() {
    sleep "${WT_HOST_START_DELAY}"

    while true
    do
        punch run | {
            read host_port
            read host_endpoint

            interface set host_port "${host_port}"

            for peer_id in ${peer_id_list}
            do
                pubsub publish "$(topic publish)" "${host_endpoint}"
            done
        }

        sleep "${WT_HOST_INTERVAL}"
    done
}

function wirething_host() {
    action="${1}" && shift
    case "${action}" in
        init)
            WT_HOST_START_DELAY="${WT_HOST_START_DELAY:-10}"
            WT_HOST_INTERVAL="${WT_HOST_INTERVAL:-900}" # 15 minutes
            ;;
        start)
            debug "wirething_host start $(short "${host_id}")"
            wirething_host_loop &
            ;;
    esac
}

# wirething peer

function wirething_peer_loop() {
    sleep "${WT_PEER_START_DELAY}"

    while true
    do
        pubsub subscribe "$(topic subscribe)" | {
            while read peer_endpoint
            do
                interface set peer_endpoint "${peer_id}" "${peer_endpoint}"
            done
        }

        sleep "${WT_PEER_INTERVAL}"
    done
}

function wirething_peer() {
    action="${1}" && shift
    case "${action}" in
        init)
            WT_PEER_START_DELAY="${WT_PEER_START_DELAY:-1}"
            WT_PEER_INTERVAL="${WT_PEER_INTERVAL:-1}" # 1 second
            ;;
        start)
            debug "wirething_peer start $(short "${peer_id}")"
            wirething_peer_loop &
            ;;
    esac
}

# more wirething hacks

WT_HOST_TYPE="${WT_HOST_TYPE:-wirething}"
WT_PEER_TYPE="${WT_PEER_TYPE:-wirething}"

alias host="${WT_HOST_TYPE}_host"
alias peer="${WT_PEER_TYPE}_peer"

host ""     || die "Invalid WT_HOST_TYPE *${WT_HOST_TYPE}*, options: $(options host)"
peer ""     || die "Invalid WT_PEER_TYPE *${WT_PEER_TYPE}*, options: $(options peer)"

# wirething main

wt_type_list=(
    interface
    punch
    pubsub
    topic
    host
    peer
)

function wt_get_alias() {
    alias ${i} | cut -f 2 -d "'"
}

function wt_type_for_each() {
    for i in "${wt_type_list[@]}"; do
        "$(wt_get_alias $i)" "${1}"
    done
}

function wt_validate_protocol() {
    punch="${1}" && shift
    interface="${1}" && shift
    [ "${punch}" != "${interface}" ] \
        && die "Punch *${WT_PUNCH_TYPE}=${punch}* and interface *${WT_INTERFACE_TYPE}=${interface}* protocol differ" \
        || true
}

function wirething() {
    action="${1}" && shift
    case "${action}" in
        init)
            WT_LOG_LEVEL="${WT_LOG_LEVEL:-info}"
            debug "wirething init"
            wt_type_for_each init
            wt_validate_protocol "$(punch protocol)" "$(interface protocol)"
            ;;
        up)
            debug "wirething up"
            wt_type_for_each up
            trap "wirething down" INT TERM EXIT
            ;;
        down)
            # Untrap to avoid infinite loops
            trap - INT TERM EXIT
            echo > /dev/stderr
            debug "wirething down"
            wt_type_for_each down
            kill 0
            ;;
        start)
            debug "wirething start"
            host_id="$(interface get host_id)"
            peer_id_list="$(interface get peers_id_list)"

            host start

            for peer_id in ${peer_id_list}
            do
                peer start
            done
            ;;
        wait)
            debug "wirething wait"
            wait $(jobs -p)
            ;;
    esac
}

# main

function main() {
    wirething init
    auto_su
    wirething up
    wirething start
    wirething wait
}

main
