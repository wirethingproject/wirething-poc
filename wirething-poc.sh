#!/usr/bin/env bash

# set: http://redsymbol.net/articles/unofficial-bash-strict-mode/
set -euo pipefail

shopt -s expand_aliases
alias sha256sum='sha256sum | cut -f 1 -d " "'

umask 077

export LC_ALL=C

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

function debug() {
    echo "$(log_date) DEBUG ${@}" > "${WT_DEBUG}"
}

function info() {
    echo "$(log_date) INFO ${@}" > "${WT_INFO}"
}

function error() {
    echo "$(log_date) ERROR ${@}" > "${WT_ERROR}"
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
                        info "wg_interface get host_id $(short "${host_id}")"
                        echo "${host_id}"
                    }
                    ;;
                peers_id_list)
                    wg show "${WG_INTERFACE}" peers | {
                        while read peer_id
                        do
                            info "wg_interface get peer_id $(short "${peer_id}")"
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

                    info "wg_interface set peer_endpoint $(short "${peer}") ${endpoint}"
                    wg set "${WG_INTERFACE}" peer "${peer}" endpoint "${endpoint}"
                    ;;
            esac
            ;;
        status)
            wg show interfaces \
                | grep "${WG_INTERFACE}" > "${WT_DEBUG}" \
                    && echo "up" \
                    || echo "down"
            ;;
    esac
}

# wireguard quick

function wg_quick_validate_files() {
    [ ! -f "${WGQ_HOST_PRIVATE_KEY_FILE}" ] \
        && die "File WGQ_HOST_PRIVATE_KEY_FILE not found *${WGQ_HOST_PRIVATE_KEY_FILE}*" \
        || true

    for peer_pub_file in ${WGQ_PEER_PUBLIC_KEY_FILE_LIST}
    do
        [ ! -f "${peer_pub_file}" ] \
            && die "File in WGQ_PEER_PUBLIC_KEY_FILE_LIST not found *${peer_pub_file}*" \
            || true
    done
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

            WGQ_HOST_ADDRESS="${WGQ_HOST_ADDRESS:-100.64.0.$((${RANDOM} % 254 + 1))}"

            WGQ_PEER_ALLOWED_IPS="${WGQ_PEER_ALLOWED_IPS:-100.64.0.0/24}"
            WGQ_PEER_PERSISTENT_KEEPALIVE="${WGQ_PEER_PERSISTENT_KEEPALIVE:-25}" # 25 seconds

            WGQ_LOG_LEVEL="${WGQ_LOG_LEVEL:-}"
            WGQ_USERSPACE="${WGQ_USERSPACE:-}"

            WGQ_INTERFACE="wirething-${WT_PID}"
            WGQ_CONFIG_FILE="${WT_EPHEMERAL_PATH}/${WGQ_INTERFACE}.conf"

            wg_quick_validate_files
            ;;
        up)
            debug "wg_quick_interface up"

            wg_quick_generate_config_file > "${WGQ_CONFIG_FILE}"

            export WG_QUICK_USERSPACE_IMPLEMENTATION="${WGQ_USERSPACE}"
            export LOG_LEVEL="${WGQ_LOG_LEVEL}"

            wg-quick up "${WGQ_CONFIG_FILE}" 2> "${WT_DEBUG}"

            case "${OSTYPE}" in
                darwin*)
                    WG_INTERFACE="$(cat "/var/run/wireguard/${WGQ_INTERFACE}.name")"
                    ;;
                linux*)
                    WG_INTERFACE="${WGQ_INTERFACE}"
                    ;;
                *)
                    die "OS not supported *${OSTYPE}*"
            esac
            ;;
        down)
            debug "wg_quick_interface down"

            [ "$(wg_interface status)" == "up" ] \
                && wg-quick down "${WGQ_CONFIG_FILE}" \
                || true

            rm -f "${WGQ_CONFIG_FILE}" && debug "wg_quick_interface *${WGQ_CONFIG_FILE}* was deleted"
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
            UDPHOLE_HOST="${UDPHOLE_HOST:-udphole.wirething.org}"
            UDPHOLE_PORT="${UDPHOLE_PORT:-6094}"
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
            NTFY_URL="${NTFY_URL:-https://ntfy.wirething.org}" # ntfy.wirething.org is a dns entry that redirects to ntfy.sh
            NTFY_CURL_OPTIONS="${NTFY_CURL_OPTIONS:--sS --no-buffer --location}"
            NTFY_PUBLISH_TIMEOUT="${NTFY_PUBLISH_TIMEOUT:-10}" # 10 seconds
            NTFY_SUBSCRIBE_TIMEOUT="${NTFY_SUBSCRIBE_TIMEOUT:-600}" # 10 minutes
            NTFY_SUBSCRIBE_PAUSE_AFTER_ERROR="${NTFY_SUBSCRIBE_PAUSE_AFTER_ERROR:-60}" # 60 seconds
            ;;
        publish)
            topic="${1}" && shift
            request="${1}" && shift
            info "ntfy_pubsub publish $(short "${topic}") $(short "${request}")"

            {
                curl ${NTFY_CURL_OPTIONS} --max-time "${NTFY_PUBLISH_TIMEOUT}" --stderr - \
                    "${NTFY_URL}/${topic}" -d "${request}" || true
            } | while read response
                do
                    echo "${response}" | hexdump -C > "${WT_TRACE}"

                    case "${response}" in
                        "{"*"event"*"message"*)
                            ;;
                        *)
                            error "ntfy_pubsub publish ${response}"
                    esac
                done
            ;;
        subscribe)
            topic="${1}" && shift
            debug "ntfy_pubsub subscribe $(short "${topic}")"

            {
                curl ${NTFY_CURL_OPTIONS} --max-time "${NTFY_SUBSCRIBE_TIMEOUT}" --stderr - \
                    "${NTFY_URL}/${topic}/raw" || true;
            } | while read response
                do
                    echo "${response}" | hexdump -C > "${WT_TRACE}"

                    case "${response}" in
                        "")
                            ;;
                        "{"*"error"*)
                            error "ntfy_pubsub subscribe ${response}"
                            sleep "${NTFY_SUBSCRIBE_PAUSE_AFTER_ERROR}"
                            ;;
                        "curl"*)
                            error "ntfy_pubsub subscribe ${response}"
                            sleep "${NTFY_SUBSCRIBE_PAUSE_AFTER_ERROR}"
                            ;;
                        "curl"*"timed out"*)
                            debug "ntfy_pubsub subscribe ${response}"
                            ;;
                        *)
                            info "ntfy_pubsub subscribe $(short "${topic}") $(short "${response}")"
                            echo "${response}"
                    esac
                done
            ;;
    esac
}

# disabled encryption

function disabled_encryption() {
    action="${1}" && shift
    case "${action}" in
        encrypt)
            data="${1}" && shift
            echo "${data}" | base64
            ;;
        decrypt)
            data="${1}" && shift
            echo "${data}" | base64 -d
            ;;
    esac
}

# gpg ephemeral

function gpg_ephemeral_validate_files() {
    for gpg_file in ${GPG_FILE_LIST}
    do
        [ ! -f "${gpg_file}" ] \
            && die "File in GPG_FILE_LIST not found *${gpg_file}*" \
            || true
    done
}

function gpg_ephemeral_encryption() {
    action="${1}" && shift
    case "${action}" in
        init)
            debug "gpg_ephemeral_encryption init"

            export GNUPGHOME="${WT_EPHEMERAL_PATH}/gpg"

            GPG_FILE_LIST="${GPG_FILE_LIST:?Variable not set}"
            GPG_DOMAIN_NAME="${GPG_DOMAIN_NAME:-wirething.gpg}"
            GPG_AGENT_CONF="${GPG_AGENT_CONF:-disable-scdaemon\n}"

            gpg_ephemeral_validate_files
            ;;
        up)
            debug "gpg_ephemeral_encryption up"

            mkdir -p "${GNUPGHOME}"

            echo -ne "${GPG_AGENT_CONF}" > "${GNUPGHOME}/gpg-agent.conf"

            for file in ${GPG_FILE_LIST}
            do
                gpg --import ${file} 2> "${WT_DEBUG}"
                gpg --show-keys --with-colons  "${file}" | grep "fpr" | cut -f "10-" -d ":" \
                    | sed "s,:,:6:," | gpg --import-ownertrust
            done

            host_id="$(interface get host_id)"
            peer_id_list="$(interface get peers_id_list)"

            for id in ${host_id} ${peer_id_list}
            do
                gpg --list-key "${id}@${GPG_DOMAIN_NAME}" > "${WT_DEBUG}" \
                    || die "Error GPG key *${id}@${GPG_DOMAIN_NAME}* not found"
            done

            value="${WT_PID}"
            encrypted_value="$(gpg_ephemeral_encryption encrypt "${host_id}" "${value}")"
            decrypted_value="$(gpg_ephemeral_encryption decrypt "${host_id}" "${encrypted_value}")"

            [ "${value}" != "${decrypted_value}" ] \
                && die "Error ${host_id}@${GPG_DOMAIN_NAME} could not encrypt and decrypt data" \
                || true

            for peer_id in ${peer_id_list}
            do
                gpg_ephemeral_encryption encrypt "${peer_id}" "${value}" \
                    || die "Error ${id}@${GPG_DOMAIN_NAME} could not encrypt data"
            done
            ;;
        down)
            debug "gpg_ephemeral_encryption down"
            rm -rf "${GNUPGHOME}" && debug "gpg_ephemeral_encryption *${GNUPGHOME}* was deleted"
            ;;
        encrypt)
            gpg_id="${1}" && shift
            data="${1}" && shift
            echo "${data}" \
                | gpg --batch --encrypt --sign --armor -r "${gpg_id}@${GPG_DOMAIN_NAME}" 2> "${WT_DEBUG}" \
                | base64
            ;;
        decrypt)
            gpg_id="${1}" && shift
            data="${1}" && shift
            echo "${data}" \
                | base64 -d \
                | gpg --batch --decrypt --default-key "${gpg_id}@${GPG_DOMAIN_NAME}" 2> "${WT_DEBUG}"
            ;;
    esac
}

# basic topic

function wirething_topic_timestamp() {
    echo -n "$((${EPOCHSECONDS} / ${WT_TOPIC_TIMESTAMP_OFFSET}))"
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
WT_ENCRYPTION_TYPE="${WT_ENCRYPTION_TYPE:-}"
WT_TOPIC_TYPE="${WT_TOPIC_TYPE:-wirething}"

alias interface="${WT_INTERFACE_TYPE}_interface"
alias punch="${WT_PUNCH_TYPE}_punch"
alias pubsub="${WT_PUBSUB_TYPE}_pubsub"
alias encryption="${WT_ENCRYPTION_TYPE}_encryption"
alias topic="${WT_TOPIC_TYPE}_topic"

interface ""    || die "Invalid WT_INTERFACE_TYPE *${WT_INTERFACE_TYPE}*, options: $(options interface)"
punch ""        || die "Invalid WT_PUNCH_TYPE *${WT_PUNCH_TYPE}*, options: $(options punch)"
pubsub ""       || die "Invalid WT_PUBSUB_TYPE *${WT_PUBSUB_TYPE}*, options: $(options pubsub)"
encryption ""   || die "Invalid WT_ENCRYPTION_TYPE *${WT_ENCRYPTION_TYPE}*, options: $(options encryption)"
topic ""        || die "Invalid WT_TOPIC_TYPE *${WT_TOPIC_TYPE}*, options: $(options topic)"

# wirething host

function wirething_host_loop() {
    debug "wirething_host start delay ${WT_HOST_START_DELAY}"
    sleep "${WT_HOST_START_DELAY}"

    while true
    do
        punch run | {
            read host_port
            read host_endpoint

            interface set host_port "${host_port}"

            for peer_id in ${peer_id_list}
            do
                encrypted_host_endpoint="$(encryption encrypt "${peer_id}" "${host_endpoint}")"
                pubsub publish "$(topic publish)" "${encrypted_host_endpoint}"
            done
        }

        debug "wirething_host publish interval ${WT_HOST_INTERVAL}"
        sleep "${WT_HOST_INTERVAL}"
    done
    debug "wirething_host end $(short "${host_id}")"
}

function wirething_host() {
    action="${1}" && shift
    case "${action}" in
        init)
            WT_HOST_START_DELAY="${WT_HOST_START_DELAY:-10}" # 10 seconds
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
    debug "wirething_peer start delay ${WT_HOST_START_DELAY}"
    sleep "${WT_PEER_START_DELAY}"

    while true
    do
        pubsub subscribe "$(topic subscribe)" | {
            while read encrypted_peer_endpoint
            do
                peer_endpoint="$(encryption decrypt "${host_id}" "${encrypted_peer_endpoint}")"
                interface set peer_endpoint "${peer_id}" "${peer_endpoint}"
            done
        }

        debug "wirething_peer subscribe interval ${WT_PEER_INTERVAL}"
        sleep "${WT_PEER_INTERVAL}"
    done
    debug "wirething_peer end $(short "${peer_id}")"
}

function wirething_peer() {
    action="${1}" && shift
    case "${action}" in
        init)
            WT_PEER_START_DELAY="${WT_PEER_START_DELAY:-1}" # 1 second
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
    encryption
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

            WT_TRACE="/dev/null"
            WT_DEBUG="/dev/null"
            WT_INFO="/dev/stderr"
            WT_ERROR="/dev/stderr"

            case "${WT_LOG_LEVEL}" in
                trace)
                    set -x
                    export PS4='+ :${LINENO} ${FUNCNAME[0]}(): '
                    WT_TRACE="/dev/stderr"
                    WT_DEBUG="/dev/stderr"
                    ;;
                debug)
                    WT_DEBUG="/dev/stderr"
                    ;;
                info)
                    ;;
                error)
                    WT_INFO="/dev/null"
                    ;;
                *)
                    die "Invalid WT_LOG_LEVEL *${WT_LOG_LEVEL}*, options: trace, debug, info, error"
            esac

            debug "wirething init"

            WT_PID="${BASHPID}"

            WT_RUN_PATH="${WT_RUN_PATH:-/var/run/wirething}"
            WT_EPHEMERAL_PATH="${WT_RUN_PATH}/${WT_PID}"

            wt_type_for_each init
            wt_validate_protocol "$(punch protocol)" "$(interface protocol)"
            ;;
        up)
            debug "wirething up"

            trap "wirething down" INT TERM EXIT
            mkdir -p "${WT_EPHEMERAL_PATH}"

            wt_type_for_each up
            ;;
        down)
            # Untrap to avoid infinite loops
            trap - INT TERM EXIT
            echo > /dev/stderr

            wt_type_for_each down

            debug "wirething down"
            rm -rf "${WT_EPHEMERAL_PATH}" && debug "wirething *${WT_EPHEMERAL_PATH}* was deleted"
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
