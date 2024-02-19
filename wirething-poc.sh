#!/usr/bin/env bash

# Basic

# set: http://redsymbol.net/articles/unofficial-bash-strict-mode/
set -euo pipefail

shopt -s expand_aliases

umask 077

export LC_ALL=C

# Utils

alias sha256sum='sha256sum | cut -f 1 -d " "'

case "${OSTYPE}" in
    darwin*)
        alias base64='base64'
        ;;
    linux*)
        alias base64='base64 -w 0'
        ;;
    *)
        die "OS not supported *${OSTYPE}*"
esac

function to_upper() {
    echo ${1} | tr "[:lower:]" "[:upper:]"
}

# auto_su: https://github.com/WireGuard/wireguard-tools/blob/master/src/wg-quick/linux.bash#L84
auto_su() {
    self="$(readlink -f "${BASH_SOURCE[0]}")"
    su_prompt="*${self##*/}* must be run as *root*. Please enter the password for *%u* to continue: "

	[[ ${UID} == 0 ]] \
        || exec sudo --preserve-env --prompt "${su_prompt}" -- "${BASH}" -- "${self}"
}

# Bash Compat

function bash_compat() {
    if [[ (${BASH_VERSINFO[0]} -gt ${1}) ||
          (${BASH_VERSINFO[0]} -eq ${1} && ${BASH_VERSINFO[1]} -ge ${2}) ]]
    then
        return 0
    else
        return 1
    fi
}

function epoch() {
    echo -n "${EPOCHSECONDS:-$(date -u +"%s")}"
}

function pid() {
    echo "${BASHPID:-${$}}"
}

function log_dev() {
    if bash_compat 4 1
    then
        exec {null}>>/dev/null
        exec {err}>&2
    else
        exec 5>>/dev/null
        exec 6>&2
        null="5"
        err="6"
    fi
}

# Bash Compat UDP

function udp() {
    action="${1}" && shift
    case "${action}" in
        open)
            host="${1}" && shift
            port="${1}" && shift

            if bash_compat 4 1
            then
                exec {UDP_SOCKET}<>/dev/udp/${host}/${port}
            else
                UDP_SOCKET=100
                exec 100<>/dev/udp/${host}/${port}
            fi
            ;;
        close)
            if bash_compat 4 1
            then
                exec {UDP_SOCKET}<&- || true
                exec {UDP_SOCKET}>&- || true
            else
                exec 100<&- || true
                exec 100>&- || true
            fi

            unset UDP_SOCKET
            ;;
        port)
            host="${1}" && shift
            port="${1}" && shift
            pid="${1}" && shift

            {
                lsof -P -n -i "udp@${host}:${port}" -a -p "${pid}" \
                    || echo " ${pid} UDP :0->"
            } | {
                grep -m 1 " ${pid} " | sed "s,.* UDP .*:\(.*\)->.*,\1,"
            }
            ;;
        writeline)
            line="${1}" && shift
            echo "${line}" >&${UDP_SOCKET}
            ;;
        readline)
            head -n 1 <&${UDP_SOCKET} || true
            ;;
    esac
}

# log

function log_default_time() {
    if [ "${SYSTEMD_EXEC_PID:-}" != "" ]
    then
        echo -n "false"
    else
        echo -n "true"
    fi
}

function log_init() {
    WT_LOG_TIME="${WT_LOG_TIME:-$(log_default_time)}"
    WT_LOG_LEVEL="${WT_LOG_LEVEL:-info}"

    log_dev

    WT_LOG_TRACE="${null}"
    WT_LOG_DEBUG="${null}"
    WT_LOG_INFO="${err}"
    WT_LOG_ERROR="${err}"

    case "${WT_LOG_LEVEL}" in
        trace)
            set -x
            export PS4='+ :${LINENO} ${FUNCNAME[0]}(): '
            WT_LOG_TRACE="${err}"
            WT_LOG_DEBUG="${err}"
            ;;
        debug)
            WT_LOG_DEBUG="${err}"
            ;;
        info)
            ;;
        error)
            WT_LOG_INFO="${null}"
            ;;
        *)
            die "Invalid WT_LOG_LEVEL *${WT_LOG_LEVEL}*, options: trace, debug, info, error"
    esac
}

function log() {
    [ "${WT_LOG_TIME}" == "true" ] \
        && echo -n "$(date -Iseconds) " || true

    echo "${@}"
}

function raw_trace() {
    log "TRACE" >&${WT_LOG_TRACE} || true
    cat >&${WT_LOG_TRACE} || true
}

function debug() {
    log "DEBUG" "${@}" >&${WT_LOG_DEBUG} || true
}

function info() {
    log "INFO" "${@}" >&${WT_LOG_INFO} || true
}

function error() {
    log "ERROR" "${@}" >&${WT_LOG_ERROR} || true
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
            WG_HANDSHAKE_TIMEOUT="${WG_HANDSHAKE_TIMEOUT:-125}" # 125 seconds
            ;;
        up)
            debug "wg_interface up"
            [ "$(wg_interface status)" == "down" ] \
                && die "Wireguard interface *${WG_INTERFACE:-}* not found." \
                || true
            ;;
        set)
            name="${1}" && shift
            case "${name}" in
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
        get)
            name="${1}" && shift
            case "${name}" in
                host_id)
                    {
                        wg show "${WG_INTERFACE}" public-key
                    } | {
                        read host_id
                        info "wg_interface get host_id $(short "${host_id}")"
                        echo "${host_id}"
                    }
                    ;;
                peers_id_list)
                    {
                        wg show "${WG_INTERFACE}" peers
                    } | {
                        while read peer_id
                        do
                            info "wg_interface get peer_id $(short "${peer_id}")"
                            echo "${peer_id}"
                        done
                    }
                    ;;
                peer_endpoint)
                    peer="${1}" && shift

                    {
                        wg show "${WG_INTERFACE}" endpoints
                    } | {
                        grep "${peer}" | cut -f 2 | sed "s,(none),,"
                    } | {
                        read endpoint
                        info "wg_interface get peer_endpoint $(short "${peer}") ${endpoint}"
                        echo "${endpoint}"
                    }
                    ;;
                latest_handshakes)
                    peer="${1}" && shift

                    {
                        wg show "${WG_INTERFACE}" latest-handshakes
                    } | {
                        grep "${peer}" | cut -f 2
                    } | {
                        read handshake
                        info "wg_interface get latest_handshakes $(short "${peer}") ${handshake}"
                        echo "${handshake}"
                    }
                    ;;
                handshake_timeout)
                    peer="${1}" && shift

                    last_handshake="$(interface get latest_handshakes "${peer_id}")"
                    handshake_timeout="$(($(epoch) - ${last_handshake} - ${WG_HANDSHAKE_TIMEOUT}))"

                    if [[ ${handshake_timeout} -gt 0 ]]
                    then
                        result="true"
                    else
                        result="false"
                    fi

                    info "wg_interface get handshake_timeout $(short "${peer}") ${result}"
                    echo "${result}"
                    ;;
            esac
            ;;
        status)
            {
                wg show interfaces
            } | {
                status="down"

                if [ "${WG_INTERFACE:-}" != "" ] && grep "${WG_INTERFACE}" 1>&${WT_LOG_DEBUG}
                then
                    status="up"
                fi

                info "wg_interface status ${status}"
                echo "${status}"
            }
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
        peer_name="${peer_pub_file##*/}" # remove path
        peer_name="${peer_name%.pub}" # remove extension
        peer_name="$(to_upper ${peer_name})" # to upper

        WGQ_PEER_ALLOWED_IPS="WGQ_PEER_${peer_name}_ALLOWED_IPS" # build the variable name

        cat <<EOF
[Peer]
PublicKey = $(cat "${peer_pub_file}")
AllowedIPs = ${!WGQ_PEER_ALLOWED_IPS:-}
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

            WGQ_PEER_ALLOWED_IPS="${WGQ_PEER_ALLOWED_IPS:-${WGQ_HOST_ADDRESS}/32}"
            WGQ_PEER_PERSISTENT_KEEPALIVE="${WGQ_PEER_PERSISTENT_KEEPALIVE:-25}" # 25 seconds

            WGQ_LOG_LEVEL="${WGQ_LOG_LEVEL:-}"
            WGQ_USERSPACE="${WGQ_USERSPACE:-}"

            WGQ_INTERFACE="wth${WT_PID}"
            WGQ_CONFIG_FILE="${WT_EPHEMERAL_PATH}/${WGQ_INTERFACE}.conf"

            wg_quick_validate_files
            ;;
        up)
            debug "wg_quick_interface up"

            wg_quick_generate_config_file | grep -v "= $" > "${WGQ_CONFIG_FILE}"

            export WG_QUICK_USERSPACE_IMPLEMENTATION="${WGQ_USERSPACE}"
            export LOG_LEVEL="${WGQ_LOG_LEVEL}"

            wg-quick up "${WGQ_CONFIG_FILE}" 2>&${WT_LOG_DEBUG}

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
            wg_interface init
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
            UDPHOLE_HOST="${UDPHOLE_HOST:-udphole.wirething.org}" # udphole.wirething.org is a dns cname poiting to hdphole.fly.dev
            UDPHOLE_PORT="${UDPHOLE_PORT:-6094}"
            UDPHOLE_READ_TIMEOUT="${UDPHOLE_READ_TIMEOUT:-10}" # 10 seconds
            ;;
        open)
            debug "udphole_punch open"
            udp open ${UDPHOLE_HOST} ${UDPHOLE_PORT} \
                && udp writeline ""
            ;;
        get)
            name="${1}" && shift
            case "${name}" in
                port)
                    {
                        udp port ${UDPHOLE_HOST} ${UDPHOLE_PORT} ${PUNCH_PID}
                    } | {
                        read -t "${UDPHOLE_READ_TIMEOUT}" port
                        if [[ ${?} -lt 128 ]]
                        then
                            info "udphole_punch get port ${port}"
                            echo "${port}"
                        else
                            error "udphole_punch get port timed out"
                            echo ""
                        fi
                    }
                    ;;
                endpoint)
                    {
                        udp readline
                    } | {
                        read -t "${UDPHOLE_READ_TIMEOUT}" endpoint
                        if [[ ${?} -lt 128 ]]
                        then
                            info "udphole_punch get endpoint ${endpoint}"
                            echo "${endpoint}"
                        else
                            error "udphole_punch get endpoint timed out"
                            echo ""
                        fi
                    }
                    ;;
            esac
            ;;
        close)
            debug "udphole_punch close"
            udp close
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
            NTFY_CURL_OPTIONS="${NTFY_CURL_OPTIONS:--sS --no-buffer --location}"
            NTFY_PUBLISH_TIMEOUT="${NTFY_PUBLISH_TIMEOUT:-25}" # 25 seconds
            NTFY_SUBSCRIBE_TIMEOUT="${NTFY_SUBSCRIBE_TIMEOUT:-600}" # 10 minutes
            NTFY_SUBSCRIBE_PAUSE_AFTER_ERROR="${NTFY_SUBSCRIBE_PAUSE_AFTER_ERROR:-${WT_PAUSE_AFTER_ERROR}}" # ${WT_PAUSE_AFTER_ERROR} seconds
            ;;
        publish)
            topic="${1}" && shift
            request="${1}" && shift
            info "ntfy_pubsub publish $(short "${topic}") $(short "${request}")"

            {
                curl ${NTFY_CURL_OPTIONS} --max-time "${NTFY_PUBLISH_TIMEOUT}" --stderr - \
                    "${NTFY_URL}/${topic}" -d "${request}" \
                    || true
            } | {
                while read publish_response
                do
                    echo "${publish_response}" | hexdump -C | raw_trace

                    case "${publish_response}" in
                        "{"*"event"*"message"*)
                            ;;
                        *)
                            error "ntfy_pubsub publish ${publish_response}"
                    esac
                done
            }
            ;;
        subscribe)
            topic="${1}" && shift
            debug "ntfy_pubsub subscribe $(short "${topic}")"

            {
                curl ${NTFY_CURL_OPTIONS} --max-time "${NTFY_SUBSCRIBE_TIMEOUT}" --stderr - \
                    "${NTFY_URL}/${topic}/raw" \
                    || true
            } | {
                while read subscribe_response
                do
                    echo "${subscribe_response}" | hexdump -C | raw_trace

                    case "${subscribe_response}" in
                        "")
                            ;;
                        "curl"*"timed out"*)
                            debug "ntfy_pubsub subscribe ${subscribe_response}"
                            ;;
                        "curl"*)
                            error "ntfy_pubsub subscribe ${subscribe_response}"
                            sleep "${NTFY_SUBSCRIBE_PAUSE_AFTER_ERROR}"
                            ;;
                        "{"*"error"*)
                            error "ntfy_pubsub subscribe ${subscribe_response}"
                            sleep "${NTFY_SUBSCRIBE_PAUSE_AFTER_ERROR}"
                            ;;
                        *)
                            info "ntfy_pubsub subscribe $(short "${topic}") $(short "${subscribe_response}")"
                            echo "${subscribe_response}"
                    esac
                done
            }
            ;;
    esac
}

# disabled encryption

function disabled_encryption() {
    action="${1}" && shift
    case "${action}" in
        encrypt)
            id="${1}" && shift
            data="${1}" && shift
            echo "${data}" | base64
            ;;
        decrypt)
            id="${1}" && shift
            data="${1}" && shift
            echo "${data}" | base64 -d
            ;;
    esac
}

# gpg ephemeral

function gpg_ephemeral_encryption() {
    action="${1}" && shift
    case "${action}" in
        init)
            debug "gpg_ephemeral_encryption init"

            export GNUPGHOME="${WT_EPHEMERAL_PATH}/gpg"

            GPG_FILE_LIST="${GPG_FILE_LIST:?Variable not set}"
            GPG_DOMAIN_NAME="${GPG_DOMAIN_NAME:-wirething.gpg}"
            GPG_OPTIONS="${GPG_OPTIONS:---disable-dirmngr --no-auto-key-locate --batch --no}"
            GPG_AGENT_CONF="${GPG_AGENT_CONF:-disable-scdaemon\nextra-socket /dev/null\nbrowser-socket /dev/null\n}" # Disabling scdaemon (smart card daemon) make gpg do not try to use your Yubikey

            for gpg_file in ${GPG_FILE_LIST}
            do
                [ ! -f "${gpg_file}" ] \
                    && die "File in GPG_FILE_LIST not found *${gpg_file}*" \
                    || true
            done
            ;;
        up)
            debug "gpg_ephemeral_encryption up"

            mkdir -p "${GNUPGHOME}"

            echo -ne "${GPG_AGENT_CONF}" > "${GNUPGHOME}/gpg-agent.conf"

            for file in ${GPG_FILE_LIST}
            do
                gpg ${GPG_OPTIONS} --import ${file} 2>&${WT_LOG_DEBUG}
                gpg ${GPG_OPTIONS} --show-keys --with-colons "${file}" 2>&${WT_LOG_DEBUG} \
                    | grep "fpr" | cut -f "10-" -d ":" | sed "s,:,:6:," \
                    | gpg ${GPG_OPTIONS} --import-ownertrust 2>&${WT_LOG_DEBUG}
            done
            ;;
        down)
            debug "gpg_ephemeral_encryption down"
            gpgconf --kill gpg-agent
            rm -rf "${GNUPGHOME}" && debug "gpg_ephemeral_encryption *${GNUPGHOME}* was deleted"
            ;;
        encrypt)
            id="${1}" && shift
            data="${1}" && shift
            echo "${data}" \
                | gpg --encrypt ${GPG_OPTIONS} --hidden-recipient "${id}@${GPG_DOMAIN_NAME}" \
                    --sign --armor 2>&${WT_LOG_DEBUG} \
                | base64
            ;;
        decrypt)
            id="${1}" && shift
            data="${1}" && shift
            echo "${data}" \
                | base64 -d \
                | gpg --decrypt ${GPG_OPTIONS} --local-user "${id}@${GPG_DOMAIN_NAME}" \
                    2>&${WT_LOG_DEBUG}
            ;;
    esac
}

# basic topic

function wirething_topic_timestamp() {
    echo -n "$(($(epoch) / ${WT_TOPIC_TIMESTAMP_OFFSET}))"
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
            host_id="${1}" && shift
            peer_id="${1}" && shift
            wirething_topic_hash_values
            echo -n "${tag_hash}:${timestamp_hash}:${host_id_hash}:${peer_id_hash}" | sha256sum
            ;;
        subscribe)
            host_id="${1}" && shift
            peer_id="${1}" && shift
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
WT_ENCRYPTION_TYPE="${WT_ENCRYPTION_TYPE:-gpg_ephemeral}"
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

# wirething

function wirething() {
    action="${1}" && shift
    case "${action}" in
        init)
            debug "wirething init"
            WT_STATE="${WT_EPHEMERAL_PATH}/state"
            WT_HOST_ENDPOINT_FILE="${WT_STATE}/host_endpoint"
            ;;
        up)
            debug "wirething up"
            punch_protocol="$(punch protocol)"
            interface_protocol="$(interface protocol)"
            [ "${punch_protocol}" != "${interface_protocol}" ] \
                && die "Punch *${WT_PUNCH_TYPE}=${punch_protocol}* and interface *${WT_INTERFACE_TYPE}=${interface_protocol}* protocol differ" \
                || true

            mkdir -p "${WT_STATE}"
            touch "${WT_HOST_ENDPOINT_FILE}"
            ;;
        up_host)
            debug "wirething up_host"
            host_id="${1}" && shift

            value="${WT_PID}"
            encrypted_value="$(encryption encrypt "${host_id}" "${value}" 2>&${WT_LOG_DEBUG})"
            decrypted_value="$(encryption decrypt "${host_id}" "${encrypted_value}" 2>&${WT_LOG_DEBUG})"

            [ "${value}" != "${decrypted_value}" ] \
                && die "Host ${host_id} could not encrypt and decrypt data" \
                || true
            ;;
        up_peer)
            debug "wirething up_peer"
            peer_id="${1}" && shift

            value="${WT_PID}"
            encryption encrypt "${peer_id}" "${value}" 1>&${WT_LOG_TRACE} 2>&${WT_LOG_DEBUG} \
                || die "Peer ${peer_id} could not encrypt data"

            ;;
        set)
            name="${1}" && shift
            case "${name}" in
                host_endpoint)
                    endpoint="${1}" && shift
                    info "wirething set host_endpoint ${endpoint}"
                    echo "${endpoint}" > "${WT_HOST_ENDPOINT_FILE}"
                    ;;
            esac
            ;;
        get)
            name="${1}" && shift
            case "${name}" in
                host_endpoint)
                    endpoint="$(cat "${WT_HOST_ENDPOINT_FILE}")"
                    info "wirething get host_endpoint ${endpoint}"
                    echo "${endpoint}"
                    ;;
            esac
            ;;
        punch_host_endpoint)
            debug "wirething punch_host_endpoint"
            punch open && {
                host_port="$(punch get port)"
                host_endpoint="$(punch get endpoint)"

                punch close

                if [[ "${host_port}" != "" && "${host_endpoint}" != "" ]]
                then
                    interface set host_port "${host_port}"
                    wirething set host_endpoint "${host_endpoint}"
                else
                    error "wirething set host_port='${host_port}' or host_endpoint='${host_endpoint}' are empty"
                fi
            }
            ;;
        broadcast_host_endpoint)
            debug "wirething broadcast_host_endpoint"
            host_id="${1}" && shift
            peer_id_list="${1}" && shift

            for peer_id in ${peer_id_list}
            do
                wirething publish_host_endpoint "${host_id}" "${peer_id}"
            done
            ;;
        publish_host_endpoint)
            debug "wirething publish_host_endpoint"
            host_id="${1}" && shift
            peer_id="${1}" && shift

            host_endpoint="$(wirething get host_endpoint)"

            echo "${host_endpoint}" | hexdump -C | raw_trace

            if [ "${host_endpoint}" != "" ]
            then
                info "wirething publish_host_endpoint $(short "${peer_id}") ${host_endpoint}"

                topic="$(topic publish "${host_id}" "${peer_id}")"
                encrypted_host_endpoint="$(encryption encrypt "${peer_id}" "${host_endpoint}")"

                pubsub publish "${topic}" "${encrypted_host_endpoint}"
            fi
            ;;
        subscribe_peer_endpoint)
            debug "wirething subscribe_peer_endpoint"
            host_id="${1}" && shift
            peer_id="${1}" && shift

            topic="$(topic subscribe "${host_id}" "${peer_id}")"

            {
                pubsub subscribe "${topic}"
            } | {
                while read encrypted_peer_endpoint
                do
                    new_peer_endpoint="$(encryption decrypt "${host_id}" "${encrypted_peer_endpoint}")"

                    echo "${new_peer_endpoint}" | hexdump -C | raw_trace

                    if [ "${new_peer_endpoint}" != "" ]
                    then
                        echo "${new_peer_endpoint}"
                    fi
                done
            }
            ;;
        on_new_peer_endpoint)
            debug "wirething on_new_peer_endpoint"
            host_id="${1}" && shift
            peer_id="${1}" && shift

            while read new_peer_endpoint
            do
                info "wirething on_new_peer_endpoint $(short "${peer_id}") ${new_peer_endpoint}"

                current_peer_endpoint="$(interface get peer_endpoint "${peer_id}")"

                if [[ "${new_peer_endpoint}" != "${current_peer_endpoint}" ]]
                then
                    interface set peer_endpoint "${peer_id}" "${new_peer_endpoint}"
                    wirething publish_host_endpoint "${host_id}" "${peer_id}"
                fi
            done
            ;;
    esac
}

# interval based punch usecase

function interval_based_punch_usecase() {
    action="${1}" && shift
    case "${action}" in
        init)
            debug "interval_based_punch_usecase init"
            WT_INTERVAL_BASED_PUNCH_ENABLED="${WT_INTERVAL_BASED_PUNCH_ENABLED:-true}"
            WT_INTERVAL_BASED_PUNCH_START_DELAY="${WT_INTERVAL_BASED_PUNCH_START_DELAY:-10}" # 10 seconds
            WT_INTERVAL_BASED_PUNCH_INTERVAL="${WT_INTERVAL_BASED_PUNCH_INTERVAL:-3600}" # 1 hour
            WT_INTERVAL_BASED_PUNCH_PID_FILE="${WT_EPHEMERAL_PATH}/interval_based_punch_usecase.pid"
            ;;
        start)
            if [[ "${WT_INTERVAL_BASED_PUNCH_ENABLED}" == "true" ]]
            then
                debug "interval_based_punch_usecase start $(short "${host_id}")"
                interval_based_punch_usecase loop &
                echo "${!}" > "${WT_INTERVAL_BASED_PUNCH_PID_FILE}"
            fi
            ;;
        loop)
            debug "interval_based_punch_usecase start $(short "${host_id}") delay ${WT_INTERVAL_BASED_PUNCH_START_DELAY}"
            sleep "${WT_INTERVAL_BASED_PUNCH_START_DELAY}"

            PUNCH_PID="$(cat "${WT_INTERVAL_BASED_PUNCH_PID_FILE}")"

            while true
            do
                if wirething punch_host_endpoint
                then
                    wirething broadcast_host_endpoint "${host_id}" "${peer_id_list}" &

                    info "interval_based_punch_usecase starting $(short "${host_id}") interval ${WT_INTERVAL_BASED_PUNCH_INTERVAL} seconds"
                    sleep "${WT_INTERVAL_BASED_PUNCH_INTERVAL}"
                else
                    info "interval_based_punch_usecase starting $(short "${host_id}") pause after error ${WT_PAUSE_AFTER_ERROR} seconds"
                    sleep "${WT_PAUSE_AFTER_ERROR}"
                fi
            done
            debug "interval_based_punch_usecase end $(short "${host_id}")"
            ;;
    esac
}

# always on peer subscribe usecase

function always_on_peer_subscribe_usecase() {
    action="${1}" && shift
    case "${action}" in
        init)
            WT_ALWAYS_ON_PEER_SUBSCRIBE_ENABLED="${WT_ALWAYS_ON_PEER_SUBSCRIBE_ENABLED:-true}"
            WT_ALWAYS_ON_PEER_SUBSCRIBE_START_DELAY="${WT_PEER_START_DELAY:-1}" # 1 second
            WT_ALWAYS_ON_PEER_SUBSCRIBE_INTERVAL="${WT_PEER_INTERVAL:-5}" # 5 second
            ;;
        start)
            if [[ "${WT_ALWAYS_ON_PEER_SUBSCRIBE_ENABLED}" == "true" ]]
            then
                debug "always_on_peer_subscribe_usecase start $(short "${peer_id}")"
                always_on_peer_subscribe_usecase loop &
            fi
            ;;
        loop)
            debug "always_on_peer_subscribe_usecase start $(short "${peer_id}") delay ${WT_ALWAYS_ON_PEER_SUBSCRIBE_START_DELAY}"
            sleep "${WT_ALWAYS_ON_PEER_SUBSCRIBE_START_DELAY}"

            while true
            do
                {
                    wirething subscribe_peer_endpoint "${host_id}" "${peer_id}"
                } | {
                    wirething on_new_peer_endpoint "${host_id}" "${peer_id}"
                }

                debug "always_on_peer_subscribe_usecase subscribe starting $(short "${peer_id}") interval ${WT_ALWAYS_ON_PEER_SUBSCRIBE_INTERVAL} seconds"
                sleep "${WT_ALWAYS_ON_PEER_SUBSCRIBE_INTERVAL}"
            done
            debug "always_on_peer_subscribe_usecase end $(short "${peer_id}")"
            ;;
    esac
}

# wirething main

wt_type_list=(
    interface
    punch
    pubsub
    encryption
    topic
)

function wt_get_alias() {
    alias ${i} | cut -f 2 -d "'"
}

function wt_type_for_each() {
    for i in "${wt_type_list[@]}"; do
        "$(wt_get_alias $i)" "${1}"
    done
}

function wirething_main() {
    action="${1}" && shift
    case "${action}" in
        init)
            debug "wirething_main init"

            WT_PID="$(pid)"
            WT_RUN_PATH="${WT_RUN_PATH:-/var/run/wirething}"
            WT_EPHEMERAL_PATH="${WT_RUN_PATH}/${WT_PID}"
            WT_PAUSE_AFTER_ERROR="${WT_PAUSE_AFTER_ERROR:-60}" # 60 seconds

            wt_type_for_each init

            wirething init
            interval_based_punch_usecase init
            always_on_peer_subscribe_usecase init
            ;;
        signal)
            signal="${1}" && shift
            result="${1}" && shift

            debug "wirething_main signal ${signal} ${result}"

            case "${signal}" in
                EXIT)
                    # Set trap to empty to run only once
                    trap "" ${signal}
                    wirething_main down
                    kill 0
                    ;;
            esac
            ;;
        up)
            debug "wirething_main up"

            for signal in SIGHUP SIGINT SIGQUIT SIGILL SIGTRAP SIGABRT \
                SIGFPE SIGKILL SIGBUS SIGSEGV SIGSYS SIGPIPE SIGALRM SIGTERM \
                SIGURG SIGSTOP SIGTSTP SIGCONT SIGTTIN SIGTTOU SIGIO \
                SIGXCPU SIGXFSZ SIGVTALRM SIGPROF SIGWINCH SIGUSR1 \
                SIGUSR2 EXIT
            do
                trap "wirething_main signal ${signal} ${?:-null}" "${signal}"
            done


            mkdir -p "${WT_EPHEMERAL_PATH}"

            wt_type_for_each up
            wirething up

            host_id="$(interface get host_id)"
            peer_id_list="$(interface get peers_id_list)"

            wirething up_host "${host_id}"

            for peer_id in ${peer_id_list}
            do
                wirething up_peer "${peer_id}"
            done
            ;;
        down)
            wt_type_for_each down
            wirething down

            debug "wirething_main down"
            rm -rf "${WT_EPHEMERAL_PATH}" && debug "wirething_main *${WT_EPHEMERAL_PATH}* was deleted"
            ;;
        start)
            debug "wirething_main start"
            host_id="$(interface get host_id)"
            peer_id_list="$(interface get peers_id_list)"

            interval_based_punch_usecase start

            for peer_id in ${peer_id_list}
            do
                always_on_peer_subscribe_usecase start
            done
            ;;
        wait)
            debug "wirething_main wait"
            wait $(jobs -p)
            ;;
    esac
}

# main

function main() {
    log_init
    wirething_main init
    auto_su
    wirething_main up
    wirething_main start
    wirething_main wait
}

main
