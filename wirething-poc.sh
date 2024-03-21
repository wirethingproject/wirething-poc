#!/usr/bin/env bash

# basic

# set: http://redsymbol.net/articles/unofficial-bash-strict-mode/

set -o errexit  # -e Exit immediately if any command returns a non-zero status
set -o errtrace # -E Make ERR trap work with shell functions
set -o nounset  # -u Treat unset variables as an error
set -o pipefail # Return non-zero if any command in a pipeline fails

shopt -s expand_aliases  # Aliases are expanded on non interactive shell
shopt -s inherit_errexit # Command substitution inherits the value of the errexit option
shopt -s execfail        # Don't exit if exec cannot execute the file

umask 077

export LC_ALL=C

# utils

function base64linux() {
    base64 -w 0 ${1:-}

    if [ "${1:-}" == "" ]
    then
        echo ""
    fi
}

function utils() {
    local action="${1}" && shift
    case "${action}" in
        deps)
            echo "bash tr readlink sudo base64 grep sed cat openssl ping"

            case "${OSTYPE}" in
                darwin*)
                    ;;
                linux*)
                    ;;
                *)
                    die "OS *${OSTYPE}* not supported"
            esac
            if bash_compat 5 0
            then
                echo "date"
            fi
            ;;
        init)
            case "${OSTYPE}" in
                darwin*)
                    alias ping="ping -c 1 -t 1"
                    ;;
                linux*)
                    alias ping="ping -c 1 -W 1"
                    alias base64='base64linux'
                    ;;
                *)
                    die "OS *${OSTYPE}* not supported"
            esac
            ;;
    esac
}

utils init

function to_upper() {
    echo ${1} | tr "[:lower:]" "[:upper:]"
}

function to_lower() {
    echo ${1} | tr "[:upper:]" "[:lower:]"
}

function hash_id() {
    echo "${1}" | openssl sha256 | sed "s,.* ,,"
}

# bash compat

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
    if bash_compat 5 0
    then
        echo "${EPOCHSECONDS}"
    else
        date -u +"%s"
    fi
}

function set_pid() {
    PID="${BASHPID:-${$}}"
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


function fd() {
    local action="${1}" && shift
    case "${action}" in
        open)
            if bash_compat 4 0
            then
                coproc cat -u
                fd="${COPROC[1]}"
            else
                fd="${WT_LOG_DEBUG}"
            fi
            ;;
        close)
            name="${1}" && shift

            if bash_compat 4 0
            then
                local fd_buffer
                exec {fd}>&-
                readarray fd_buffer <&${COPROC[0]}
                declare -g "${name}"="$(IFS=''; echo "${fd_buffer[*]}")"
            else
                declare -g "${name}"=""
            fi
            ;;
    esac
}

# bash compat udp

function udp() {
    local action="${1}" && shift
    case "${action}" in
        deps)
            echo "lsof grep sed head"
            ;;
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
                exec {UDP_SOCKET}>&- || true
            else
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
            export PS4='+ :${LINENO:-} ${FUNCNAME[0]:-}(): '
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
            die "invalid WT_LOG_LEVEL *${WT_LOG_LEVEL}*, options: trace, debug, info, error"
    esac
}

log_init

function log() {
    if [ "${WT_LOG_TIME}" == "true" ]
    then
        echo -n "$(date -Iseconds) "
    fi

    echo "${@}"
}

function raw_trace() {
    log "TRACE" >&${WT_LOG_TRACE} || true
    cat >&${WT_LOG_TRACE} || true
}

function debug() {
    local prefix="$(short "${peer_id:-${host_id:---------}}") ${FUNCNAME[1]:-} ${action:-}"
    log "DEBUG" "${prefix}" "${@}" >&${WT_LOG_DEBUG} || true
}

function info() {
    local prefix="$(short "${peer_id:-${host_id:---------}}") ${FUNCNAME[1]:-} ${action:-}"
    log "INFO " "${prefix}" "${@}" >&${WT_LOG_INFO} || true
}

function error() {
    local prefix="$(short "${peer_id:-${host_id:---------}}") ${FUNCNAME[1]:-} ${action:-}"
    log "ERROR" "${prefix}" "${@}" >&${WT_LOG_ERROR} || true
}

function die() {
    action="${FUNCNAME[1]:-} ${action:-}"
    error "${@}"
    exit 1
}

function short() {
    echo "${1::8}"
}

# wg interface

function wg_interface() {
    local action="${1}" && shift
    case "${action}" in
        protocol)
            echo "udp"
            ;;
        deps)
            echo "wg grep cut sed sort tail ping"
            ;;
        init)
            info
            WG_INTERFACE="${WG_INTERFACE:?Variable not set}"
            WG_HANDSHAKE_TIMEOUT="${WG_HANDSHAKE_TIMEOUT:-125}" # 125 seconds
            info "WG_INTERFACE=${WG_INTERFACE}"
            ;;
        up)
            info
            if [ "$(wg_interface status)" == "down" ]
            then
                die "wireguard interface *${WG_INTERFACE:-}* not found."
            fi
            ;;
        set)
            name="${1}" && shift
            case "${name}" in
                host_port)
                    port="${1}" && shift
                    info "host_port ${port:-''}"
                    wg set "${WG_INTERFACE}" listen-port "${port}"
                    ;;
                peer_endpoint)
                    peer="${1}" && shift
                    endpoint="${1}" && shift
                    info "peer_endpoint $(short "${peer}") ${endpoint:-''}"
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
                        debug "host_id $(short "${host_id:-''}")"
                        echo "${host_id}"
                    }
                    ;;
                peer_id_list)
                    {
                        wg show "${WG_INTERFACE}" peers
                    } | {
                        while read peer_id
                        do
                            debug "peer_id $(short "${peer_id:-''}")"
                            echo "${peer_id}"
                        done
                    }
                    ;;
                peer_address)
                    peer="${1}" && shift

                    {
                        wg show "${WG_INTERFACE}" allowed-ips
                    } | {
                        grep "${peer}" | cut -f 2 | sed "s,/32,,"
                    } | {
                        read address
                        debug "peer_address $(short "${peer}") ${address:-''}"
                        echo "${address}"
                    }
                    ;;
                peer_status)
                    peer="${1}" && shift
                    address="$(wg_interface get peer_address "${peer}")"

                    if ping "${address}" 2>&${WT_LOG_TRACE} | raw_trace
                    then
                        result="online"
                    else
                        result="offline"
                    fi

                    debug "peer_status $(short "${peer}") ${result:-''}"
                    echo "${result}"
                    ;;
                latest_handshake)
                    peer="${1}" && shift

                    {
                        wg show "${WG_INTERFACE}" latest-handshakes
                    } | {
                        grep "${peer/latest/}" | cut -f 2 | sort -n | tail -n 1
                    } | {
                        read handshake
                        debug "latest_handshake $(short "${peer}") ${handshake:-''}"
                        echo "${handshake}"
                    }
                    ;;
                handshake_timeouted)
                    peer="${1}" && shift

                    last_handshake="$(wg_interface get latest_handshake "${peer}")"
                    handshake_delta="$(($(epoch) - ${last_handshake}))"

                    if [[ ${handshake_delta} -lt ${WG_HANDSHAKE_TIMEOUT} ]]
                    then
                        result="false"
                    else
                        result="true"
                    fi

                    debug "handshake_timeouted $(short "${peer}") ${result:-''}"
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

                info "${status}"
                echo "${status}"
            }
            ;;
    esac
}

# wg quick interface

function wg_quick_validate_peers() {
    if [ ! -f "${WT_CONFIG_PATH}/${WGQ_HOST_PRIVATE_KEY_FILE}" ]
    then
        die "file WGQ_HOST_PRIVATE_KEY_FILE not found *${WT_CONFIG_PATH}/${WGQ_HOST_PRIVATE_KEY_FILE}*"
    fi

    local host_id="$(cat "${WT_CONFIG_PATH}/${WGQ_HOST_PRIVATE_KEY_FILE}" | wg pubkey)"

    for peer_pub_file in ${WGQ_PEER_PUBLIC_KEY_FILE_LIST}
    do
        if [ ! -f "${WT_CONFIG_PATH}/${peer_pub_file}" ]
        then
            die "file in WGQ_PEER_PUBLIC_KEY_FILE_LIST not found *${WT_CONFIG_PATH}/${peer_pub_file}*"
        fi

        local peer_id="$(cat "${WT_CONFIG_PATH}/${peer_pub_file}")"

        if [ "${peer_id}" == "${host_id}" ]
        then
            continue
        fi

        local peer_name="${peer_pub_file##*/}" # remove path
        peer_name="${peer_name%.pub}" # remove extension
        peer_name="$(to_upper ${peer_name})" # to upper

        WGQ_PEER_ALLOWED_IPS_VAR_NAME="WGQ_PEER_${peer_name}_ALLOWED_IPS"
        local value="${!WGQ_PEER_ALLOWED_IPS_VAR_NAME:?Variable not set}"
    done
}

function wg_quick_generate_config_file() {
    cat <<EOF
[Interface]
Address = ${WGQ_HOST_ADDRESS}
EOF

    if [ -f "${WT_HOST_PORT_FILE}" ]
    then
            cat <<EOF
ListenPort = $(cat "${WT_HOST_PORT_FILE}")
EOF
    fi

    if [ "${WGQ_USE_POSTUP_TO_SET_PRIVATE_KEY}" == "true" ]
    then
        cat <<EOF
PostUp = wg set %i private-key ${WT_CONFIG_PATH}/${WGQ_HOST_PRIVATE_KEY_FILE}
EOF
    else
        cat <<EOF
PrivateKey = $(cat "${WT_CONFIG_PATH}/${WGQ_HOST_PRIVATE_KEY_FILE}")
EOF
    fi

    local host_id="$(cat "${WT_CONFIG_PATH}/${WGQ_HOST_PRIVATE_KEY_FILE}" | wg pubkey)"

    for peer_pub_file in ${WGQ_PEER_PUBLIC_KEY_FILE_LIST}
    do
        local peer_name="${peer_pub_file##*/}" # remove path
        peer_name="${peer_name%.pub}" # remove extension
        peer_name="$(to_upper ${peer_name})" # to upper

        local peer_id="$(cat "${WT_CONFIG_PATH}/${peer_pub_file}")"

        if [ "${peer_id}" == "${host_id}" ]
        then
            continue
        fi

        WGQ_PEER_ALLOWED_IPS_VAR_NAME="WGQ_PEER_${peer_name}_ALLOWED_IPS"

        cat <<EOF

[Peer]
PublicKey = ${peer_id}
AllowedIPs = ${!WGQ_PEER_ALLOWED_IPS_VAR_NAME}
PersistentKeepalive = ${WGQ_PEER_PERSISTENT_KEEPALIVE}
EOF

        if [ -f "${WT_PEER_ENDPOINT_PATH}/$(hash_id "${peer_id}")" ]
        then
            cat <<EOF
Endpoint = $(cat "${WT_PEER_ENDPOINT_PATH}/$(hash_id "${peer_id}")")
EOF
        fi
    done
}

function wg_quick_interface() {
    local action="${1}" && shift
    case "${action}" in
        protocol)
            echo "udp"
            ;;
        deps)
            wg_interface deps
            echo "wg-quick wg cat grep rm"
            case "${OSTYPE}" in
                darwin*)
                    echo "wireguard-go"
                    ;;
            esac
            ;;
        init)
            info

            if bash_compat 4 0
            then
                :
            else
                die "bash < 4.0 not supported"
            fi

            WGQ_HOST_PRIVATE_KEY_FILE="${WGQ_HOST_PRIVATE_KEY_FILE:?Variable not set}"
            WGQ_PEER_PUBLIC_KEY_FILE_LIST="${WGQ_PEER_PUBLIC_KEY_FILE_LIST:?Variable not set}"
            WGQ_HOST_ADDRESS="${WGQ_HOST_ADDRESS:?Variable not set}"

            WGQ_USE_POSTUP_TO_SET_PRIVATE_KEY="${WGQ_USE_POSTUP_TO_SET_PRIVATE_KEY:-true}"
            WGQ_PEER_PERSISTENT_KEEPALIVE="${WGQ_PEER_PERSISTENT_KEEPALIVE:-25}" # 25 seconds

            WGQ_LOG_LEVEL="${WGQ_LOG_LEVEL:-}"
            WGQ_USERSPACE="${WGQ_USERSPACE:-}"

            WGQ_INTERFACE="wth${WT_PID}"
            WGQ_CONFIG_FILE="${WT_EPHEMERAL_PATH}/${WGQ_INTERFACE}.conf"

            info "WGQ_INTERFACE=${WGQ_INTERFACE}"

            wg_quick_validate_peers
            ;;
        up)
            info

            wg_quick_generate_config_file > "${WGQ_CONFIG_FILE}"

            export WG_QUICK_USERSPACE_IMPLEMENTATION="${WGQ_USERSPACE}"
            export LOG_LEVEL="${WGQ_LOG_LEVEL}"

            info "wg-quick up ${WGQ_CONFIG_FILE}"
            wg-quick up "${WGQ_CONFIG_FILE}" 2>&${WT_LOG_DEBUG}

            case "${OSTYPE}" in
                darwin*)
                    WG_INTERFACE="$(cat "/var/run/wireguard/${WGQ_INTERFACE}.name")"
                    ;;
                linux*)
                    WG_INTERFACE="${WGQ_INTERFACE}"
                    ;;
                *)
                    die "OS *${OSTYPE}* not supported"
            esac
            wg_interface init
            ;;
        down)
            info

            if [ "$(wg_interface status)" == "up" ]
            then
                info "wg-quick down ${WGQ_CONFIG_FILE}"
                wg-quick down "${WGQ_CONFIG_FILE}"
            fi

            if rm -f "${WGQ_CONFIG_FILE}"
            then
                info "*${WGQ_CONFIG_FILE}* was deleted"
            else
                error "*${WGQ_CONFIG_FILE}* delete error"
            fi
            ;;
        set)
            wg_interface "${action}" ${@}
            ;;
        get)
            name="${1}" && shift
            case "${name}" in
                host_id)
                    {
                        cat "${WT_CONFIG_PATH}/${WGQ_HOST_PRIVATE_KEY_FILE}" | wg pubkey
                    } | {
                        read host_id
                        debug "host_id $(short "${host_id:-''}")"
                        echo "${host_id}"
                    }
                    ;;
                peer_id_list)
                    {
                        cat "${WT_CONFIG_PATH}/${WGQ_HOST_PRIVATE_KEY_FILE}" | wg pubkey
                    } | {
                        read host_id

                        for peer_pub_file in ${WGQ_PEER_PUBLIC_KEY_FILE_LIST}
                        do
                            {
                                cat "${WT_CONFIG_PATH}/${peer_pub_file}"
                            } | {
                                read peer_id

                                if [ "${peer_id}" != "${host_id}" ]
                                then
                                    debug "peer_id $(short "${peer_id:-''}")"
                                    echo "${peer_id}"
                                fi

                            }
                        done
                    }
                    ;;
                *)
                    wg_interface "${action}" "${name}" ${@}
            esac
            ;;
    esac
}

# wireproxy interface

function wireproxy_generate_config_file() {
    wg_quick_generate_config_file > "${WGQ_CONFIG_FILE}"
    WGQ_USE_POSTUP_TO_SET_PRIVATE_KEY=false wg_quick_generate_config_file

    if [ "${WIREPROXY_SOCKS5_BIND}" != "" ]
    then
        cat <<EOF

[Socks5]
BindAddress = ${WIREPROXY_SOCKS5_BIND}
EOF
    fi

    if [ "${WIREPROXY_HTTP_BIND}" != "" ]
    then
        cat <<EOF

[http]
BindAddress = ${WIREPROXY_HTTP_BIND}
EOF
    fi

    for port in ${WIREPROXY_EXPOSE_PORT_LIST}
    do
        cat <<EOF

[TCPServerTunnel]
ListenPort = ${port}
Target = 127.0.0.1:${port}
EOF
    done

    for forward in ${WIREPROXY_FORWARD_PORT_LIST}
    do
        {
            echo "${forward/:/ }"
        } | {
            read local_port remote_endpoint
            cat <<EOF

[TCPClientTunnel]
BindAddress = 127.0.0.1:${local_port}
Target = ${remote_endpoint}
EOF
        }
    done
}

function wireproxy_interface() {
    local action="${1}" && shift

    case "${action}" in
        protocol)
            echo "udp"
            ;;
        deps)
            echo "wg cat grep rm"
            echo "wireproxy"
            ;;
        init)
            info

            WIREPROXY_LOG_LEVEL="${WIREPROXY_LOG_LEVEL:-}"
            WIREPROXY_COMAND="${WIREPROXY_COMAND:-wireproxy}"
            WIREPROXY_PID_FILE="${WT_EPHEMERAL_PATH}/wireproxy.pid"
            WIREPROXY_RELOAD_FILE="${WT_EPHEMERAL_PATH}/wireproxy.reload"
            WIREPROXY_HTTP_BIND="${WIREPROXY_HTTP_BIND:-127.0.0.1:1080}"
            WIREPROXY_SOCKS5_BIND="${WIREPROXY_SOCKS5_BIND:-127.0.0.1:1050}"
            WIREPROXY_STATUS_TIMEOUT="${WIREPROXY_STATUS_TIMEOUT:-35}" # 35 seconds
            WIREPROXY_HANDSHAKE_TIMEOUT="${WIREPROXY_HANDSHAKE_TIMEOUT:-135}" # 135 seconds
            WIREPROXY_EXPOSE_PORT_LIST="${WIREPROXY_EXPOSE_PORT_LIST:-}"
            WIREPROXY_FORWARD_PORT_LIST="${WIREPROXY_FORWARD_PORT_LIST:-}"

            wg_quick_interface init
            ;;
        up)
            info

            wireproxy_interface start
            ;;
        down)
            info
            ;;
        start)
            info

            {
                wireproxy_interface get host_id
                wireproxy_interface get peer_id_list
            } | {
                local id_list
                readarray id_list
                wireproxy_interface loop "$(IFS=''; echo "${id_list[*]}")" &
            }
            ;;
        stop)
            info
            if [ -f "${WIREPROXY_PID_FILE}" ]
            then
                {
                    cat "${WIREPROXY_PID_FILE}"
                } | {
                    read pid
                    info "kill -TERM ${pid}"
                    kill -TERM "${pid}" || true
                }
            fi
            ;;
        reload)
            local peer_id=""
            info

            if [ ! -f "${WIREPROXY_RELOAD_FILE}" ]
            then
                touch "${WIREPROXY_RELOAD_FILE}"
                wireproxy_interface stop
            fi
            ;;
        log)
            case "${line}" in
                ERROR*)
                    echo "[wireproxy] ${line}" >&${WT_LOG_ERROR}
                    ;;
                DEBUG*)
                    if [ "${WIREPROXY_LOG_LEVEL}" == "debug" ]
                    then
                        echo "[wireproxy] ${line}" >&${WT_LOG_DEBUG}
                    fi
                    ;;
                *)
                    echo "[wireproxy] ${line}" >&${WT_LOG_INFO}
            esac
            ;;
        loop)
            info
            local id_list="${1}" && shift

            {
                while true
                do
                    coproc WIREPROXY_PROC ("${WIREPROXY_COMAND}" -c <(wireproxy_generate_config_file) 2>&1)
                    echo "${!}" > "${WIREPROXY_PID_FILE}"
                    rm -f "${WIREPROXY_RELOAD_FILE}"

                    cat <&${WIREPROXY_PROC[0]} || true
                    rm -f "${WIREPROXY_PID_FILE}"

                    if [ ! -f "${WIREPROXY_RELOAD_FILE}" ]
                    then
                        break
                    fi

                    sleep 1
                done
            } | {
                while read line
                do
                    wireproxy_interface log "${line}"

                    if ! grep "peer(" <<<"${line}" > /dev/null
                    then
                        continue
                    fi

                    peer_regex="$(echo "${line}" | sed "s,.*peer(\(.*\)…\(.*\)) - .*,\1.*\2=,")"
                    id="$(echo -e "${id_list}" | grep "${peer_regex}" || true)"

                    if [ "${id}" == "" ]
                    then
                        error "regex=${peer_regex:=''} id="${id:=''}" peer not found: ${line}"
                        continue
                    fi

                    case "${line}" in
                        *"Receiving keepalive packet")
                            epoch > "${WT_PEER_LAST_KEEPALIVE_PATH}/$(hash_id "${id}")"
                            debug "keepalive $(short ${id})"
                            ;;
                        *"Received handshake response")
                            epoch > "${WT_PEER_LAST_KEEPALIVE_PATH}/$(hash_id "${id}")"
                            debug "handshake $(short ${id})"
                            ;;
                    esac
                done
            }
            ;;
        set)
            name="${1}" && shift
            case "${name}" in
                host_port)
                    port="${1}" && shift
                    info "host_port ${port:-''}"

                    if ! grep -q "ListenPort = ${port}" < "${WGQ_CONFIG_FILE}"
                    then
                        wireproxy_interface reload
                    fi
                    ;;
                peer_endpoint)
                    peer="${1}" && shift
                    endpoint="${1}" && shift
                    info "peer_endpoint $(short "${peer}") ${endpoint:-''}"

                    if ! grep -q "Endpoint = ${endpoint}" < "${WGQ_CONFIG_FILE}"
                    then
                        wireproxy_interface reload
                    fi
                    ;;
            esac
            ;;
        get)
            name="${1}" && shift
            case "${name}" in
                peer_status)
                    peer="${1}" && shift

                    {
                        if [ ! -f "${WT_PEER_LAST_KEEPALIVE_PATH}/$(hash_id "${peer}")" ]
                        then
                            echo "0" > "${WT_PEER_LAST_KEEPALIVE_PATH}/$(hash_id "${peer}")"
                        fi

                        cat "${WT_PEER_LAST_KEEPALIVE_PATH}/$(hash_id "${peer}")"
                    } | {
                        read last_keepalive

                        keepalive_delta="$(($(epoch) - ${last_keepalive}))"

                        debug "last_keepalive=${last_keepalive} keepalive_delta=${keepalive_delta} timeout=${WIREPROXY_STATUS_TIMEOUT}"

                        if [[ ${keepalive_delta} -lt ${WIREPROXY_STATUS_TIMEOUT} ]]
                        then
                            result="online"
                        else
                            result="offline"
                        fi

                        debug "peer_status $(short "${peer}") ${result:-''}"
                        echo "${result}"
                    }
                    ;;
                handshake_timeouted)
                    peer="${1}" && shift

                    {
                        echo 0
                        cat "${WT_PEER_LAST_KEEPALIVE_PATH}/"* || true
                    }  | sort -n | tail -n 1 | {
                        read last_keepalive

                        keepalive_delta="$(($(epoch) - ${last_keepalive}))"

                        debug "last_keepalive=${last_keepalive} keepalive_delta=${keepalive_delta} timeout=${WIREPROXY_HANDSHAKE_TIMEOUT}"

                        if [[ ${keepalive_delta} -lt ${WIREPROXY_HANDSHAKE_TIMEOUT} ]]
                        then
                            result="false"
                        else
                            result="true"
                        fi

                        debug "handshake_timeout $(short "${peer}") ${result:-''}"
                        echo "${result}"
                    }
                    ;;
                host_id)
                    wg_quick_interface "${action}" "${name}" ${@}
                    ;;
                peer_id_list)
                    wg_quick_interface "${action}" "${name}" ${@}
                    ;;
            esac
            ;;
    esac
}

# udphole punch

function udphole_punch() {
    local action="${1}" && shift
    case "${action}" in
        protocol)
            echo "udp"
            ;;
        deps)
            udp deps
            ;;
        init)
            info
            UDPHOLE_HOST="${UDPHOLE_HOST:-udphole.wirething.org}" # udphole.wirething.org is a dns cname poiting to hdphole.fly.dev
            UDPHOLE_PORT="${UDPHOLE_PORT:-6094}"
            UDPHOLE_READ_TIMEOUT="${UDPHOLE_READ_TIMEOUT:-10}" # 10 seconds
            ;;
        open)
            debug

            if ! udp open "${UDPHOLE_HOST}" "${UDPHOLE_PORT}"
            then
                info "pause after error: ${WT_PAUSE_AFTER_ERROR} seconds"
                sleep "${WT_PAUSE_AFTER_ERROR}"
                return 1
            fi

            if ! udp writeline ""
            then
                info "pause after error: ${WT_PAUSE_AFTER_ERROR} seconds"
                sleep "${WT_PAUSE_AFTER_ERROR}"
                return 1
            fi
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
                            info "port ${port:-''}"
                            echo "${port}"
                        else
                            error "port timed out"
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
                            info "endpoint ${endpoint:-''}"
                            echo "${endpoint}"
                        else
                            error "endpoint timed out"
                            echo ""
                        fi
                    }
                    ;;
            esac
            ;;
        close)
            debug
            udp close
            ;;
    esac
}

# ntfy pubsub

function ntfy_pubsub() {
    local action="${1}" && shift
    case "${action}" in
        deps)
            echo "curl sleep hexdump"
            ;;
        init)
            info
            NTFY_URL="${NTFY_URL:-https://ntfy.sh}"
            NTFY_CURL_OPTIONS="${NTFY_CURL_OPTIONS:--sS --no-buffer --location}"
            NTFY_PUBLISH_TIMEOUT="${NTFY_PUBLISH_TIMEOUT:-25}" # 25 seconds
            NTFY_POLL_TIMEOUT="${NTFY_POLL_TIMEOUT:-25}" # 25 seconds
            NTFY_SUBSCRIBE_TIMEOUT="${NTFY_SUBSCRIBE_TIMEOUT:-720}" # 12 minutes
            NTFY_SUBSCRIBE_PAUSE_AFTER_ERROR="${NTFY_SUBSCRIBE_PAUSE_AFTER_ERROR:-${WT_PAUSE_AFTER_ERROR}}" # ${WT_PAUSE_AFTER_ERROR} seconds
            ;;
        publish)
            topic="${1}" && shift
            request="${1}" && shift
            info "$(short "${topic}") request: $(short "${request}")"

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
                            error "$(short "${topic}") response: ${publish_response:-''}"
                    esac
                done
            }
            ;;
        poll)
            topic="${1}" && shift
            since="${1}" && shift

            {
                curl ${NTFY_CURL_OPTIONS} --max-time "${NTFY_POLL_TIMEOUT}" --stderr - \
                    "${NTFY_URL}/${topic}/raw?poll=1&since=${since}" \
                    || true
            } | tail -n 1 | {
                read poll_response || true
                echo "${poll_response}" | hexdump -C | raw_trace

                case "${poll_response}" in
                    "curl"*)
                        error "$(short "${topic}") ${since} response: ${poll_response}"
                        echo "error"
                        ;;
                    "{"*"error"*)
                        error "$(short "${topic}") ${since} response: ${poll_response}"
                        echo "error"
                        ;;
                    "triggered")
                        echo ""
                        ;;
                    *)
                        debug "$(short "${topic}") ${since} response: $(short "${poll_response:-''}")"
                        echo "${poll_response}"
                esac
            }
            ;;
        subscribe)
            topic="${1}" && shift
            debug "$(short "${topic}") starting"

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
                            debug "$(short "${topic}") response: ${subscribe_response}"
                            ;;
                        "curl"*)
                            error "$(short "${topic}") response: ${subscribe_response}"
                            sleep "${NTFY_SUBSCRIBE_PAUSE_AFTER_ERROR}"
                            ;;
                        "{"*"error"*)
                            error "$(short "${topic}") response: ${subscribe_response}"
                            sleep "${NTFY_SUBSCRIBE_PAUSE_AFTER_ERROR}"
                            ;;
                        *)
                            info "$(short "${topic}") response: $(short "${subscribe_response:-''}")"
                            echo "${subscribe_response}"
                    esac
                done
            }
            ;;
    esac
}

# gpg ephemeral encryption

function gpg_ephemeral_encryption() {
    local action="${1}" && shift
    case "${action}" in
        deps)
            echo "gpg mkdir grep cut sed gpgconf rm base64"
            ;;
        init)
            info

            export GNUPGHOME="${WT_EPHEMERAL_PATH}/gpg"

            GPG_FILE_LIST="${GPG_FILE_LIST:?Variable not set}"
            GPG_DOMAIN_NAME="${GPG_DOMAIN_NAME:-wirething.gpg}"
            GPG_OPTIONS="${GPG_OPTIONS:---disable-dirmngr --no-auto-key-locate --batch --no}"
            GPG_AGENT_CONF="${GPG_AGENT_CONF:-disable-scdaemon\nextra-socket /dev/null\nbrowser-socket /dev/null\n}" # Disabling scdaemon (smart card daemon) make gpg do not try to use your Yubikey

            for gpg_file in ${GPG_FILE_LIST}
            do
                if [ ! -f "${gpg_file}" ]
                then
                    die "file in GPG_FILE_LIST not found *${gpg_file}*"
                fi
            done
            ;;
        up)
            info

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
            info
            gpgconf --kill gpg-agent
            if rm -rf "${GNUPGHOME}"
            then
                info "*${GNUPGHOME}* was deleted"
            else
                error "*${GNUPGHOME}* delete error"
            fi
            ;;
        encrypt)
            debug
            data="${1}" && shift
            id_list="${@}" && shift

            printf -v recipient " --hidden-recipient %s@${GPG_DOMAIN_NAME}" ${id_list}

            {
                echo "${data}"
            } | {
                gpg --encrypt ${GPG_OPTIONS} ${recipient} --sign --armor \
                        2>&${WT_LOG_DEBUG}
            } | {
                base64
            }
            ;;
        decrypt)
            debug
            data="${1}" && shift
            id="${1}" && shift

            {
                echo "${data}"
            } | {
                base64 -d
            } | {
                fd open

                gpg --decrypt ${GPG_OPTIONS} --local-user "${id}@${GPG_DOMAIN_NAME}" \
                    2>&${fd}

                fd close output


                if grep -iq "Good signature" <<<"${output}"
                then
                    echo "${output}" >&${WT_LOG_DEBUG}
                    return 0
                else
                    echo "${output}" >&${WT_LOG_ERROR}
                    return 1
                fi
            }
            ;;
    esac
}

# totp topic

function totp_interval() {
    {
        cat <<<"$(($(epoch) / ${TOTP_PERIOD}))"
    } | {
        # int2hex
        read int
        printf "%016X\n" "${int}"
    } | {
        # hex2bin
        read hex
        echo -ne "$(sed "s,..,\\\x&,g" <<<"${hex}")"
    }
}

function totp_secret() {
    {
        base64 -d <<<"${!1}"
        base64 -d <<<"${!2}"
    } | openssl sha256 -binary
}

function totp_hmac_digest_python_src() {
    cat <<EOF
import sys, hmac, hashlib

with open(sys.argv[1], mode="rb") as key:
    h = hmac.new(key.read(), sys.stdin.buffer.read(), hashlib.$(to_lower "${TOTP_ALGORITHM}"))
    print(h.hexdigest())
EOF
}

function totp_hmac_digest_python() {
    python3 -c "$(totp_hmac_digest_python_src)" "${1}"
}

function totp_hmac_digest_openssl() {
    openssl dgst -"${TOTP_ALGORITHM}" -hmac "$(cat "${1}")" \
        | sed "s,.* ,,"
}


function totp_digest() {
    totp_interval | "totp_hmac_digest_${TOTP_HMAC}" <(totp_secret "${1}" "${2}")
}

function totp_token() {
    read digest
    # Read the last 4 bits and convert it into an unsigned integer.
    start="$(( 0x${digest:(-1)} * 2))"
    # Read a 32-bit positive integer and take at most six rightmost digits.
    token="$(( ((0x${digest:${start}:8}) & 0x7FFFFFFF) % $((10 ** ${TOTP_DIGITS})) ))"
    # Pad the token number with leading zeros if needed.
    printf "%0${TOTP_DIGITS}d\n" "${token}"
}

function totp_topic() {
    local action="${1}" && shift
    case "${action}" in
        deps)
            echo "cat base64 openssl sed python3"
            ;;
        init)
            info
            TOTP_TOKEN="${TOTP_TOKEN:-cat}"
            TOTP_DIGITS="${TOTP_DIGITS:-6}"
            TOTP_PERIOD="${TOTP_PERIOD:-28800}" # 8 hours
            TOTP_ALGORITHM="${TOTP_ALGORITHM:-SHA256}"
            TOTP_HMAC="${TOTP_HMAC:-python}"
            ;;
        publish)
            host_id="${1}" && shift
            peer_id="${1}" && shift

            totp_digest "host_id" "peer_id" | "${TOTP_TOKEN}"
            ;;
        subscribe)
            host_id="${1}" && shift
            peer_id="${1}" && shift

            totp_digest "peer_id" "host_id" | "${TOTP_TOKEN}"
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
WT_TOPIC_TYPE="${WT_TOPIC_TYPE:-totp}"

alias interface="${WT_INTERFACE_TYPE}_interface"
alias punch="${WT_PUNCH_TYPE}_punch"
alias pubsub="${WT_PUBSUB_TYPE}_pubsub"
alias encryption="${WT_ENCRYPTION_TYPE}_encryption"
alias topic="${WT_TOPIC_TYPE}_topic"

interface ""    || die "invalid WT_INTERFACE_TYPE *${WT_INTERFACE_TYPE}*, options: $(options interface)"
punch ""        || die "invalid WT_PUNCH_TYPE *${WT_PUNCH_TYPE}*, options: $(options punch)"
pubsub ""       || die "invalid WT_PUBSUB_TYPE *${WT_PUBSUB_TYPE}*, options: $(options pubsub)"
encryption ""   || die "invalid WT_ENCRYPTION_TYPE *${WT_ENCRYPTION_TYPE}*, options: $(options encryption)"
topic ""        || die "invalid WT_TOPIC_TYPE *${WT_TOPIC_TYPE}*, options: $(options topic)"

# wirething

function wirething() {
    local action="${1}" && shift
    case "${action}" in
        deps)
            echo "mkdir touch cat hexdump"
            ;;
        init)
            info
            WT_STATE="${WT_CONFIG_PATH}/state"
            WT_HOST_PORT_FILE="${WT_STATE}/host_port"
            WT_HOST_ENDPOINT_FILE="${WT_STATE}/host_endpoint"
            WT_PEER_ENDPOINT_PATH="${WT_STATE}/peer_endpoint"
            WT_PEER_LAST_KEEPALIVE_PATH="${WT_STATE}/peer_last_keepalive"
            ;;
        up)
            info
            punch_protocol="$(punch protocol)"
            interface_protocol="$(interface protocol)"

            if [ "${punch_protocol}" != "${interface_protocol}" ]
            then
                die "punch *${WT_PUNCH_TYPE}=${punch_protocol}* and interface *${WT_INTERFACE_TYPE}=${interface_protocol}* protocol differ"
            fi

            mkdir -p "${WT_STATE}"
            touch "${WT_HOST_PORT_FILE}"
            touch "${WT_HOST_ENDPOINT_FILE}"
            mkdir -p "${WT_PEER_ENDPOINT_PATH}"
            mkdir -p "${WT_PEER_LAST_KEEPALIVE_PATH}"
            ;;
        up_host)
            local host_id="${1}" && shift
            info "$(short "${host_id}")"

            local value="${WT_PID}"

            {
                encryption encrypt "${value}" "${host_id}" 2>&${WT_LOG_DEBUG} \
                    || die "host could not encrypt data"
            } | {
                read encrypted_value

                encryption decrypt "${encrypted_value}" "${host_id}" 2>&${WT_LOG_DEBUG} \
                    || die "host could not decrypt data"
            } | {
                read decrypted_value

                if [ "${value}" != "${decrypted_value}" ]
                then
                    die "host could not encrypt and decrypt data"
                else
                    info "host could encrypt and decrypt data"
                fi
            }

            {
                wirething get host_port
            } | {
                read host_port

                if [ "${host_port}" != "" ]
                then
                    interface set host_port "${host_port}"
                else
                    info "host_port is '${host_port:-''}'"
                fi
            }

            {
                wirething get host_endpoint
            } | {
                read host_endpoint

                info "host_endpoint is ${host_endpoint:-''}"
            }
            ;;
        up_peer)
            local peer_id="${1}" && shift
            local host_id="${1}" && shift
            info "$(short "${peer_id}")"

            value="${WT_PID}"

            {
                encryption encrypt "${value}" "${host_id} ${peer_id}" 2>&${WT_LOG_DEBUG} \
                    || die "peer could not encrypt data"
            } | {
                read encrypted_value

                encryption decrypt "${encrypted_value}" "${host_id}" 2>&${WT_LOG_DEBUG} \
                    || die "host could not decrypt peer data"
            } | {
                read decrypted_value

                if [ "${value}" != "${decrypted_value}" ]
                then
                    die "host could not encrypt and decrypt peer data"
                else
                    info "host could encrypt and decrypt peer data"
                fi
            }

            {
                wirething get peer_endpoint "${peer_id}"
            } | {
                read peer_endpoint

                if [ "${peer_endpoint}" != "" ]
                then
                    interface set peer_endpoint "${peer_id}" "${peer_endpoint}"
                else
                    info "peer_endpoint is ${peer_endpoint:-''}"
                fi
            }
            ;;
        set)
            name="${1}" && shift
            case "${name}" in
                host_port)
                    port="${1}" && shift
                    info "host_port ${port}"
                    echo "${port}" > "${WT_HOST_PORT_FILE}"

                    interface set host_port "${host_port}"
                    ;;
                host_endpoint)
                    endpoint="${1}" && shift
                    info "host_endpoint ${endpoint}"
                    echo "${endpoint}" > "${WT_HOST_ENDPOINT_FILE}"
                    ;;
                peer_endpoint)
                    peer_id="${1}" && shift
                    endpoint="${1}" && shift
                    info "peer_endpoint $(short "${peer_id}") ${endpoint}"
                    echo "${endpoint}" > "${WT_PEER_ENDPOINT_PATH}/$(hash_id "${peer_id}")"

                    interface set peer_endpoint "${peer_id}" "${new_peer_endpoint}"
                    ;;
            esac
            ;;
        get)
            name="${1}" && shift
            case "${name}" in
                host_port)
                    port="$(cat "${WT_HOST_PORT_FILE}" 2>&${WT_LOG_DEBUG} || echo)"
                    debug "host_port ${port:-''}"
                    echo "${port}"
                    ;;
                host_endpoint)
                    endpoint="$(cat "${WT_HOST_ENDPOINT_FILE}" 2>&${WT_LOG_DEBUG} || echo)"
                    debug "host_endpoint ${endpoint:-''}"
                    echo "${endpoint}"
                    ;;
                peer_endpoint)
                    peer_id="${1}" && shift
                    endpoint="$(cat "${WT_PEER_ENDPOINT_PATH}/$(hash_id "${peer_id}")" 2>&${WT_LOG_DEBUG} || echo)"
                    debug "peer_endpoint $(short "${peer_id}") ${endpoint:-''}"
                    echo "${endpoint}"
                    ;;
            esac
            ;;
        punch_host_endpoint)
            debug
            if punch open
            then
                host_port="$(punch get port)"
                host_endpoint="$(punch get endpoint)"

                punch close

                if [[ "${host_port}" != "" && "${host_endpoint}" != "" ]]
                then
                    wirething set host_port "${host_port}"
                    wirething set host_endpoint "${host_endpoint}"
                else
                    error "host_port='${host_port}' or host_endpoint='${host_endpoint}' are empty"
                fi
            fi
            ;;
        broadcast_host_endpoint)
            debug
            host_id="${1}" && shift
            peer_id_list="${1}" && shift

            for _peer_id in ${peer_id_list}
            do
                wirething publish_host_endpoint "${host_id}" "${_peer_id}"
            done
            ;;
        publish_host_endpoint)
            debug
            host_id="${1}" && shift
            peer_id="${1}" && shift

            {
                wirething get host_endpoint
            } | {
                read host_endpoint
                echo "${host_endpoint}" | hexdump -C | raw_trace

                if [ "${host_endpoint}" != "" ]
                then
                    info "${host_endpoint}"

                    {
                        topic publish "${host_id}" "${peer_id}"
                    } | {
                        read topic
                        {
                            encryption encrypt "${host_endpoint}" "${host_id} ${peer_id}"
                        } | {
                            read encrypted_host_endpoint

                            if [ "${encrypted_host_endpoint}" != "" ]
                            then
                                pubsub publish "${topic}" "${encrypted_host_endpoint}"
                            else
                                error "empty encrypted_host_endpoint"
                            fi
                        }
                    }
                fi
            }
            ;;
        poll_encrypted_host_endpoint)
            debug
            host_id="${1}" && shift
            peer_id="${1}" && shift
            since="${1}" && shift

            {
                topic publish "${host_id}" "${peer_id}"
            } | {
                read topic
                pubsub poll "${topic}" "${since}"
            }
            ;;
        poll_encrypted_peer_endpoint)
            debug
            host_id="${1}" && shift
            peer_id="${1}" && shift
            since="${1}" && shift

            {
                topic subscribe "${host_id}" "${peer_id}"
            } | {
                read topic
                pubsub poll "${topic}" "${since}"
            }
            ;;
        on_new_peer_endpoint)
            debug
            host_id="${1}" && shift
            peer_id="${1}" && shift

            while read new_peer_endpoint
            do
                info "${new_peer_endpoint}"

                current_peer_endpoint="$(wirething get peer_endpoint "${peer_id}")"

                if [[ "${new_peer_endpoint}" != "${current_peer_endpoint}" ]]
                then
                    wirething set peer_endpoint "${peer_id}" "${new_peer_endpoint}"
                fi
            done
            ;;
        ensure_host_endpoint_is_published)
            info
            host_id="${1}" && shift
            peer_id="${1}" && shift
            since="all"

            {
                wirething poll_encrypted_host_endpoint "${host_id}" "${peer_id}" "${since}"
            } | {
                read encrypted_host_endpoint

                case "${encrypted_host_endpoint}" in
                    "error")
                        info "pause after poll_encrypted_host_endpoint error: ${WT_PAUSE_AFTER_ERROR} seconds"
                        sleep "${WT_PAUSE_AFTER_ERROR}"
                        return 1
                        ;;
                    *)
                        {
                            if [[ "${encrypted_host_endpoint}" != "" ]]
                            then
                                encryption decrypt "${encrypted_host_endpoint}" "${host_id}"
                            else
                                echo ""
                            fi
                        } | {
                            read published_host_endpoint

                            debug "published_host_endpoint ${published_host_endpoint}"

                            echo "${published_host_endpoint}" | hexdump -C | raw_trace

                            {
                                wirething get host_endpoint
                            } | {
                                read host_endpoint

                                if [ "${published_host_endpoint}" != "${host_endpoint}" ]
                                then
                                    wirething publish_host_endpoint "${host_id}" "${peer_id}"
                                fi
                            }
                        }
                esac
            }
            ;;
        fetch_peer_endpoint)
            debug
            host_id="${1}" && shift
            peer_id="${1}" && shift
            since="${1}" && shift

            {
                wirething poll_encrypted_peer_endpoint "${host_id}" "${peer_id}" "${since}"
            } | {
                read encrypted_peer_endpoint

                case "${encrypted_peer_endpoint}" in
                    "")
                        ;;
                    "error")
                        info "pause after poll_encrypted_peer_endpoint error: ${WT_PAUSE_AFTER_ERROR} seconds"
                        sleep "${WT_PAUSE_AFTER_ERROR}"
                        return 1
                        ;;
                    *)
                        {
                            encryption decrypt "${encrypted_peer_endpoint}" "${host_id}"
                        } | {
                            read new_peer_endpoint

                            echo "${new_peer_endpoint}" | hexdump -C | raw_trace

                            if [ "${new_peer_endpoint}" != "" ]
                            then
                                echo "${new_peer_endpoint}"
                            fi
                        } | {
                            wirething on_new_peer_endpoint "${host_id}" "${peer_id}"
                        }
                esac
            }
            ;;
    esac
}

# on interval punch usecase

function on_interval_punch_usecase() {
    local action="${1}" && shift
    case "${action}" in
        deps)
            echo "cat sleep"
            ;;
        init)
            info
            WT_ON_INTERVAL_PUNCH_ENABLED="${WT_ON_INTERVAL_PUNCH_ENABLED:-false}"
            WT_ON_INTERVAL_PUNCH_START_DELAY="${WT_ON_INTERVAL_PUNCH_START_DELAY:-5}" # 5 seconds
            WT_ON_INTERVAL_PUNCH_INTERVAL="${WT_ON_INTERVAL_PUNCH_INTERVAL:-691200}" # 8 hours
            WT_ON_INTERVAL_PUNCH_PID_FILE="${WT_EPHEMERAL_PATH}/on_interval_punch_usecase.pid"
            ;;
        start)
            local host_id="${1}" && shift
            info "$(short "${host_id}")"

            if [[ "${WT_ON_INTERVAL_PUNCH_ENABLED}" == "true" ]]
            then
                info "enabled"
                on_interval_punch_usecase loop &
                echo "${!}" > "${WT_ON_INTERVAL_PUNCH_PID_FILE}"
            else
                info "disabled"
            fi
            ;;
        loop)
            info "pause before start: ${WT_ON_INTERVAL_PUNCH_START_DELAY} seconds"
            sleep "${WT_ON_INTERVAL_PUNCH_START_DELAY}"

            PUNCH_PID="$(cat "${WT_ON_INTERVAL_PUNCH_PID_FILE}")"

            while true
            do
                if wirething punch_host_endpoint
                then
                    wirething broadcast_host_endpoint "${host_id}" "${peer_id_list}" &

                    info "pause: ${WT_ON_INTERVAL_PUNCH_INTERVAL} seconds"
                    sleep "${WT_ON_INTERVAL_PUNCH_INTERVAL}"
                else
                    info "pause after punch_host_endpoint error: ${WT_PAUSE_AFTER_ERROR} seconds"
                    sleep "${WT_PAUSE_AFTER_ERROR}"
                fi
            done
            info "end"
            ;;
    esac
}

# on handshake timeout punch usecase

function on_handshake_timeout_punch_usecase() {
    local action="${1}" && shift
    case "${action}" in
        deps)
            echo "cat sleep"
            ;;
        init)
            info
            WT_ON_HANDSHAKE_TIMEOUT_PUNCH_ENABLED="${WT_ON_HANDSHAKE_TIMEOUT_PUNCH_ENABLED:-true}"
            WT_ON_HANDSHAKE_TIMEOUT_PUNCH_START_DELAY="${WT_ON_HANDSHAKE_TIMEOUT_PUNCH_START_DELAY:-45}" # 46 seconds
            WT_ON_HANDSHAKE_TIMEOUT_PUNCH_INTERVAL="${WT_ON_HANDSHAKE_TIMEOUT_PUNCH_INTERVAL:-15}" # 15 seconds
            WT_ON_HANDSHAKE_TIMEOUT_PUNCH_MAX_BROADCAST_DAY="${WT_ON_HANDSHAKE_TIMEOUT_PUNCH_MAX_BROADCAST_DAY:-250}"
            WT_ON_HANDSHAKE_TIMEOUT_PUNCH_PID_FILE="${WT_EPHEMERAL_PATH}/on_handshake_timeout_punch_usecase.pid"
            ;;
        start)
            local host_id="${1}" && shift
            info "$(short "${host_id}")"

            if [[ "${WT_ON_HANDSHAKE_TIMEOUT_PUNCH_ENABLED}" == "true" ]]
            then
                info "enabled"
                on_handshake_timeout_punch_usecase loop &
                echo "${!}" > "${WT_ON_HANDSHAKE_TIMEOUT_PUNCH_PID_FILE}"
            else
                info "disabled"
            fi
            ;;
        loop)
            info "pause before start: ${WT_ON_HANDSHAKE_TIMEOUT_PUNCH_START_DELAY} seconds"
            sleep "${WT_ON_HANDSHAKE_TIMEOUT_PUNCH_START_DELAY}"

            PUNCH_PID="$(cat "${WT_ON_HANDSHAKE_TIMEOUT_PUNCH_PID_FILE}")"
            SECONDS_DAY="$((24 * 60 * 60))"
            BROADCAST_INTERVAL="$(("${SECONDS_DAY}" / "${WT_ON_HANDSHAKE_TIMEOUT_PUNCH_MAX_BROADCAST_DAY}" * "${peer_id_count}" ))"

            while true
            do
                if [ "$(interface get handshake_timeouted "latest")" == "true" ]
                then
                    info "handshake_timeout is true"
                    if wirething punch_host_endpoint
                    then
                        wirething broadcast_host_endpoint "${host_id}" "${peer_id_list}" &
                        info "pause after broadcast_host_endpoint: ${BROADCAST_INTERVAL} seconds"
                        sleep "${BROADCAST_INTERVAL}"
                    else
                        info "pause after punch_host_endpoint error: ${WT_PAUSE_AFTER_ERROR} seconds"
                        sleep "${WT_PAUSE_AFTER_ERROR}"
                    fi
                else
                    debug "pause: ${WT_ON_HANDSHAKE_TIMEOUT_PUNCH_INTERVAL} seconds"
                    sleep "${WT_ON_HANDSHAKE_TIMEOUT_PUNCH_INTERVAL}"
                fi
            done
            info "end"
            ;;
    esac
}

# peer offline usecase

function peer_offline_usecase() {
    local action="${1}" && shift
    case "${action}" in
        deps)
            echo "sleep"
            ;;
        init)
            info
            WT_PEER_OFFLINE_ENABLED="${WT_PEER_OFFLINE_ENABLED:-true}"
            WT_PEER_OFFLINE_START_DELAY="${WT_PEER_OFFLINE_START_DELAY:-25}" # 25 seconds
            WT_PEER_OFFLINE_FETCH_SINCE="${WT_PEER_OFFLINE_FETCH_SINCE:-60}" # 1 minute
            WT_PEER_OFFLINE_FETCH_INTERVAL="${WT_PEER_OFFLINE_FETCH_INTERVAL:-45}" # 45 seconds
            WT_PEER_OFFLINE_ENSURE_INTERVAL="${WT_PEER_OFFLINE_ENSURE_INTERVAL:-900}" # 15 minutes
            WT_PEER_OFFLINE_INTERVAL="${WT_PEER_OFFLINE_INTERVAL:-25}" # 25 seconds
            ;;
        start)
            local host_id="${1}" && shift
            local peer_id="${1}" && shift
            info "$(short "${peer_id}")"

            if [[ "${WT_PEER_OFFLINE_ENABLED}" == "true" ]]
            then
                info "enabled"
                peer_offline_usecase loop &
            else
                info "disabled"
            fi
            ;;
        loop)
            info "pause before start: ${WT_PEER_OFFLINE_START_DELAY} seconds"
            sleep "${WT_PEER_OFFLINE_START_DELAY}"

            local last_status=""

            while true
            do
                local status="$(interface get peer_status "${peer_id}")"

                if [ "${status}" != "${last_status}" ]
                then
                    info "peer status: ${status}"
                    last_status="${status}"
                fi

                local since="all"
                local next_ensure="0"

                while [ "${status}" == "offline" ]
                do
                    if [ "${since}" == "all" ]
                    then
                        info "fetch_peer_endpoint: started"
                    fi

                    if [[ $(epoch) -gt ${next_ensure} ]]
                    then
                        if wirething ensure_host_endpoint_is_published "${host_id}" "${peer_id}"
                        then
                            next_ensure="$(($(epoch) + "${WT_PEER_OFFLINE_ENSURE_INTERVAL}"))"
                            info "next ensure_host_endpoint_is_published in $((${next_ensure} - $(epoch))) seconds"
                        else
                            break
                        fi
                    fi

                    if ! wirething fetch_peer_endpoint "${host_id}" "${peer_id}" "${since}"
                    then
                        break
                    fi

                    debug "pause after fetch_peer_endpoint: ${WT_PEER_OFFLINE_FETCH_INTERVAL} seconds"
                    sleep "${WT_PEER_OFFLINE_FETCH_INTERVAL}"

                    since="${WT_PEER_OFFLINE_FETCH_SINCE}s"
                    status="$(interface get peer_status "${peer_id}")"
                done

                if [ "${since}" != "all" ]
                then
                    info "fetch_peer_endpoint: stopped"
                fi

                debug "pause: ${WT_PEER_OFFLINE_INTERVAL} seconds"
                sleep "${WT_PEER_OFFLINE_INTERVAL}"
            done
            info "end"
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

wt_others_list=(
    utils
    udp
    wirething
    on_interval_punch_usecase
    on_handshake_timeout_punch_usecase
    peer_offline_usecase
)

function wt_get_alias() {
    alias ${wt_type} | cut -f 2 -d "'"
}

function wt_type_for_each() {
    for wt_type in "${wt_type_list[@]}"
    do
        "$(wt_get_alias "${wt_type}")" "${1}"
    done
}

function wt_others_for_each() {
    for wt_other in "${wt_others_list[@]}"
    do
        "${wt_other}" "${1}"
    done
}

function wirething_main() {
    local action="${1}" && shift
    case "${action}" in
        deps)
            {
                echo "mkdir rm sed sort uniq wc"

                wt_type_for_each deps
                wt_others_for_each deps
            } | sed "s, ,\n,g" | sort | uniq | {
                while read dep
                do
                    printf "%-13s" "${dep}"
                    echo "$(type -P "${dep}" || echo "not found")"
                done
            }
            ;;
        init)
            info

            set_pid
            WT_PID="${PID}"
            WT_CONFIG_PATH="${PWD}"
            WT_RUN_PATH="${WT_RUN_PATH:-/var/run/wirething}"
            WT_EPHEMERAL_PATH="${WT_RUN_PATH}/${WT_PID}"
            WT_PAUSE_AFTER_ERROR="${WT_PAUSE_AFTER_ERROR:-30}" # 30 seconds

            info "WT_PID=${WT_PID}"

            wt_type_for_each init
            wt_others_for_each init
            ;;
        signal)
            info "${@}"

            local signal="${1:-}" && shift
            local result="${1:-}" && shift
            local lineno="${1:-}" && shift
            local funcname="${1:-}" && shift

            case "${signal}" in
                ERR)
                    error "signal=${signal} result=${result} lineno=${lineno} funcname=${funcname}"
                    ;;
                EXIT)
                    # Set trap to empty to run only once
                    trap "" ${signal}
                    info "pkill -term -g ${WT_PID}"
                    pkill -TERM -g "${WT_PID}" || true
                    wirething_main down
                    ;;
            esac
            return 0
            ;;
        trap)
            for signal in EXIT ERR SIGTERM
            do
                trap "wirething_main signal \"${signal}\" \"${?:-null}\" \"\${LINENO:-}\" \"\${FUNCNAME[0]:-}\"" "${signal}"
            done
            ;;
        up)
            info

            wirething_main trap

            mkdir -p "${WT_EPHEMERAL_PATH}"

            wt_type_for_each up
            wt_others_for_each up

            local _host_id="$(interface get host_id)"
            local peer_id_list="$(interface get peer_id_list)"

            wirething up_host "${_host_id}"

            for _peer_id in ${peer_id_list}
            do
                wirething up_peer "${_peer_id}" "${_host_id}"
            done
            ;;
        down)
            wt_type_for_each down
            wt_others_for_each down

            info
            if rm -rf "${WT_EPHEMERAL_PATH}"
            then
                info "*${WT_EPHEMERAL_PATH}* was deleted"
            else
                error "*${WT_EPHEMERAL_PATH}* delete error"
            fi
            ;;
        start)
            info
            local _host_id="$(interface get host_id)"
            local peer_id_list="$(interface get peer_id_list)"
            local peer_id_count="$(interface get peer_id_list | wc -l)"

            on_interval_punch_usecase start "${_host_id}"
            on_handshake_timeout_punch_usecase start "${_host_id}"

            for _peer_id in ${peer_id_list}
            do
                peer_offline_usecase start "${_host_id}" "${_peer_id}"
            done
            ;;
        wait)
            info
            wait $(jobs -p) || true
            info "end"
            ;;
    esac
}

# main

function main() {
    wirething_main init
    wirething_main up
    wirething_main start
    wirething_main wait
}

case "${1:-${WT_ACTION:-}}" in
    deps)
        wirething_main deps
        ;;
    test)
        ;;
    *)
        main
esac
