# wireproxy interface

function wireproxy_notify_location() {
    local action=""
    debug

    for _peer_name in ${config["peer_name_list"]}
    do
        wg_quick_interface on_location "${_peer_name}"
    done
}

function wireproxy_generate_config_file() {
    local action=""
    debug

    wg_quick_generate_config_file

    if [ "${WIREPROXY_SOCKS5_BIND}" != "disabled" ]
    then
        cat <<EOF

[Socks5]
BindAddress = ${WIREPROXY_SOCKS5_BIND}
EOF
    fi

    if [ "${WIREPROXY_HTTP_BIND}" != "disabled" ]
    then
        cat <<EOF

[http]
BindAddress = ${WIREPROXY_HTTP_BIND}
EOF
    fi

    for _port in ${WIREPROXY_EXPOSE_PORT_LIST}
    do
        IFS=: read __port __ip <<<"${_port}"
        cat <<EOF

[TCPServerTunnel]
ListenPort = ${__port}
Target = ${__ip:-127.0.0.1}:${__port}
EOF
    done

    for _forward in ${WIREPROXY_FORWARD_PORT_LIST}
    do
        {
            echo "${_forward//:/ }"
        } | {
            read local_port remote_endpoint remote_port local_ip
            cat <<EOF

[TCPClientTunnel]
BindAddress = ${local_ip:-127.0.0.1}:${local_port}
Target = ${remote_endpoint}:${remote_port}
EOF
        }
    done
}


function wireproxy_compat() {
    local major minor patch

    IFS=. read major minor patch < <("${WIREPROXY_COMMAND}" --version | cut -f 3 -d " " | sed "s,^v,,")

    if [[ (${major} -gt ${1}) ||
          (${major} -eq ${1} && ${minor} -gt ${2}) ||
          (${major} -eq ${1} && ${minor} -eq ${2} && ${patch} -ge ${3}) ]]
    then
        return 0
    else
        return 1
    fi
}

function wireproxy_interface() {
    local action="${1}" && shift

    case "${action}" in
        protocol)
            echo "udp"
            ;;
        deps)
            echo "wg cat cut find grep rm sort tail touch sleep"
            ;;
        init)
            info

            WIREPROXY_COMMAND="${WIREPROXY_COMMAND:-wireproxy}"
            WIREPROXY_RELOAD_FILE="${WT_EPHEMERAL_PATH}/wireproxy.reload"
            WIREPROXY_READY_FILE="${WT_EPHEMERAL_PATH}/wireproxy.ready"
            WIREPROXY_HTTP_BIND="${WIREPROXY_HTTP_BIND:-disabled}" # 127.0.0.1:3128
            WIREPROXY_SOCKS5_BIND="${WIREPROXY_SOCKS5_BIND:-127.0.0.1:1080}"
            WIREPROXY_HEALTH_BIND="${WIREPROXY_HEALTH_BIND:-127.0.0.1:9080}"
            WIREPROXY_PEER_STATUS_TIMEOUT="${WIREPROXY_PEER_STATUS_TIMEOUT:-90}" # 35 seconds
            WIREPROXY_HOST_STATUS_TIMEOUT="${WIREPROXY_HOST_STATUS_TIMEOUT:-120}" # 45 seconds
            WIREPROXY_HANDSHAKE_TIMEOUT="${WIREPROXY_HANDSHAKE_TIMEOUT:-135}" # 135 seconds
            WIREPROXY_EXPOSE_PORT_LIST="${WIREPROXY_EXPOSE_PORT_LIST:-}"
            WIREPROXY_FORWARD_PORT_LIST="${WIREPROXY_FORWARD_PORT_LIST:-}"

            if [ "${OS_LOCALE}" == "UTF-8" ]
            then
                WIREPROXY_LOG_PEER_LEN="9"
            else
                WIREPROXY_LOG_PEER_LEN="11"
            fi

            if [ ! -f "${WIREPROXY_COMMAND}" ]
            then
                die "command in WIREPROXY_COMMAND not found *${WIREPROXY_COMMAND}*"
            fi

            if ! wireproxy_compat 1 0 9
            then
                WIREPROXY_HEALTH_BIND="disabled"
                error "health bind disabled, wireproxy not compatible with version 1.0.9"
            fi

            wg_quick_interface init

            declare -g -A wireproxy_name_table
            declare -g -A wireproxy_peer_status
            ;;
        up)
            info

            wg_quick_update_location
            wireproxy_generate_config_file | sys buffer_to_file "${WGQ_CONFIG_FILE}"

            local wg_pub="${config["host_wg_pub"]}"
            local index="${wg_pub::4}…${wg_pub:(-5):4}"
            wireproxy_name_table["${index}"]="${config["host_name"]}"

            for _peer_name in ${config["peer_name_list"]}
            do
                wg_pub="${config["peer_wg_pub_${_peer_name}"]}"
                index="${wg_pub::4}…${wg_pub:(-5):4}"
                wireproxy_name_table["${index}"]="${_peer_name}"
            done

            for _peer_name in ${config["peer_name_list"]}
            do
                wireproxy_peer_status["${_peer_name}"]="wait"
            done

            coproc WIREPROXY_BG (wireproxy_interface run)
            ;;
        down)
            if [[ ! -v WIREPROXY_BG_PID ]]
            then
                info "'wireproxy_bg' was not running"
            else
                if sys terminate "${WIREPROXY_BG_PID}"
                then
                    info "'wireproxy_bg' pid=${WIREPROXY_BG_PID} was successfully stopped"
                else
                    info "'wireproxy_bg' pid=${WIREPROXY_BG_PID} was not running"
                fi
            fi
            ;;
        start)
            info
            local wireproxy_params=""

            if timeout 2 nc -z ${WIREPROXY_HEALTH_BIND/:/ } 2>&${null}
            then
                error "health bind disabled, tcp ${WIREPROXY_HEALTH_BIND} address already in use"
            elif [ "${WIREPROXY_HEALTH_BIND}" != "disabled" ]
            then
                wireproxy_params="-i ${WIREPROXY_HEALTH_BIND}"
            fi

            local host_port="0"
            local host_endpoint=""

            if [ -f "${WT_HOST_PORT_FILE}" ]
            then
                host_port="$(cat "${WT_HOST_PORT_FILE}" 2>&${WT_LOG_DEBUG} || echo)"
            fi

            if [ -f "${WT_HOST_ENDPOINT_FILE}" ]
            then
                host_endpoint="$(cat "${WT_HOST_ENDPOINT_FILE}" 2>&${WT_LOG_DEBUG} || echo)"
            fi

            wg_quick_update_location
            wireproxy_generate_config_file | sys buffer_to_file "${WGQ_CONFIG_FILE}"

            exec {WIREPROXY_FD}< <({
                set +o errexit  # +e Don't exit immediately if any command returns a non-zero status
                "${WIREPROXY_COMMAND}" ${wireproxy_params} -c \
                    <(WGQ_USE_POSTUP_TO_SET_PRIVATE_KEY=false wireproxy_generate_config_file) 2>&1 \
                        | log file "wireproxy"
                wireproxy_interface _status "${?}" "${host_port}" "${host_endpoint}"
            })
            WIREPROXY_PPID="${!}"

            wireproxy_notify_location
            ;;
        _status)
            local exit_status="${1}" && shift
            local host_port="${1}" && shift
            local host_endpoint="${1}" && shift

            action="wireproxy" info "exit status: ${exit_status}"

            if [[ "${exit_status}" != "0" ]]
            then
                if [[ "${host_port}" != "0" && "${host_port}" != "" && "${host_endpoint}" != "" ]] &&
                    "${WT_PUNCH_TYPE}_punch" status "${host_port}" "${host_endpoint}"
                then
                    info "success"
                else
                    info "failed"
                    event fire punch
                fi
            fi
            ;;
        stop)
            info

            if rm -f "${WIREPROXY_READY_FILE}"
            then
                info "'${WIREPROXY_READY_FILE}' was successfully deleted"
            else
                error "'${WIREPROXY_READY_FILE}' delete error"
            fi

            if [[ ! -v WIREPROXY_PPID ]]
            then
                info "'wireproxy' was not running"
            else
                if sys terminate_from_parent_pid "${WIREPROXY_PPID}"
                then
                    info "'wireproxy' ppid=${WIREPROXY_PPID} was successfully stopped"
                else
                    info "'wireproxy' ppid=${WIREPROXY_PPID} was not running"
                fi
            fi

            while wireproxy_interface process_log
            do
                :
            done

            exec {WIREPROXY_FD}>&- || true

            unset -v WIREPROXY_FD
            ;;
        run)
            trap "wireproxy_interface stop" "EXIT"

            wireproxy_interface start

            while wireproxy_interface process_log
            do
                if [[ -f "${WIREPROXY_RELOAD_FILE}" && -f "${WIREPROXY_READY_FILE}" ]]
                then
                    if rm -f "${WIREPROXY_RELOAD_FILE}"
                    then
                        info "'${WIREPROXY_RELOAD_FILE}' was successfully deleted"
                    else
                        error "'${WIREPROXY_RELOAD_FILE}' delete error"
                    fi

                    wireproxy_interface stop
                    wireproxy_interface start
                fi
            done

            info "down"
            ;;
        process_log)
            local line

            if [[ ! -v WIREPROXY_FD ]]
            then
                return 1
            fi

            if ! read line <&"${WIREPROXY_FD}"
            then
                return 1
            fi

            local log_level="info"

            case "${line}" in
                *"Received"*)
                    log_level="trace"
                    ;;
                *"Receiving"*)
                    log_level="trace"
                    ;;
                *"Sending"*)
                    log_level="trace"
                    ;;
                *"Health metric request"*)
                    log_level="trace"
                    ;;
                *"Handshake did not complete after 5 seconds"*)
                    log_level="trace"
                    ;;
                "DEBUG: "*)
                    log_level="debug"
                    ;;
                "ERROR: "*)
                    log_level="error"
                    ;;
            esac

            local log_index=20

            case "${line}" in
                "DEBUG: "*)
                    log_index=27
                    ;;
                "ERROR: "*)
                    log_index=27
                    ;;
            esac

            custom_log "${line}" wireproxy "${log_level}" "${log_index}"

            local index="${line:32:${WIREPROXY_LOG_PEER_LEN}}"

            case "${line}" in
                *"Receiving keepalive packet")
                    local peer_name="${wireproxy_name_table["${index}"]}"

                    if [ "${wireproxy_peer_status["${peer_name}"]}" != "online" ]
                    then
                        wireproxy_peer_status["${peer_name}"]="online"
                        event fire peer_status "${peer_name} online"
                    fi
                    ;;
                *"Received handshake response")
                    local peer_name="${wireproxy_name_table["${index}"]}"

                    if [ "${wireproxy_peer_status["${peer_name}"]}" != "online" ]
                    then
                        wireproxy_peer_status["${peer_name}"]="online"
                        event fire peer_status "${peer_name} online"
                    fi
                    ;;
                *"Failed to send data packets"*)
                    local peer_name="${wireproxy_name_table["${index}"]}"

                    if [ "${wireproxy_peer_status["${peer_name}"]}" != "offline" ]
                    then
                        wireproxy_peer_status["${peer_name}"]="offline"
                        event fire peer_status "${peer_name} offline"
                    fi
                    ;;
                *"Failed to send handshake initiation"*)
                    local peer_name="${wireproxy_name_table["${index}"]}"

                    if [ "${wireproxy_peer_status["${peer_name}"]}" != "offline" ]
                    then
                        wireproxy_peer_status["${peer_name}"]="offline"
                        event fire peer_status "${peer_name} offline"
                    fi
                    ;;
                *"Handshake did not complete after"*)
                    local peer_name="${wireproxy_name_table["${index}"]}"

                    if [ "${wireproxy_peer_status["${peer_name}"]}" != "offline" ]
                    then
                        wireproxy_peer_status["${peer_name}"]="offline"
                        event fire peer_status "${peer_name} offline"
                    fi
                    ;;
                *"Interface state was Down, requested Up, now Up")
                    info "interface is ready"
                    touch "${WIREPROXY_READY_FILE}"
                    event fire ready
                    ;;
                "ERROR"*"IPC error -48: failed to set listen_port: listen udp4 :"*": bind: address already in use")
                    event fire punch
                    ;;
                *"IPC error -48: failed to set listen_port: listen udp4 :"*": bind: address already in use")
                    info "interface was failed"
                    sleep 10
                    ;;
                *"address already in use")
                    info "interface was failed"
                    touch "${WIREPROXY_READY_FILE}"
                    ;;
            esac
            ;;
        reload)
            info
            touch "${WIREPROXY_RELOAD_FILE}"
            ;;
        event)
            local event="${1}" && shift

            case "${event}" in
                peer_status)
                    local peer_name="${1}" && shift
                    local status="${1}" && shift

                    info "peer_status ${peer_name} ${status}"

                    wireproxy_peer_status["${peer_name}"]="${status}"
                    peer_state set_polled_status "${peer_name}" "${status}"
                    ;;
                punch)
                    if wirething punch_host_endpoint
                    then
                        info "punch succeeded"
                        wirething broadcast_host_endpoint
                    else
                        info "punch failed"
                    fi

                    touch "${WIREPROXY_READY_FILE}"
                    ;;
                ready)
                    ui after_status_changed
            esac
            ;;
        get)
            local name="${1}" && shift

            case "${name}" in
                generates_status_events)
                    return 0
                    ;;
                is_peer_local)
                    wg_quick_interface "${action}" "${name}" ${@}
                    ;;
                peer_status)
                    local peer_name="${1}" && shift
                    shift # var_name
                    local var_name="${1}" && shift

                    local result="offline"

                    if [[ "${wireproxy_peer_status["${peer_name}"]}" == "online" ]]
                    then
                        result="online"
                    fi

                    read -N "${#result}" "${var_name}" <<<"${result}"
                    ;;
                host_status)
                    shift # var_name
                    local var_name="${1}" && shift

                    local all_local="true"
                    local has_online_peer="false"
                    local has_online_local_peer="false"

                    for _peer_name in ${config["peer_name_list"]}
                    do
                        if wireproxy_interface get is_peer_local "${_peer_name}"
                        then
                            if [[ "${wireproxy_peer_status["${_peer_name}"]}" == "online" ]]
                            then
                                has_online_local_peer="true"
                            fi
                        else
                            all_local="false"

                            if [[ "${wireproxy_peer_status["${_peer_name}"]}" == "online" ]]
                            then
                                has_online_peer="true"
                            fi
                        fi
                    done

                    if [ "${all_local}" == "true" ]
                    then
                        has_online_peer="${has_online_local_peer}"
                    fi

                    local result="offline"

                    if [[ "${has_online_peer}" == "true" ]]
                    then
                        result="online"
                    fi

                    debug "host_status ${result}"

                    read -N "${#result}" "${var_name}" <<<"${result}"
                    ;;
            esac
            ;;
    esac
}

