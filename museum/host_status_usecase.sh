function host_status_usecase() {
    local action="${1}" && shift

    case "${action}" in
        deps)
            echo "sleep"
            ;;
        init)
            info
            WT_HOST_OFFLINE_ENABLED="${WT_HOST_OFFLINE_ENABLED:-true}"
            WT_HOST_OFFLINE_START_DELAY="${WT_HOST_OFFLINE_START_DELAY:-20}" # 20 seconds
            WT_HOST_OFFLINE_INTERVAL="${WT_HOST_OFFLINE_INTERVAL:-30}" # 30 seconds
            WT_HOST_OFFLINE_ENSURE_INTERVAL="${WT_HOST_OFFLINE_ENSURE_INTERVAL:-60}" # 1 minute
            WT_HOST_OFFLINE_PUNCH_PID_FILE="${WT_EPHEMERAL_PATH}/host_status_usecase.pid"
            ;;
        start)
            local host_id="${1}" && shift
            local log_id="${host_id}"
            local log_name="$(interface get hostname "${host_id}")"

            info "$(short "${host_id}")"

            if [[ "${WT_HOST_OFFLINE_ENABLED}" == "true" ]]
            then
                info "enabled"
                host_status_usecase loop &
                echo "${!}" > "${WT_HOST_OFFLINE_PUNCH_PID_FILE}"
            else
                info "disabled"
            fi
            ;;
        online)
            info
            while [ "$(interface get host_status "${host_id}")" == "online" ]
            do
                debug "pause: ${WT_HOST_OFFLINE_INTERVAL} seconds"
                sleep "${WT_HOST_OFFLINE_INTERVAL}"
            done
            ;;
        offline)
            info

            local next_ensure="0"

            while [ "$(interface get host_status "${host_id}")" == "offline" ]
            do
                if [[ $(epoch) -gt ${next_ensure} ]]
                then
                    local status="online"

                    if [ "$(pubsub status)" == "offline" ]
                    then
                        info "pubsub status: offline"
                        status="offline"
                    else
                        read host_endpoint < <(wirething get host_endpoint)
                        read host_port < <(wirething get host_port)

                        wirething set host_port "0"

                        if [[ "${host_port}" != "0" && "$(punch status "${host_port}" "${host_endpoint}")" == "online" ]]
                        then
                            wirething set host_port "${host_port}"
                        else
                            info "punch status: offline"
                            status="offline"

                            if wirething punch_host_endpoint
                            then
                                wirething broadcast_host_endpoint "${host_id}" "${peer_id_list}" &
                                status="online"
                            else
                                wirething set host_port "${host_port}"
                            fi
                        fi
                    fi

                    if [ "${status}" == "online" ]
                    then
                        for _peer_id in ${peer_id_list}
                        do
                            if ! wirething ensure_host_endpoint_is_published "${host_id}" "${_peer_id}"
                            then
                                status="offline"
                            fi
                        done
                    fi

                    if [ "${status}" == "online" ]
                    then
                        next_ensure="$(($(epoch) + "${WT_HOST_OFFLINE_ENSURE_INTERVAL}"))"
                        info "next ensure_host_endpoint_is_published in $((${next_ensure} - $(epoch))) seconds"
                    fi

                    if [ "${status}" == "offline" ]
                    then
                        info "pause after error: ${WT_PAUSE_AFTER_ERROR} seconds"
                        sleep "${WT_PAUSE_AFTER_ERROR}"
                        continue
                    fi
                fi

                debug "pause: ${WT_HOST_OFFLINE_INTERVAL} seconds"
                sleep "${WT_HOST_OFFLINE_INTERVAL}"
            done
            ;;
        loop)
            info "pause before start: ${WT_HOST_OFFLINE_START_DELAY} seconds"
            sleep "${WT_HOST_OFFLINE_START_DELAY}"

            PUNCH_PID="$(cat "${WT_HOST_OFFLINE_PUNCH_PID_FILE}")"

            while true
            do
                case "$(interface get host_status "${host_id}")" in
                    online)
                        host_status_usecase online
                        ;;
                    offline)
                        host_status_usecase offline
                        ;;
                    *)
                        error "invalid host status"
                esac

            done

            info "end"
            ;;
    esac
}
