function peer_status_usecase() {
    local action="${1}" && shift

    case "${action}" in
        deps)
            echo "sleep"
            ;;
        init)
            info
            WT_PEER_OFFLINE_ENABLED="${WT_PEER_OFFLINE_ENABLED:-true}"
            WT_PEER_OFFLINE_START_DELAY="${WT_PEER_OFFLINE_START_DELAY:-10}" # 10 seconds
            WT_PEER_OFFLINE_FETCH_SINCE="${WT_PEER_OFFLINE_FETCH_SINCE:-60}" # 1 minute
            WT_PEER_OFFLINE_FETCH_INTERVAL="${WT_PEER_OFFLINE_FETCH_INTERVAL:-45}" # 45 seconds
            WT_PEER_OFFLINE_ENSURE_INTERVAL="${WT_PEER_OFFLINE_ENSURE_INTERVAL:-900}" # 15 minutes
            WT_PEER_OFFLINE_INTERVAL="${WT_PEER_OFFLINE_INTERVAL:-30}" # 30 seconds
            ;;
        start)
            local host_id="${1}" && shift
            local peer_id="${1}" && shift
            local peer_name="$(interface get hostname "${peer_id}")"
            local log_id="${peer_id}"
            local log_name="${peer_name}"

            info "${peer_name}"

            if [[ "${WT_PEER_OFFLINE_ENABLED}" == "true" ]]
            then
                info "enabled"
                peer_status_usecase loop &
            else
                info "disabled"
            fi
            ;;
        online)
            info
            while [ "$(interface get peer_status "${peer_id}")" == "online" ]
            do
                debug "pause: ${WT_PEER_OFFLINE_INTERVAL} seconds"
                sleep "${WT_PEER_OFFLINE_INTERVAL}"
            done
            ;;
        offline)
            info

            local since="all"
            local next_ensure="0"

            while [ "$(interface get peer_status "${peer_id}")" == "offline" ]
            do
                if [[ $(epoch) -gt ${next_ensure} ]]
                then
                    if wirething ensure_host_endpoint_is_published "${host_id}" "${peer_id}"
                    then
                        next_ensure="$(($(epoch) + "${WT_PEER_OFFLINE_ENSURE_INTERVAL}"))"
                        info "next ensure_host_endpoint_is_published in $((${next_ensure} - $(epoch))) seconds"
                    else
                        info "pause after error: ${WT_PAUSE_AFTER_ERROR} seconds"
                        sleep "${WT_PAUSE_AFTER_ERROR}"
                        continue
                    fi
                fi

                if ! wirething fetch_peer_endpoint "${host_id}" "${peer_id}" "${since}"
                then
                    info "pause after error: ${WT_PAUSE_AFTER_ERROR} seconds"
                    sleep "${WT_PAUSE_AFTER_ERROR}"
                    continue
                fi

                debug "pause after fetch_peer_endpoint: ${WT_PEER_OFFLINE_FETCH_INTERVAL} seconds"
                sleep "${WT_PEER_OFFLINE_FETCH_INTERVAL}"

                since="${WT_PEER_OFFLINE_FETCH_SINCE}s"
            done
            ;;
        loop)
            info "pause before start: ${WT_PEER_OFFLINE_START_DELAY} seconds"
            sleep "${WT_PEER_OFFLINE_START_DELAY}"

            while true
            do
                case "$(interface get peer_status "${peer_id}")" in
                    online)
                        peer_status_usecase online
                        ;;
                    offline)
                        peer_status_usecase offline
                        ;;
                    *)
                        error "invalid peer status"
                esac

            done

            info "end"
            ;;
    esac
}
