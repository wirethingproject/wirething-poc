
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
            WT_ON_HANDSHAKE_TIMEOUT_PUNCH_START_DELAY="${WT_ON_HANDSHAKE_TIMEOUT_PUNCH_START_DELAY:-45}" # 45 seconds
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
