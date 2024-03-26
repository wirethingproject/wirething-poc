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
