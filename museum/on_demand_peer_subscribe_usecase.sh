# on demand peer subscribe usecase

function on_demand_peer_subscribe_usecase() {
    action="${1}" && shift
    case "${action}" in
        deps)
            echo "sleep"
            ;;
        init)
            info "on_demand_peer_subscribe_usecase init"
            WT_ON_DEMAND_PEER_SUBSCRIBE_ENABLED="${WT_ON_DEMAND_PEER_SUBSCRIBE_ENABLED:-false}"
            WT_ON_DEMAND_PEER_SUBSCRIBE_START_DELAY="${WT_ON_DEMAND_PEER_SUBSCRIBE_START_DELAY:-1}" # 1 second
            WT_ON_DEMAND_PEER_SUBSCRIBE_INTERVAL="${WT_ON_DEMAND_PEER_SUBSCRIBE_INTERVAL:-60}" # 60 second
            ;;
        start)
            if [[ "${WT_ON_DEMAND_PEER_SUBSCRIBE_ENABLED}" == "true" ]]
            then
                info "on_demand_peer_subscribe_usecase start $(short "${peer_id}")"
                on_demand_peer_subscribe_usecase loop &
            else
                info "on_demand_peer_subscribe_usecase disabled $(short "${peer_id}")"
            fi
            ;;
        loop)
            debug "on_demand_peer_subscribe_usecase start $(short "${peer_id}") delay ${WT_ON_DEMAND_PEER_SUBSCRIBE_START_DELAY}"
            sleep "${WT_ON_DEMAND_PEER_SUBSCRIBE_START_DELAY}"
            while true
            do
                if [ "$(interface get handshake_timeout "${peer_id}")" == "true" ]
                then
                    wirething listen_peer_endpoint "${host_id}" "${peer_id}"
                else
                    debug "on_demand_peer_subscribe_usecase handshake_timeout $(short "${peer_id}") interval ${WT_ON_DEMAND_PEER_SUBSCRIBE_INTERVAL} seconds"
                    sleep "${WT_ON_DEMAND_PEER_SUBSCRIBE_INTERVAL}"
                fi
            done
            debug "on_demand_peer_subscribe_usecase end $(short "${peer_id}")"
            ;;
    esac
}
