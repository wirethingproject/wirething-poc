# always on peer subscribe usecase

function always_on_peer_subscribe_usecase() {
    action="${1}" && shift
    case "${action}" in
        deps)
            echo "sleep"
            ;;
        init)
            info "always_on_peer_subscribe_usecase init"
            WT_ALWAYS_ON_PEER_SUBSCRIBE_ENABLED="${WT_ALWAYS_ON_PEER_SUBSCRIBE_ENABLED:-true}"
            WT_ALWAYS_ON_PEER_SUBSCRIBE_START_DELAY="${WT_ALWAYS_ON_PEER_SUBSCRIBE_START_DELAY:-25}" # 25 second
            WT_ALWAYS_ON_PEER_SUBSCRIBE_INTERVAL="${WT_ALWAYS_ON_PEER_SUBSCRIBE_INTERVAL:-5}" # 5 second
            ;;
        start)
            if [[ "${WT_ALWAYS_ON_PEER_SUBSCRIBE_ENABLED}" == "true" ]]
            then
                info "always_on_peer_subscribe_usecase start $(short "${peer_id}")"
                always_on_peer_subscribe_usecase loop &
            else
                info "always_on_peer_subscribe_usecase disabled $(short "${peer_id}")"
            fi
            ;;
        loop)
            debug "always_on_peer_subscribe_usecase start $(short "${peer_id}") delay ${WT_ALWAYS_ON_PEER_SUBSCRIBE_START_DELAY}"
            sleep "${WT_ALWAYS_ON_PEER_SUBSCRIBE_START_DELAY}"

            if [ "$(interface get handshake_timeout "${peer_id}")" == "true" ]
            then
                wirething fetch_peer_endpoint "${host_id}" "${peer_id}"
            fi

            while true
            do
                wirething listen_peer_endpoint "${host_id}" "${peer_id}"

                debug "always_on_peer_subscribe_usecase subscribe starting $(short "${peer_id}") interval ${WT_ALWAYS_ON_PEER_SUBSCRIBE_INTERVAL} seconds"
                sleep "${WT_ALWAYS_ON_PEER_SUBSCRIBE_INTERVAL}"
            done
            debug "always_on_peer_subscribe_usecase end $(short "${peer_id}")"
            ;;
    esac
}
