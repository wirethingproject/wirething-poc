function wirething() {
    local action="${1}" && shift
    case "${action}" in
        subscribe_peer_endpoint)
            debug
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
        listen_peer_endpoint)
            debug
            host_id="${1}" && shift
            peer_id="${1}" && shift

            {
                wirething subscribe_peer_endpoint "${host_id}" "${peer_id}"
            } | {
                wirething on_new_peer_endpoint "${host_id}" "${peer_id}"
            }
            ;;
    esac
}
