
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
        deps)
            echo "sha256sum"
            ;;
        init)
            info "wirething_topic init"
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
