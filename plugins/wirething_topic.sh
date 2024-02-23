
# basic topic

function wirething_topic_timestamp() {
    echo -n "$(($(epoch) / ${WT_TOPIC_TIMESTAMP_OFFSET}))"
}

function wirething_topic_hash_values() {
    tag_hash="$(echo -n ${WT_TOPIC_TAG} | sha256sum | cut -f 1 -d " ")"
    timestamp_hash="$(wirething_topic_timestamp | sha256sum | cut -f 1 -d " ")"
    host_id_hash="$(echo -n "${host_id}" | sha256sum | cut -f 1 -d " ")"
    peer_id_hash="$(echo -n "${peer_id}" | sha256sum | cut -f 1 -d " ")"
}

function wirething_topic() {
    action="${1}" && shift
    case "${action}" in
        deps)
            echo "sha256sum cut"
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
            echo -n "${tag_hash}:${timestamp_hash}:${host_id_hash}:${peer_id_hash}" | sha256sum | cut -f 1 -d " "
            ;;
        subscribe)
            host_id="${1}" && shift
            peer_id="${1}" && shift
            wirething_topic_hash_values
            echo -n "${tag_hash}:${timestamp_hash}:${peer_id_hash}:${host_id_hash}" | sha256sum | cut -f 1 -d " "
            ;;
    esac
}
