# json kv

function json_kv() {
    local action="${1}" && shift

    case "${action}" in
        deps)
            echo "cat jq"
            ;;
        init)
            info

            WT_KV_FILENAME="${WT_KV_FILENAME:-${WT_STATE_PATH}/kv.json}"

            declare -g -A _kv

            json_kv load
            ;;
        up)
            info
            ;;
        down)
            info

            json_kv store
            ;;
        load)
            info

            if [ -f "${WT_KV_FILENAME}" ]
            then
                local key value
                while read -r key value
                do
                    _kv["${key}"]="${value}"
                done < <(cat "${WT_KV_FILENAME}" | jq -r 'to_entries[] | "\(.key) \(.value)"')
            fi

            ;;
        store)
            info

            local json="{"

            for _key in "${!_kv[@]}"; do
                json+="\n  \"${_key}\":\"${_kv[${_key}]}\","
            done

            json="${json%,}"
            json+="\n}\n"

            echo -ne "${json}" > "${WT_KV_FILENAME}"
            ;;
        get)
            local name="${1}" && shift
            local key="${1}" && shift

            echo -n "${_kv["${name}_${key}"]}"
            ;;
        set)
            local name="${1}" && shift
            local key="${1}" && shift
            local value="${1}" && shift

            _kv["${name}_${key}"]="${value}"
            ;;
    esac
}

WT_KV_TYPE="${WT_KV_TYPE:-json}"
alias kv="${WT_KV_TYPE}_kv"
kv ""        || die "invalid WT_KV_TYPE *${WT_KV_TYPE}*, options: $(options kv)"



