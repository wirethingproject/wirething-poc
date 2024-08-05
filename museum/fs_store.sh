# store

function fs_store() {
    local action="${1}" && shift

    case "${action}" in
        _init)
            WT_STORE_VERSION="v1"

            if [ "$(id -u)" != 0 ]
            then
                WT_STORE_PATH="${WT_STORE_PATH:-${HOME}/.wirething}"
            else
                WT_STORE_PATH="${WT_STORE_PATH:-/etc/wirething}"
            fi

            if [ ! -e "${WT_STORE_PATH}" ]
            then
                mkdir -p "${WT_STORE_PATH}"
            fi
            ;;
        create)
            local domain="${1}" && shift
            local hostname="${1}" && shift

            local domain_path="${WT_STORE_PATH}/${domain}"

            if [ -e "${domain_path}" ]
            then
                die "${domain_path} domain exists"
            fi

            local version_path="${WT_STORE_PATH}/${domain}/${WT_STORE_VERSION}"

            mkdir -p "${version_path}"/{peers,state}

            echo "${WT_STORE_VERSION}" > "${domain_path}/.version"

            info "${domain_path} created"

            fs_store _gen env "${domain}" "${hostname}"
            fs_store _gen "${WT_INTERFACE_TYPE}" "${domain}"
            fs_store _gen gpg "${domain}"
            ;;
        add)
            local domain="${1:?Missing domain param}" && shift
            local peer_file="${1:?Missing peer_file param}" && shift

            if [ ! -e "${peer_file}" ]
            then
                die "${peer_file} not found"
            fi

            {
                cat "${peer_file}" \
                    | grep "^WT_PEER_HOSTNAME=" \
                    | sed 's,.*"\(.*\)",\1,'
            } | {
                read hostname

                cat "${peer_file}" \
                    | fs_store _set "${domain}" "peers/${hostname}.peer"
            }
            ;;
        peer)
            local subaction="${1:?Missing subaction param, options: address}" && shift

            case "${subaction}" in
                address)
                    local domain="${1:?Missing domain param}" && shift
                    local peer_name="${1:?Missing peer param}" && shift

                    fs_store _get "${domain}" "peers/${peer_name}.peer" \
                            | grep "^WT_PEER_ADDRESS=" \
                            | sed 's,.*"\(.*\)",\1,'
                    ;;
            esac
            ;;
        export)
            local domain="${1}" && shift
            local hostname="${1}" && shift
            local host_peer_file="${1}" && shift

            if [ -e "${host_peer_file}" ]
            then
                die "'${host_peer_file}' exists"
            fi

            ({
                source "$(fs_store _filename "${domain}" "env")"

                cat <<EOF
WT_PEER_HOSTNAME="${hostname}"
WT_PEER_ADDRESS="${WT_ADDRESS}"
WT_PEER_ROUTE_LIST="${WT_ROUTE_LIST}"
WT_PEER_INTERFACE_TYPE="${WT_INTERFACE_TYPE}"
WT_PEER_PUBSUB_TYPE="${WT_PUBSUB_TYPE}"
WT_PEER_ENCRYPTION_TYPE="${WT_ENCRYPTION_TYPE}"
WT_PEER_TOPIC_TYPE="${WT_TOPIC_TYPE}"
EOF

                case "${WT_INTERFACE_TYPE}" in
                    wg_quick|wireproxy)
                        cat <<EOF
WT_PEER_WG_PUB="$(fs_store _get "${domain}" "wg.pub")"
EOF
                        ;;
                esac

                case "${WT_ENCRYPTION_TYPE}" in
                    gpg_ephemeral)
                        fs_store _get "${domain}" "gpg.pub"
                        ;;
                esac
            }) > "${host_peer_file}"

            info "${host_peer_file} created"
            ;;
        to_env)
            local domain="${1}" && shift

            local version_path="${WT_STORE_PATH}/${domain}/${WT_STORE_VERSION}"

            WT_CONFIG_PATH="${version_path}"

            if [ "$(id -u)" != 0 ]
            then
                WT_RUN_PATH="${WT_RUN_PATH:-${WT_CONFIG_PATH}/_run}"
            else
                WT_RUN_PATH="${WT_RUN_PATH:-/var/run/wirething}"
            fi

            rm -rf "${WT_CONFIG_PATH}/_env"
            mkdir -p "${WT_CONFIG_PATH}/_env"
            mkdir -p "${WT_RUN_PATH}"

            source <(fs_store _get "${domain}" "env")

            WGQ_HOST_ADDRESS="${WT_ADDRESS}/32"
            WGQ_HOST_PRIVATE_KEY_FILE="wg.key"
            WGQ_PEER_PUBLIC_KEY_FILE_LIST=""
            GPG_FILE_LIST="gpg.key gpg.pub"

            while read peer_file
            do
                local hostname="$(fs_store _get "${domain}" "peers/${peer_file}" \
                        | grep "^WT_PEER_HOSTNAME=" \
                        | sed 's,.*"\(.*\)",\1,'
                )"
                local address="$(fs_store _get "${domain}" "peers/${peer_file}" \
                        | grep "^WT_PEER_ADDRESS=" \
                        | sed 's,.*"\(.*\)",\1,'
                )"

                source <({

                    fs_store _get "${domain}" "peers/${peer_file}" \
                        | grep "^WT_PEER_.*=" \
                        | sed "s,^WT_PEER,WT_PEER_${hostname^^},"

                    cat <<EOF
WGQ_PEER_${hostname^^}_ALLOWED_IPS="\${WT_PEER_${hostname^^}_ROUTE_LIST}"
EOF

                })

                WGQ_PEER_PUBLIC_KEY_FILE_LIST+=" _env/${hostname}.pub"
                WGQ_PEER_PUBLIC_KEY_VAR_NAME="WT_PEER_${hostname^^}_ID"
                echo "${!WGQ_PEER_PUBLIC_KEY_VAR_NAME}" \
                    | fs_store _set "${domain}" "_env/${hostname}.pub"

                GPG_FILE_LIST+=" _env/${hostname}-pub.gpg"
                fs_store _get "${domain}" "peers/${peer_file}" \
                    | grep -v "^WT_PEER_.*=" \
                    | fs_store _set "${domain}" "_env/${hostname}-pub.gpg"
            done < <(fs_store _peer_list "${domain}")
            ;;
        from_env)
            local domain="${1}" && shift
            ;;
        _peer_list)
            local domain="${1}" && shift

            local version_path="${WT_STORE_PATH}/${domain}/${WT_STORE_VERSION}"

            ls "${version_path}/peers"
            ;;
        _gen)
            local subaction="${1}" && shift

            case "${subaction}" in
                env)
                    local domain="${1}" && shift
                    local hostname="${1}" && shift

                    local address="100.$((${RANDOM} % 62 + 65)).$((${RANDOM} % 254 + 1)).$((${RANDOM} % 254 + 1))"

                    {
                        cat <<EOF
WT_DOMAIN="${domain}"
WT_HOSTNAME="${hostname}"
WT_ADDRESS="${address}"
WT_ROUTE_LIST="${address}/32"
WT_INTERFACE_TYPE="${WT_INTERFACE_TYPE}"
WT_PUNCH_TYPE="${WT_PUNCH_TYPE}"
WT_PUBSUB_TYPE="${WT_PUBSUB_TYPE}"
WT_ENCRYPTION_TYPE="${WT_ENCRYPTION_TYPE}"
WT_TOPIC_TYPE="${WT_TOPIC_TYPE}"
WT_LOG_LEVEL="info"
EOF
                case "${WT_INTERFACE_TYPE}" in
                    wireproxy)
                        cat <<EOF
WIREPROXY_COMMAND="${WIREPROXY_COMMAND}"
WIREPROXY_HTTP_BIND="${WIREPROXY_HTTP_BIND:-disabled}" # 127.0.0.1:3128
WIREPROXY_SOCKS5_BIND="${WIREPROXY_SOCKS5_BIND:-127.0.0.1:1080}"
WIREPROXY_HEALTH_BIND="${WIREPROXY_HEALTH_BIND:-127.0.0.1:9080}"
WIREPROXY_EXPOSE_PORT_LIST="${WIREPROXY_EXPOSE_PORT_LIST:-}"
WIREPROXY_FORWARD_PORT_LIST=""
EOF
                        ;;
                esac
                    } | fs_store _set "${domain}" "env"
                    ;;
                wg)
                    local domain="${1}" && shift
                    ;;
                wg_quick|wireproxy)
                    local domain="${1}" && shift

                    ({
                        umask 077

                        wg genkey \
                            | fs_store _set "${domain}" "wg.key"

                        fs_store _get "${domain}" "wg.key" \
                            | wg pubkey \
                            | fs_store _set "${domain}" "wg.pub"
                    })
                    ;;
                gpg)
                    local domain="${1}" && shift

                    local gpg_domain_name="${GPG_DOMAIN_NAME:-wirething.gpg}"

                    ({
                        umask 077

                        export GNUPGHOME="$(mktemp -d)"

                        {
                            fs_store _get "${domain}" "wg.pub"
                        } | {
                            read host_wg_pub

                            local keyname="${host_wg_pub}@${gpg_domain_name}"

                            gpg --pinentry-mode=loopback  --passphrase "" --yes --quick-generate-key "${keyname}" \
                                1>&${WT_LOG_DEBUG} 2>&${WT_LOG_DEBUG}

                            gpg --armor --export-secret-keys "${keyname}" 2>&${WT_LOG_DEBUG} \
                                | fs_store _set "${domain}" "gpg.key"

                            gpg --armor --export "${keyname}" 2>&${WT_LOG_DEBUG} \
                                | fs_store _set "${domain}" "gpg.pub"
                        }

                        rm -rf "${GNUPGHOME}"
                        unset -v GNUPGHOME
                    })
                    ;;
            esac
            ;;
        _filename)
            local domain="${1}" && shift
            local filename="${1}" && shift

            local version_path="${WT_STORE_PATH}/${domain}/${WT_STORE_VERSION}"

            echo "${version_path}/${filename}"
            ;;
        _set)
            local domain="${1}" && shift
            local filename="${1}" && shift

            local version_path="${WT_STORE_PATH}/${domain}/${WT_STORE_VERSION}"

            cat > "${version_path}/${filename}"

            info "${version_path}/${filename} created"
            ;;
        _get)
            local domain="${1}" && shift
            local filename="${1}" && shift

            local version_path="${WT_STORE_PATH}/${domain}/${WT_STORE_VERSION}"

            cat "${version_path}/${filename}"
            ;;
    esac
}

WT_STORE_TYPE="${WT_STORE_TYPE:-fs}"
alias store="${WT_STORE_TYPE}_store"
store ""    || die "invalid WT_STORE_TYPE *${WT_STORE_TYPE}*, options: $(options store)"

if [ "${WT_STORE_ENABLED:-false}" == "true" ]
then
    store _init
    store to_env "${WT_DOMAIN:?Variable not set}"
fi

# cli

function help() {
    cat <<EOF
Usage: wirething-poc.sh cli <action>
EOF
}

function cli() {
    local action="${1:?Missing action param, options: new export add peer}" && shift

    case "${action}" in
        init)
            store _init
            ;;
        to_env|from_env)
            local domain="${1:?Missing domain param}" && shift
            set -a
            store "${action}" "${domain}"
            set +a
            printenv | grep "^WGQ_\|WT_\|GPG_" | sort
            ;;
        new)
            local domain="${1:?Missing domain param}" && shift
            local hostname="${1:?Missing hostname param}" && shift

            store create "${domain}" "${hostname}"
            ;;
        export)
            local domain="${1:?Missing domain param}" && shift
            local hostname="${1:?Missing hostname param}" && shift
            local host_peer_file="${1:-${PWD}/${hostname}.peer}"

            store export "${domain}" "${hostname}" "${host_peer_file}"
            ;;
        add)
            local domain="${1:?Missing domain param}" && shift
            local peer_file="${1:?Missing peer_file param}" && shift

            store add "${domain}" "${peer_file}"
            ;;
        peer)
            store peer ${@}
            ;;
        *)
            help
    esac
}

case "${1:-${WT_ACTION:-}}" in
    cli)
        shift || true
        cli init
        cli ${@}
        ;;
esac
