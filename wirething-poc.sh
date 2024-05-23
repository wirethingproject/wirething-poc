#!/usr/bin/env bash

# basic

umask 077

export LC_ALL=C

# bash compat

function is_bash_compat() {
    if [[ (${BASH_VERSINFO[0]} -gt ${1}) ||
          (${BASH_VERSINFO[0]} -eq ${1} && ${BASH_VERSINFO[1]} -ge ${2}) ]]
    then
        return 0
    else
        return 1
    fi
}

function bash_compat() {
    local action="${1}" && shift

    case "${action}" in
        deps)
            ;;
        _init)
            # changelog:    https://github.com/bminor/bash/blob/master/NEWS
            # bash changes: https://web.archive.org/web/20230401195427/https://wiki.bash-hackers.org/scripting/bashchanges

            if ! is_bash_compat 5 0
            then
                local version="${BASH_VERSINFO[@]}"
                echo "bash ${version// /.}"
                echo "bash < 5.0 not supported"
                exit 1
            fi

            # set: http://redsymbol.net/articles/unofficial-bash-strict-mode/

            set -o errexit  # -e Exit immediately if any command returns a non-zero status
            set -o errtrace # -E Make ERR trap work with shell functions
            set -o nounset  # -u Treat unset variables as an error
            set -o pipefail # Return non-zero if any command in a pipeline fails

            shopt -s expand_aliases  # Aliases are expanded on non interactive shell
            shopt -s inherit_errexit # Command substitution inherits the value of the errexit option
            shopt -s execfail        # Don't exit if exec cannot execute the file

            alias epoch='echo "${EPOCHSECONDS}"' # requires bash 5.0
            ;;
    esac
}

bash_compat _init

# utils

function base64linux() {
    base64 -w 0 ${1:-}

    if [ "${1:-}" == "" ]
    then
        echo ""
    fi
}

function utils() {
    local action="${1}" && shift

    case "${action}" in
        deps)
            echo "bash tr readlink base64 grep sed cat openssl ping"

            case "${OSTYPE}" in
                darwin*)
                    ;;
                linux*)
                    ;;
                *)
                    die "OS *${OSTYPE}* not supported"
            esac
            ;;
        _init)
            case "${OSTYPE}" in
                darwin*)
                    alias ping="ping -c 1 -t 5"
                    ;;
                linux*)
                    alias ping="ping -c 1 -W 5"
                    alias base64='base64linux'
                    ;;
                *)
                    die "OS *${OSTYPE}* not supported"
            esac
            ;;
    esac
}

utils _init

function to_upper() {
    echo ${1} | tr "[:lower:]" "[:upper:]"
}

function to_lower() {
    echo ${1} | tr "[:upper:]" "[:lower:]"
}

function hash_id() {
    echo "${1}" | openssl sha256 | sed "s,.* ,,"
}

function options() {
    set | grep "_${1} ()" | sed "s,_${1} (),," | tr -d "\n"
}

function set_pid() {
    PID="${BASHPID:-${$}}"
}

function capture() {
    local action="${1}" shift

    case "${action}" in
        start)
            local name="${1}" shift

            coproc "capture" (cat -u)
            ;;
        stop)
            exec {capture[1]}>&-
            ;;
    esac
}

function log_dev() {
    exec {null}>>/dev/null
    exec {err}>&2
}

# udp

function udp() {
    local action="${1}" && shift

    case "${action}" in
        deps)
            echo "lsof grep sed head"
            ;;
        open)
            local host="${1}" && shift
            local port="${1}" && shift

            exec {UDP_SOCKET}<>/dev/udp/${host}/${port}
            ;;
        close)
            exec {UDP_SOCKET}>&- || true

            unset UDP_SOCKET
            ;;
        port)
            local host="${1}" && shift
            local port="${1}" && shift
            local pid="${1}" && shift

            {
                lsof -P -n -i "udp@${host}:${port}" -a -p "${pid}" \
                    || echo " ${pid} UDP :0->"
            } | {
                grep -m 1 " ${pid} " | sed "s,.* UDP .*:\(.*\)->.*,\1,"
            }
            ;;
        writeline)
            local line="${1}" && shift
            echo "${line}" >&${UDP_SOCKET}
            ;;
        readline)
            head -n 1 <&${UDP_SOCKET} || true
            ;;
    esac
}

# log

function log_default_time() {
    if [[ "${JOURNAL_STREAM:-}" != "" || "${SVDIR:-}" != "" ]]
    then
        echo -n "false"
    else
        echo -n "true"
    fi
}

function log_init() {
    WT_LOG_TIME="${WT_LOG_TIME:-$(log_default_time)}"
    WT_LOG_LEVEL="${WT_LOG_LEVEL:-info}"

    log_id=""
    log_name=""

    log_dev

    WT_LOG_TRACE="${null}"
    WT_LOG_DEBUG="${null}"
    WT_LOG_INFO="${err}"
    WT_LOG_ERROR="${err}"

    export PS4='+ :${LINENO:-} ${FUNCNAME[0]:-}(): '

    case "${WT_LOG_LEVEL}" in
        trace)
            WT_LOG_TRACE="${err}"
            WT_LOG_DEBUG="${err}"
            ;;
        debug)
            WT_LOG_DEBUG="${err}"
            ;;
        info)
            ;;
        error)
            WT_LOG_INFO="${null}"
            ;;
        *)
            die "invalid WT_LOG_LEVEL *${WT_LOG_LEVEL}*, options: trace, debug, info, error"
    esac
}

log_init

function log() {
    if [ "${WT_LOG_TIME}" == "true" ]
    then
        echo -n "$(date -Iseconds) "
    fi

    echo "${@}"
}

function raw_trace() {
    log "TRACE" >&${WT_LOG_TRACE} || true
    cat >&${WT_LOG_TRACE} || true
}

function hex_raw_trace() {
    log "TRACE" >&${WT_LOG_TRACE} || true
    hexdump -C >&${WT_LOG_TRACE} || true
}

function raw_log_set_level() {
    local _level

    if [ "${level}" == "from_line" ]
    then
        _level="${line}"
    else
        _level="${level}"
    fi

    case "${_level}" in
        trace*|TRACE*)
            level_fd="${WT_LOG_TRACE}"
            level_name="TRACE"
            ;;
        debug*|DEBUG*)
            level_fd="${WT_LOG_DEBUG}"
            level_name="DEBUG"
            ;;
        info*|INFO*)
            level_fd="${WT_LOG_INFO}"
            level_name="INFO "
            ;;
        error*|ERROR*)
            level_fd="${WT_LOG_ERROR}"
            level_name="ERROR"
            ;;
        *)
            level_fd="${WT_LOG_ERROR}"
            level_name="ERROR"
    esac
}

function raw_log() {
    local app="${1}" && shift
    local level="${1}" && shift
    local start_index="${1:-0}" && shift

    local line=""
    local level_fd=""
    local level_name=""

    if [ "${level}" == "from_line" ]
    then
        while read line
        do
            raw_log_set_level
            log "${level_name} [${app}] ${line:${start_index}}" >&${level_fd} || true
        done
    else
        raw_log_set_level
        cat | cut -c "$((${start_index} + 1))-" | sed "s,^,$(log "${level_name}" "[${app}] ")," >&${level_fd} || true
    fi
}

function log_set_prefix() {
    prefix="[$(short4 "${log_name}----")-$(short4 "${log_id}----")] ${FUNCNAME[2]:-} ${action:-}"
}

function debug() {
    log_set_prefix
    log "DEBUG" "${prefix}" "${@}" >&${WT_LOG_DEBUG} || true
}

function info() {
    log_set_prefix
    log "INFO " "${prefix}" "${@}" >&${WT_LOG_INFO} || true
}

function error() {
    log_set_prefix
    log "ERROR" "${prefix}" "${@}" >&${WT_LOG_ERROR} || true
}

function die() {
    action="${FUNCNAME[1]:-} ${action:-}"
    error "${@}"
    exit 1
}

function short4() {
    echo "${1::4}"
}

function short() {
    echo "${1::9}"
}

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
                    local peer="${1:?Missing peer param}" && shift

                    fs_store _get "${domain}" "peers/${peer}.peer" \
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
                die "*${host_peer_file}* exists"
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
WT_PEER_ID="$(fs_store _get "${domain}" "wg.pub")"
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
                        | sed "s,^WT_PEER,WT_PEER_$(to_upper ${hostname}),"

                    cat <<EOF
WGQ_PEER_$(to_upper "${hostname}")_ALLOWED_IPS="\${WT_PEER_$(to_upper "${hostname}")_ROUTE_LIST}"
EOF

                })

                WGQ_PEER_PUBLIC_KEY_FILE_LIST+=" _env/${hostname}.pub"
                WGQ_PEER_PUBLIC_KEY_VAR_NAME="WT_PEER_$(to_upper "${hostname}")_ID"
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
WIREPROXY_HTTP_BIND="${WIREPROXY_HTTP_BIND:-disabled}"
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
                        unset GNUPGHOME
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

            for key in "${!_kv[@]}"; do
                json+="\n  \"${key}\":\"${_kv[${key}]}\","
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

# env_config

function env_config() {
    local key="${1}" && shift

    case "${key}" in
        deps)
            echo "wg"
            ;;
        init)
            info

            local config_path="${WT_CONFIG_PATH:?Variable not set}"
            local host_wg_key_file="${WGQ_HOST_PRIVATE_KEY_FILE:?Variable not set}"
            local peer_wg_pub_file_list="${WGQ_PEER_PUBLIC_KEY_FILE_LIST:?Variable not set}"
            local gpg_domain_name="${GPG_DOMAIN_NAME:-wirething.gpg}"

            declare -g -A config

            if [ ! -f "${config_path}/${host_wg_key_file}" ]
            then
                die "file WGQ_HOST_PRIVATE_KEY_FILE not found *${config_path}/${host_wg_key_file}*"
            fi

            local host_wg_pub="$(cat "${config_path}/${host_wg_key_file}" | wg pubkey)"

            local host_name="${host_wg_key_file##*/}" # remove path
            host_name="${host_name%.key}" # remove extension

            config["host_name"]="${host_name}"
            config["host_log_name"]="${host_name}"
            config["host_log_id"]="${host_wg_pub}"
            config["host_wg_pub"]="${host_wg_pub}"
            config["host_gpg_keyname"]="${host_wg_pub}@${gpg_domain_name}"
            config["host_totp_id"]="${host_wg_pub}"

            config["peer_name_list"]=""
            config["peer_id_list"]=""
            config["peer_wg_pub_list"]=""

            for peer_wg_pub_file in ${peer_wg_pub_file_list}
            do
                if [ ! -f "${config_path}/${peer_wg_pub_file}" ]
                then
                    die "file in WGQ_PEER_PUBLIC_KEY_FILE_LIST not found *${config_path}/${peer_wg_pub_file}*"
                fi

                local peer_wg_pub="$(cat "${config_path}/${peer_wg_pub_file}")"

                if [ "${peer_wg_pub}" == "${host_wg_pub}" ]
                then
                    continue
                fi

                local peer_name="${peer_wg_pub_file##*/}" # remove path
                peer_name="${peer_name%.pub}" # remove extension

                config["peer_id_${peer_name}"]="${peer_wg_pub}"

                config["peer_log_name_${peer_name}"]="${peer_name}"
                config["peer_log_id_${peer_name}"]="${host_wg_pub}"

                config["peer_wg_pub_${peer_name}"]="${peer_wg_pub}"
                config["peer_gpg_keyname_${peer_name}"]="${peer_wg_pub}@${gpg_domain_name}"
                config["peer_totp_id_${peer_name}"]="${peer_wg_pub}"

                config["peer_name_list"]+="${peer_name} "
                config["peer_id_list"]+="${peer_wg_pub} "
                config["peer_wg_pub_list"]+="${peer_wg_pub} "
            done

            config["peer_name_list"]="${config["peer_name_list"]% }"
            config["peer_id_list"]="${config["peer_id_list"]% }"
            config["peer_wg_pub_list"]="${config["peer_wg_pub_list"]% }"
            ;;
        up)
            info

            declare -r -g -A config
            ;;
    esac
}

alias config="env_config"

WT_CONFIG_TYPE="${WT_CONFIG_TYPE:-env}"
alias config="${WT_CONFIG_TYPE}_config"
config ""        || die "invalid WT_KVWT_CONFIG_TYPE_TYPE *${WT_CONFIG_TYPE}*, options: $(options config)"

# tasks

function tasks() {
    local action="${1}" && shift

    case "${action}" in
        deps)
            ;;
        init)
            info

            declare -g -A _tasks
            declare -g -A _tasks_next
            ;;
        register)
            shift # name
            local name="${1}" && shift
            shift # frequency
            local frequency="${1}" && shift
            shift # now or +start
            local plus_start="${1}" && shift
            shift # never or +stop
            local plus_stop="${1}" && shift
            shift # task
            local task="${1}" && shift

            local now="$(epoch)"
            local max_now="(1<<63)-1"
            local start="$((${now} ${plus_start/now/+0}))"
            local stop="$((${now} ${plus_stop/never/+${max_now}-${now}}))"

            _tasks["${name}"]="${frequency} ${start} ${stop} ${task}"
            _tasks_next["${name}"]="${start}"

            debug "name=${name} now=${now} next=${_tasks_next["${name}"]} frequency/start/stop/task=${_tasks["${name}"]}"
            ;;
        unregister)
            shift # name
            local name="${1}" && shift

            debug "name=${name} now=$(epoch) next=${_tasks_next["${name}"]} frequency/start/stop/task=${_tasks["${name}"]}"

            unset _tasks["${name}"]
            unset _tasks_next["${name}"]
            ;;
        run)
            local name frequency start stop task next now

            for name in "${!_tasks[@]}"
            do
                read frequency start stop task <<<"${_tasks[${name}]}"
                read next <<<"${_tasks_next[${name}]}"
                read now <<<"$(epoch)"

                if [[ ${now} -ge ${start} && ${now} -ge ${next} && ${now} -lt ${stop} ]]
                then
                    # debug "name=${name} frequency=${frequency} start=${start} stop=${stop} next=${next} now=${now}"
                    ## debug "name=${name} task='${task}'"

                    _tasks_next["${name}"]="$((${now} + ${frequency}))"
                    ${task} || error "task '${task}' returns ${?}"
                fi
            done
            ;;
    esac
}

# wg interface

function wg_interface() {
    local action="${1}" && shift

    case "${action}" in
        protocol)
            echo "udp"
            ;;
        deps)
            echo "wg grep cut sed sort tail ping id"
            ;;
        init)
            info
            WG_INTERFACE="${WG_INTERFACE:?Variable not set}"
            WG_HANDSHAKE_TIMEOUT="${WG_HANDSHAKE_TIMEOUT:-125}" # 125 seconds
            info "WG_INTERFACE=${WG_INTERFACE}"
            ;;
        up)
            info

            if [ "$(id -u)" != 0 ]
            then
                die "wireguard must be run as root: user id $(id -u) != 0"
            fi

            if [ "$(wg_interface status)" == "down" ]
            then
                die "wireguard interface *${WG_INTERFACE:-}* not found."
            fi
            ;;
        set)
            name="${1}" && shift
            case "${name}" in
                host_port)
                    local port="${1}" && shift
                    info "host_port ${port:-''}"
                    wg set "${WG_INTERFACE}" listen-port "${port}"
                    ;;
                peer_endpoint)
                    local peer="${1}" && shift
                    local endpoint="${1}" && shift
                    info "peer_endpoint $(short "${peer}") ${endpoint:-''}"
                    wg set "${WG_INTERFACE}" peer "${peer}" endpoint "${endpoint}"
                    ;;
            esac
            ;;
        get)
            name="${1}" && shift
            case "${name}" in
                peer_address)
                    local peer="${1}" && shift

                    {
                        wg show "${WG_INTERFACE}" allowed-ips
                    } | {
                        grep "${peer}" | cut -f 2 | sed "s,/32,,"
                    } | {
                        read address
                        debug "peer_address $(short "${peer}") ${address:-''}"
                        echo "${address}"
                    }
                    ;;
                peer_status)
                    local peer="${1}" && shift
                    local address="$(wg_interface get peer_address "${peer}")"

                    local result

                    if ping "${address}" 2>&${WT_LOG_DEBUG} | raw_trace
                    then
                        result="online"
                    else
                        result="offline"
                    fi

                    debug "peer_status $(short "${peer}") ${result:-''}"
                    echo "${result}"
                    ;;
                host_status)
                    local result

                    {
                        wg show "${WG_INTERFACE}" allowed-ips
                    } | cut -f 2 | sed "s,/32,," | {
                        result="offline"

                        while read address
                        do
                            if ping "${address}" 2>&${WT_LOG_DEBUG} | raw_trace
                            then
                                result="online"
                            fi

                        done

                        debug "host_status ${result}"
                        echo "${result}"
                    }
                    ;;
                latest_handshake)
                    local peer="${1}" && shift

                    {
                        wg show "${WG_INTERFACE}" latest-handshakes
                    } | {
                        grep "${peer/latest/}" | cut -f 2 | sort -n | tail -n 1
                    } | {
                        read handshake
                        debug "latest_handshake $(short "${peer}") ${handshake:-''}"
                        echo "${handshake}"
                    }
                    ;;
                handshake_timeouted)
                    local peer="${1}" && shift

                    local last_handshake="$(wg_interface get latest_handshake "${peer}")"
                    local handshake_delta="$(($(epoch) - ${last_handshake}))"

                    local result

                    if [[ ${handshake_delta} -lt ${WG_HANDSHAKE_TIMEOUT} ]]
                    then
                        result="false"
                    else
                        result="true"
                    fi

                    debug "handshake_timeouted $(short "${peer}") ${result:-''}"
                    echo "${result}"
                    ;;
            esac
            ;;
        status)
            {
                wg show interfaces
            } | {
                local status="down"

                if [ "${WG_INTERFACE:-}" != "" ] && grep "${WG_INTERFACE}" 1>&${WT_LOG_DEBUG}
                then
                    status="up"
                fi

                info "${status}"
                echo "${status}"
            }
            ;;
    esac
}

# wg quick interface

function wg_quick_validate_peers() {
    local peer_name

    for peer_name in ${config["peer_name_list"]}
    do
        WGQ_PEER_ALLOWED_IPS_VAR_NAME="WGQ_PEER_${peer_name^^}_ALLOWED_IPS"
        local value="${!WGQ_PEER_ALLOWED_IPS_VAR_NAME:?Variable not set}"
    done
}

function wg_quick_generate_config_file() {
    debug

    cat <<EOF
[Interface]
Address = ${WGQ_HOST_ADDRESS}
EOF

    if [ -f "${WT_HOST_PORT_FILE}" ]
    then
            cat <<EOF
ListenPort = $(cat "${WT_HOST_PORT_FILE}")
EOF
    else
            cat <<EOF
ListenPort = 0
EOF
    fi

    if [ "${WGQ_USE_POSTUP_TO_SET_PRIVATE_KEY}" == "true" ]
    then
        cat <<EOF
PostUp = wg set %i private-key ${WT_CONFIG_PATH}/${WGQ_HOST_PRIVATE_KEY_FILE}
EOF
    else
        cat <<EOF
PrivateKey = $(cat "${WT_CONFIG_PATH}/${WGQ_HOST_PRIVATE_KEY_FILE}")
EOF
    fi

    for peer_pub_file in ${WGQ_PEER_PUBLIC_KEY_FILE_LIST}
    do
        local peer_name="${peer_pub_file##*/}" # remove path
        peer_name="${peer_name%.pub}" # remove extension
        peer_name="$(to_upper ${peer_name})" # to upper

        local peer_id="$(cat "${WT_CONFIG_PATH}/${peer_pub_file}")"

        if [ "${peer_id}" == "${config["host_wg_pub"]}" ]
        then
            continue
        fi

        WGQ_PEER_ALLOWED_IPS_VAR_NAME="WGQ_PEER_${peer_name}_ALLOWED_IPS"

        cat <<EOF

[Peer]
PublicKey = ${peer_id}
AllowedIPs = ${!WGQ_PEER_ALLOWED_IPS_VAR_NAME}
PersistentKeepalive = ${WGQ_PEER_PERSISTENT_KEEPALIVE}
EOF

        if [ -f "${WT_PEER_ENDPOINT_PATH}/$(hash_id "${peer_id}")" ]
        then
            local endpoint=$(cat "${WT_PEER_ENDPOINT_PATH}/$(hash_id "${peer_id}")")
            if [ "${endpoint}" != "" ]
            then
            cat <<EOF
Endpoint = ${endpoint}
EOF
            fi
        fi
    done
}

function wg_quick_interface() {
    local action="${1}" && shift

    case "${action}" in
        protocol)
            echo "udp"
            ;;
        deps)
            wg_interface deps
            echo "wg-quick wg cat grep rm id"
            case "${OSTYPE}" in
                darwin*)
                    echo "wireguard-go"
                    ;;
            esac
            ;;
        init)
            info

            WGQ_HOST_PRIVATE_KEY_FILE="${WGQ_HOST_PRIVATE_KEY_FILE:?Variable not set}"
            WGQ_PEER_PUBLIC_KEY_FILE_LIST="${WGQ_PEER_PUBLIC_KEY_FILE_LIST:?Variable not set}"
            WGQ_HOST_ADDRESS="${WGQ_HOST_ADDRESS:?Variable not set}"

            # WT_*
            WGQ_HOSTNAME="${WT_HOSTNAME:-${WGQ_HOST_PRIVATE_KEY_FILE%.key}}"
            # WT_*

            WGQ_USE_POSTUP_TO_SET_PRIVATE_KEY="${WGQ_USE_POSTUP_TO_SET_PRIVATE_KEY:-true}"
            WGQ_PEER_PERSISTENT_KEEPALIVE="${WGQ_PEER_PERSISTENT_KEEPALIVE:-25}" # 25 seconds

            WGQ_LOG_LEVEL="${WGQ_LOG_LEVEL:-}"
            WGQ_USERSPACE="${WGQ_USERSPACE:-}"

            WGQ_INTERFACE="wth${WT_PID}"
            WGQ_CONFIG_FILE="${WT_EPHEMERAL_PATH}/${WGQ_INTERFACE}.conf"

            info "WGQ_INTERFACE=${WGQ_INTERFACE}"

            wg_quick_validate_peers
            ;;
        up)
            info

            if [ "$(id -u)" != 0 ]
            then
                die "wg-quick must be run as root: user id $(id -u) != 0"
            fi

            wg_quick_generate_config_file > "${WGQ_CONFIG_FILE}"

            export WG_QUICK_USERSPACE_IMPLEMENTATION="${WGQ_USERSPACE}"
            export LOG_LEVEL="${WGQ_LOG_LEVEL}"

            info "wg-quick up ${WGQ_CONFIG_FILE}"
            wg-quick up "${WGQ_CONFIG_FILE}" 2>&${WT_LOG_DEBUG}

            cat "${WGQ_CONFIG_FILE}" >&${WT_LOG_TRACE}

            case "${OSTYPE}" in
                darwin*)
                    WG_INTERFACE="$(cat "/var/run/wireguard/${WGQ_INTERFACE}.name")"
                    ;;
                linux*)
                    WG_INTERFACE="${WGQ_INTERFACE}"
                    ;;
                *)
                    die "OS *${OSTYPE}* not supported"
            esac
            wg_interface init
            ;;
        down)
            info

            if [ "$(wg_interface status)" == "up" ]
            then
                info "wg-quick down ${WGQ_CONFIG_FILE}"
                wg-quick down "${WGQ_CONFIG_FILE}"
            fi

            if rm -f "${WGQ_CONFIG_FILE}"
            then
                info "*${WGQ_CONFIG_FILE}* was deleted"
            else
                error "*${WGQ_CONFIG_FILE}* delete error"
            fi
            ;;
        set)
            wg_interface "${action}" ${@}
            ;;
        get)
            local name="${1}" && shift
            case "${name}" in
                *)
                    wg_interface "${action}" "${name}" ${@}
            esac
            ;;
    esac
}

# wireproxy interface

function wireproxy_generate_config_file() {
    debug

    wg_quick_generate_config_file > "${WGQ_CONFIG_FILE}"

    cat "${WGQ_CONFIG_FILE}" >&${WT_LOG_TRACE}

    WGQ_USE_POSTUP_TO_SET_PRIVATE_KEY=false wg_quick_generate_config_file

    if [ "${WIREPROXY_SOCKS5_BIND}" != "disabled" ]
    then
        cat <<EOF

[Socks5]
BindAddress = ${WIREPROXY_SOCKS5_BIND}
EOF
    fi

    if [ "${WIREPROXY_HTTP_BIND}" != "disabled" ]
    then
        cat <<EOF

[http]
BindAddress = ${WIREPROXY_HTTP_BIND}
EOF
    fi

    for port in ${WIREPROXY_EXPOSE_PORT_LIST}
    do
        cat <<EOF

[TCPServerTunnel]
ListenPort = ${port}
Target = 127.0.0.1:${port}
EOF
    done

    for forward in ${WIREPROXY_FORWARD_PORT_LIST}
    do
        {
            echo "${forward/:/ }"
        } | {
            read local_port remote_endpoint
            cat <<EOF

[TCPClientTunnel]
BindAddress = 127.0.0.1:${local_port}
Target = ${remote_endpoint}
EOF
        }
    done
}


function wireproxy_compat() {
    local major minor patch

    IFS=. read major minor patch < <("${WIREPROXY_COMMAND}" --version | cut -f 3 -d " " | sed "s,^v,,")

    if [[ (${major} -gt ${1}) ||
          (${major} -eq ${1} && ${minor} -gt ${2}) ||
          (${major} -eq ${1} && ${minor} -eq ${2} && ${patch} -ge ${3}) ]]
    then
        return 0
    else
        return 1
    fi
}

function wireproxy_interface() {
    local action="${1}" && shift

    case "${action}" in
        protocol)
            echo "udp"
            ;;
        deps)
            echo "wg cat cut find grep rm sort tail touch"
            ;;
        init)
            info

            WIREPROXY_COMMAND="${WIREPROXY_COMMAND:-wireproxy}"
            WIREPROXY_PID_FILE="${WT_EPHEMERAL_PATH}/wireproxy.pid"
            WIREPROXY_RELOAD_FILE="${WT_EPHEMERAL_PATH}/wireproxy.reload"
            WIREPROXY_READY_FILE="${WT_EPHEMERAL_PATH}/wireproxy.ready"
            WIREPROXY_HTTP_BIND="${WIREPROXY_HTTP_BIND:-disabled}"
            WIREPROXY_SOCKS5_BIND="${WIREPROXY_SOCKS5_BIND:-127.0.0.1:1080}"
            WIREPROXY_HEALTH_BIND="${WIREPROXY_HEALTH_BIND:-127.0.0.1:9080}"
            WIREPROXY_PEER_STATUS_TIMEOUT="${WIREPROXY_PEER_STATUS_TIMEOUT:-90}" # 35 seconds
            WIREPROXY_HOST_STATUS_TIMEOUT="${WIREPROXY_HOST_STATUS_TIMEOUT:-120}" # 45 seconds
            WIREPROXY_HANDSHAKE_TIMEOUT="${WIREPROXY_HANDSHAKE_TIMEOUT:-135}" # 135 seconds
            WIREPROXY_EXPOSE_PORT_LIST="${WIREPROXY_EXPOSE_PORT_LIST:-}"
            WIREPROXY_FORWARD_PORT_LIST="${WIREPROXY_FORWARD_PORT_LIST:-}"

            if [ ! -f "${WIREPROXY_COMMAND}" ]
            then
                die "command in WIREPROXY_COMMAND not found *${WIREPROXY_COMMAND}*"
            fi

            if ! wireproxy_compat 1 0 9
            then
                WIREPROXY_HEALTH_BIND="disabled"
                error "health bind disabled, wireproxy not compatible with version 1.0.9"
            fi

            wg_quick_interface init
            ;;
        up)
            info

            wireproxy_interface start
            ;;
        down)
            info
            ;;
        start)
            info

            wireproxy_interface loop &
            ;;
        stop)
            info
            if [ -f "${WIREPROXY_PID_FILE}" ]
            then
                {
                    cat "${WIREPROXY_PID_FILE}"
                } | {
                    read pid
                    info "kill -TERM ${pid}"
                    rm -f "${WIREPROXY_READY_FILE}"
                    kill -TERM "${pid}" || true
                }
            fi
            ;;
        reload)
            local peer_id=""
            info

            if [ ! -f "${WIREPROXY_RELOAD_FILE}" ]
            then
                local reload_timeout="$(($(epoch) + 45))"
                local reload_status="success"

                touch "${WIREPROXY_RELOAD_FILE}"
                wireproxy_interface stop

                while [ ! -f "${WIREPROXY_READY_FILE}" ]
                do
                    if [[ "$(epoch)" -gt "${reload_timeout}" ]]
                    then
                        error "timeouted"
                        reload_status="failed"
                        break
                    fi
                    sleep 1
                done

                info "${reload_status}"
            fi
            ;;
        loop)
            info

            id_list="${config["host_wg_pub"]} ${config["peer_wg_pub_list"]}"
            id_list="${id_list// /\\n}"

            {
                while true
                do
                    local wireproxy_params=""

                    if nc -z ${WIREPROXY_HEALTH_BIND/:/ } 2>&${null}
                    then
                        error "health bind disabled, tcp ${WIREPROXY_HEALTH_BIND} address already in use"
                    elif [ "${WIREPROXY_HEALTH_BIND}" != "disabled" ]
                    then
                        wireproxy_params="-i ${WIREPROXY_HEALTH_BIND}"
                    fi

                    coproc WIREPROXY_PROC ("${WIREPROXY_COMMAND}" ${wireproxy_params} -c <(wireproxy_generate_config_file) 2>&1)
                    echo "${!}" > "${WIREPROXY_PID_FILE}"
                    rm -f "${WIREPROXY_RELOAD_FILE}"

                    cat <&${WIREPROXY_PROC[0]} || true
                    rm -f "${WIREPROXY_PID_FILE}"

                    sleep 5 # TODO evaluate if this sleep still needed

                    if [ ! -f "${WIREPROXY_RELOAD_FILE}" ]
                    then
                        break
                    fi

                    sleep 1
                done
            } | {
                while read line
                do
                    echo "${line}" | { grep "Received\|Receiving\|Sending\|Handshake did not complete after 5 seconds" || true; } \
                        | raw_log wireproxy trace 27

                    echo "${line}" | { grep -v "Received\|Receiving\|Sending\|Handshake did not complete after 5 seconds" || true; } \
                        | {
                        case "${line}" in
                            "DEBUG: "*|"ERROR: "*)
                                raw_log wireproxy from_line 27
                                ;;
                            *)
                                raw_log wireproxy from_line 20
                        esac
                    }

                    if ! grep "peer(" <<<"${line}" > /dev/null
                    then
                        case "${line}" in
                            "DEBUG"*"Interface state was Down, requested Up, now Up")
                                touch "${WIREPROXY_READY_FILE}"
                                info "ready"
                                ;;
                            "ERROR"*"address already in use")
                                wirething set host_port 0 &
                                ;;
                            "panic: listen tcp ${WIREPROXY_HEALTH_BIND}: bind: address already in use")
                                # TODO disable health bind if address already in use
                                ;;
                        esac
                        continue
                    else
                        local peer_regex="$(echo "${line}" | sed "s,.*peer(\(.*\)…\(.*\)) - .*,\1.*\2=,")"
                        local id="$(echo -e "${id_list}" | grep "${peer_regex}" || true)"

                        if [ "${id}" == "" ]
                        then
                            error "regex=${peer_regex:=''} id="${id:=''}" peer not found: ${line}"
                            continue
                        fi

                        case "${line}" in
                            *"Receiving keepalive packet")
                                epoch > "${WT_PEER_LAST_KEEPALIVE_PATH}/$(hash_id "${id}")"
                                ;;
                            *"Received handshake response")
                                epoch > "${WT_PEER_LAST_KEEPALIVE_PATH}/$(hash_id "${id}")"
                                ;;
                        esac
                    fi
                done
            }
            ;;
        set)
            local name="${1}" && shift
            case "${name}" in
                host_port)
                    local port="${1}" && shift
                    info "host_port ${port:-''}"

                    if ! grep -q "ListenPort = ${port}" < "${WGQ_CONFIG_FILE}"
                    then
                        wireproxy_interface reload
                    fi
                    ;;
                peer_endpoint)
                    local peer="${1}" && shift
                    local endpoint="${1}" && shift
                    info "peer_endpoint $(short "${peer}") ${endpoint:-''}"

                    if ! grep -q "Endpoint = ${endpoint}" < "${WGQ_CONFIG_FILE}"
                    then
                        wireproxy_interface reload
                    fi
                    ;;
            esac
            ;;
        get)
            local name="${1}" && shift
            case "${name}" in
                peer_status)
                    local peer="${1}" && shift

                    {
                        if [ ! -f "${WT_PEER_LAST_KEEPALIVE_PATH}/$(hash_id "${peer}")" ]
                        then
                            echo "0" > "${WT_PEER_LAST_KEEPALIVE_PATH}/$(hash_id "${peer}")"
                        fi

                        cat "${WT_PEER_LAST_KEEPALIVE_PATH}/$(hash_id "${peer}")"
                    } | {
                        read last_keepalive

                        local keepalive_delta="$(($(epoch) - ${last_keepalive}))"

                        local result

                        if [[ ${keepalive_delta} -lt ${WIREPROXY_PEER_STATUS_TIMEOUT} ]]
                        then
                            result="online"
                        else
                            result="offline"
                        fi

                        debug "peer_status ${result} last_keepalive=${last_keepalive} keepalive_delta=${keepalive_delta} timeout=${WIREPROXY_PEER_STATUS_TIMEOUT}"

                        echo "${result}"
                    }
                    ;;
                host_status)
                    {
                        find "${WT_PEER_LAST_KEEPALIVE_PATH}" -type f
                    } | {
                        echo "0"
                        while read peer_keepalive_file
                        do
                            cat "${peer_keepalive_file}"
                        done
                    } | sort -n | tail -n 1 | {
                        read last_keepalive

                        local keepalive_delta="$(($(epoch) - ${last_keepalive}))"

                        debug "host_status last_keepalive=${last_keepalive} keepalive_delta=${keepalive_delta} timeout=${WIREPROXY_HOST_STATUS_TIMEOUT}"
                        local result

                        if [[ ${keepalive_delta} -lt ${WIREPROXY_HOST_STATUS_TIMEOUT} ]]
                        then
                            result="online"
                        else
                            result="offline"
                        fi

                        debug "host_status ${result}"
                        echo "${result}"
                    }
                    ;;
                handshake_timeouted)
                    local peer="${1}" && shift

                    {
                        echo 0
                        cat "${WT_PEER_LAST_KEEPALIVE_PATH}/"* || true
                    }  | sort -n | tail -n 1 | {
                        read last_keepalive

                        local keepalive_delta="$(($(epoch) - ${last_keepalive}))"

                        debug "last_keepalive=${last_keepalive} keepalive_delta=${keepalive_delta} timeout=${WIREPROXY_HANDSHAKE_TIMEOUT}"
                        local result

                        if [[ ${keepalive_delta} -lt ${WIREPROXY_HANDSHAKE_TIMEOUT} ]]
                        then
                            result="false"
                        else
                            result="true"
                        fi

                        debug "handshake_timeout $(short "${peer}") ${result:-''}"
                        echo "${result}"
                    }
                    ;;
            esac
            ;;
    esac
}

# udphole punch

function udphole_punch() {
    local action="${1}" && shift

    case "${action}" in
        protocol)
            echo "udp"
            ;;
        deps)
            echo "nc"
            udp deps
            ;;
        init)
            info
            UDPHOLE_HOSTNAME="${UDPHOLE_HOSTNAME:-udphole.wirething.org}" # udphole.wirething.org is a dns cname poiting to hdphole.fly.dev
            UDPHOLE_PORT="${UDPHOLE_PORT:-6094}"
            UDPHOLE_READ_TIMEOUT="${UDPHOLE_READ_TIMEOUT:-10}" # 10 seconds
            ;;
        status)
            local host_port="${1}" && shift
            local host_endpoint="${1}" && shift

            debug "local *${host_port}* *${host_endpoint}*"

            local result="offline"

            {
                echo "" | nc -w 1 -p "${host_port}" -u "${UDPHOLE_HOSTNAME}" "${UDPHOLE_PORT}" \
                    || echo ""
            } | {
                read endpoint
                debug "udphole *${host_port}* *${endpoint}*"

                if [[ "${host_endpoint}" == "${endpoint}" ]]
                then
                    result="online"
                fi

                info "${result:-''}"
                echo "${result}"
            }
            ;;
        open)
            debug

            if ! udp open "${UDPHOLE_HOSTNAME}" "${UDPHOLE_PORT}"
            then
                return 1
            fi

            if ! udp writeline ""
            then
                return 1
            fi
            ;;
        get)
            local name="${1}" && shift
            case "${name}" in
                port)
                    {
                        udp port ${UDPHOLE_HOSTNAME} ${UDPHOLE_PORT} ${PUNCH_PID}
                    } | {
                        read -t "${UDPHOLE_READ_TIMEOUT}" port
                        if [[ ${?} -lt 128 ]]
                        then
                            info "port ${port:-''}"
                            echo "${port}"
                        else
                            error "port timed out"
                            echo ""
                        fi
                    }
                    ;;
                endpoint)
                    {
                        udp readline
                    } | {
                        read -t "${UDPHOLE_READ_TIMEOUT}" endpoint
                        if [[ ${?} -lt 128 ]]
                        then
                            info "endpoint ${endpoint:-''}"
                            echo "${endpoint}"
                        else
                            error "endpoint timed out"
                            echo ""
                        fi
                    }
                    ;;
            esac
            ;;
        close)
            debug
            udp close
            ;;
    esac
}

# stun punch

function stun_punch() {
    local action="${1}" && shift

    case "${action}" in
        protocol)
            echo "udp"
            ;;
        deps)
            echo "stunclient"
            ;;
        init)
            info
            STUN_HOSTNAME="${STUN_HOSTNAME:-stunserver.stunprotocol.org}" # Stun service hosting the Stuntman
            STUN_PORT="${STUN_PORT:-3478}"

            STUN_PROTOCOL="udp"
            STUN_FAMILY="4"
            ;;
        status)
            local host_port="${1}" && shift
            local host_endpoint="${1}" && shift

            debug "local *${host_port}* *${host_endpoint}*"

            local result="offline"

            if stun_punch open "${host_port}"
            then
                read port < <(stun_punch get port)
                read endpoint < <(stun_punch get endpoint)

                debug "stun *${port}* *${endpoint}*"

                if [[ "${host_port}" == "${port}" && "${host_endpoint}" == "${endpoint}" ]]
                then
                    result="online"
                fi

                stun_punch close
            else
                debug "stun ** **"
            fi

            info "${result:-''}"
            echo "${result}"
            ;;
        open)
            debug "${STUN_HOSTNAME}" "${STUN_PORT}"
            local host_port="${1:-}" && shift

            if [ "${host_port}" == "" ]
            then
                local_port=""
            else
                local_port="--localport ${host_port}"
            fi

            coproc STUN_UDP_PROC (cat -u)

            stunclient "${STUN_HOSTNAME}" "${STUN_PORT}" ${local_port} \
                --protocol "${STUN_PROTOCOL}" --family "${STUN_FAMILY}" \
                2>&1 1>&${STUN_UDP_PROC[1]}

            exec {STUN_UDP_PROC[1]}>&-

            readarray -u "${STUN_UDP_PROC[0]}" -t stun_buffer

            for line in "${stun_buffer[@]}"
            do
                echo "${line}" | raw_log stunclient debug

                case "${line}" in
                    "Binding test: success")
                        ;;
                    "Local address: "*)
                        STUN_LOCAL_PORT="${line/*:/}"
                        ;;
                    "Mapped address: "*)
                        STUN_REMOTE_ENDPOINT="${line/*: /}"
                        ;;
                    *)
                        error "${line}"
                        return 1
                esac
            done
            ;;
        get)
            local name="${1}" && shift
            case "${name}" in
                port)
                    info "port ${STUN_LOCAL_PORT:-''}"
                    echo "${STUN_LOCAL_PORT}"
                    ;;
                endpoint)
                    info "endpoint ${STUN_REMOTE_ENDPOINT:-''}"
                    echo "${STUN_REMOTE_ENDPOINT}"
                    ;;
            esac
            ;;
        close)
            debug
            unset STUN_LOCAL_PORT
            unset STUN_REMOTE_ENDPOINT
            ;;
    esac
}

# ntfy pubsub

function ntfy_pubsub() {
    local action="${1}" && shift

    case "${action}" in
        deps)
            echo "curl sleep hexdump"
            ;;
        init)
            info
            NTFY_URL="${NTFY_URL:-https://ntfy.sh}"
            NTFY_CURL_OPTIONS="${NTFY_CURL_OPTIONS:--sS --no-buffer --location}"
            NTFY_PUBLISH_TIMEOUT="${NTFY_PUBLISH_TIMEOUT:-25}" # 25 seconds
            NTFY_POLL_TIMEOUT="${NTFY_POLL_TIMEOUT:-5}" # 5 seconds
            NTFY_SUBSCRIBE_TIMEOUT="${NTFY_SUBSCRIBE_TIMEOUT:-720}" # 12 minutes
            NTFY_SUBSCRIBE_PAUSE_AFTER_ERROR="${NTFY_SUBSCRIBE_PAUSE_AFTER_ERROR:-${WT_PAUSE_AFTER_ERROR}}" # ${WT_PAUSE_AFTER_ERROR} seconds
            ;;
        status)
            debug "curl -sS --head ${NTFY_URL}"

            local result

            if curl -sS --head "${NTFY_URL}" 2>&${WT_LOG_DEBUG} >&${WT_LOG_DEBUG}
            then
                result="online"
            else
                result="offline"
            fi

            info "${result:-''}"
            echo "${result}"
            ;;
        publish)
            local topic="${1}" && shift
            local request="${1}" && shift
            info "$(short "${topic}") request: $(short "${request}")"

            {
                curl ${NTFY_CURL_OPTIONS} --max-time "${NTFY_PUBLISH_TIMEOUT}" --stderr - \
                    "${NTFY_URL}/${topic}" -d "${request}" \
                    || true
            } | {
                while read publish_response
                do
                    echo "${publish_response}" | hexdump -C | raw_trace

                    case "${publish_response}" in
                        "{"*"event"*"message"*)
                            ;;
                        *)
                            error "$(short "${topic}") response: ${publish_response:-''}"
                    esac
                done
            }
            ;;
        poll)
            local topic="${1}" && shift
            local since="${1}" && shift

            {
                curl ${NTFY_CURL_OPTIONS} --max-time "${NTFY_POLL_TIMEOUT}" --stderr - \
                    "${NTFY_URL}/${topic}/raw?poll=1&since=${since}" \
                    || true
            } | tail -n 1 | {
                read poll_response || true
                echo "${poll_response}" | hexdump -C | raw_trace

                case "${poll_response}" in
                    "curl"*)
                        error "$(short "${topic}") ${since} response: ${poll_response}"
                        echo "error"
                        ;;
                    "{"*"error"*)
                        error "$(short "${topic}") ${since} response: ${poll_response}"
                        echo "error"
                        ;;
                    "triggered")
                        echo ""
                        ;;
                    *)
                        debug "$(short "${topic}") ${since} response: $(short "${poll_response:-''}")"
                        echo "${poll_response}"
                esac
            }
            ;;
        subscribe)
            local topic="${1}" && shift
            debug "$(short "${topic}") starting"

            {
                curl ${NTFY_CURL_OPTIONS} --max-time "${NTFY_SUBSCRIBE_TIMEOUT}" --stderr - \
                    "${NTFY_URL}/${topic}/raw" \
                    || true
            } | {
                while read subscribe_response
                do
                    echo "${subscribe_response}" | hexdump -C | raw_trace

                    case "${subscribe_response}" in
                        "")
                            ;;
                        "curl"*"timed out"*)
                            debug "$(short "${topic}") response: ${subscribe_response}"
                            ;;
                        "curl"*)
                            error "$(short "${topic}") response: ${subscribe_response}"
                            sleep "${NTFY_SUBSCRIBE_PAUSE_AFTER_ERROR}"
                            ;;
                        "{"*"error"*)
                            error "$(short "${topic}") response: ${subscribe_response}"
                            sleep "${NTFY_SUBSCRIBE_PAUSE_AFTER_ERROR}"
                            ;;
                        *)
                            info "$(short "${topic}") response: $(short "${subscribe_response:-''}")"
                            echo "${subscribe_response}"
                    esac
                done
            }
            ;;
    esac
}

# gpg ephemeral encryption

function gpg_ephemeral_encryption() {
    local action="${1}" && shift

    case "${action}" in
        deps)
            echo "gpg mkdir grep cut sed gpgconf rm base64"
            ;;
        init)
            info

            export GNUPGHOME="${WT_EPHEMERAL_PATH}/gpg"

            GPG_FILE_LIST="${GPG_FILE_LIST:?Variable not set}"
            GPG_DOMAIN_NAME="${GPG_DOMAIN_NAME:-wirething.gpg}"
            GPG_OPTIONS="${GPG_OPTIONS:---disable-dirmngr --no-auto-key-locate --batch --no}"
            GPG_AGENT_CONF="${GPG_AGENT_CONF:-disable-scdaemon\nextra-socket /dev/null\nbrowser-socket /dev/null\n}" # Disabling scdaemon (smart card daemon) make gpg do not try to use your Yubikey

            for gpg_file in ${GPG_FILE_LIST}
            do
                if [ ! -f "${WT_CONFIG_PATH}/${gpg_file}" ]
                then
                    die "file in GPG_FILE_LIST not found *${WT_CONFIG_PATH}/${gpg_file}*"
                fi
            done
            ;;
        up)
            info

            mkdir -p "${GNUPGHOME}"

            echo -ne "${GPG_AGENT_CONF}" > "${GNUPGHOME}/gpg-agent.conf"

            for gpg_file in ${GPG_FILE_LIST}
            do
                gpg ${GPG_OPTIONS} --import "${WT_CONFIG_PATH}/${gpg_file}" 2>&${WT_LOG_DEBUG}
                gpg ${GPG_OPTIONS} --show-keys --with-colons "${WT_CONFIG_PATH}/${gpg_file}" 2>&${WT_LOG_DEBUG} \
                    | grep "fpr" | cut -f "10-" -d ":" | sed "s,:,:6:," \
                    | gpg ${GPG_OPTIONS} --import-ownertrust 2>&${WT_LOG_DEBUG}
            done
            ;;
        down)
            info
            gpgconf --kill gpg-agent
            if rm -rf "${GNUPGHOME}"
            then
                info "*${GNUPGHOME}* was deleted"
            else
                error "*${GNUPGHOME}* delete error"
            fi
            ;;
        encrypt)
            debug
            local data="${1}" && shift
            local id_list="${@}" && shift

            local recipients

            printf -v recipients " --hidden-recipient %s@${GPG_DOMAIN_NAME}" ${id_list}

            recipients+=" --hidden-recipient ${config["host_gpg_keyname"]}"

            {
                echo "${data}"
            } | {
                gpg --encrypt ${GPG_OPTIONS} ${recipients} --sign --armor \
                        2>&${WT_LOG_DEBUG}
            } | {
                base64
            }
            ;;
        decrypt)
            debug
            local data="${1}" && shift

            {
                echo "${data}"
            } | {
                base64 -d
            } | {
                capture start

                gpg --decrypt ${GPG_OPTIONS} \
                    --local-user "${config["host_gpg_keyname"]}" \
                    2>&${capture[1]} \
                    || error "gpg returns ${?}"

                capture stop

                readarray -u "${capture[0]}" gpg_buffer

                if grep -iq "Good signature" <<<"${gpg_buffer[*]}"
                then
                    (IFS=''; echo -en "${gpg_buffer[*]}";) | raw_log gpg debug 5
                    return 0
                else
                    (IFS=''; echo -en "${gpg_buffer[*]}";) | raw_log gpg error 5
                    error "gpg 'Good signature' not found"
                    return 1
                fi
            }
            ;;
    esac
}

# totp topic

function totp_interval() {
    {
        cat <<<"$(($(epoch) / ${TOTP_PERIOD}))"
    } | {
        # int2hex
        read int
        printf "%016X\n" "${int}"
    } | {
        # hex2bin
        read hex
        echo -ne "$(sed "s,..,\\\x&,g" <<<"${hex}")"
    }
}

function totp_secret() {
    {
        case "${1}" in
            publish)
                base64 -d <<<"${config["host_totp_id"]}"
                base64 -d <<<"${peer_id}"
                ;;
            subscribe)
                base64 -d <<<"${peer_id}"
                base64 -d <<<"${config["host_totp_id"]}"
                ;;
            *)
                die "invalid action *${1}*, options: publish, subscribe"
                ;;
        esac
    } | openssl sha256 -binary
}

function totp_hmac_digest_python_src() {
    cat <<EOF
import sys, hmac, hashlib

with open(sys.argv[1], mode="rb") as key:
    h = hmac.new(key.read(), sys.stdin.buffer.read(), hashlib.$(to_lower "${TOTP_ALGORITHM}"))
    print(h.hexdigest())
EOF
}

function totp_hmac_digest_python() {
    python3 -c "$(totp_hmac_digest_python_src)" "${1}"
}

function totp_hmac_digest_openssl() {
    openssl dgst -"${TOTP_ALGORITHM}" -hmac "$(cat "${1}")" \
        | sed "s,.* ,,"
}


function totp_digest() {
    totp_interval | "totp_hmac_digest_${TOTP_HMAC}" <(totp_secret "${1}")
}

function totp_token() {
    read digest
    # Read the last 4 bits and convert it into an unsigned integer.
    local start="$(( 0x${digest:(-1)} * 2))"
    # Read a 32-bit positive integer and take at most six rightmost digits.
    local token="$(( ((0x${digest:${start}:8}) & 0x7FFFFFFF) % $((10 ** ${TOTP_DIGITS})) ))"
    # Pad the token number with leading zeros if needed.
    printf "%0${TOTP_DIGITS}d\n" "${token}"
}

function totp_topic() {
    local action="${1}" && shift

    case "${action}" in
        deps)
            echo "cat base64 openssl sed python3"
            ;;
        init)
            info
            TOTP_TOKEN="${TOTP_TOKEN:-cat}"
            TOTP_DIGITS="${TOTP_DIGITS:-6}"
            TOTP_PERIOD="${TOTP_PERIOD:-28800}" # 8 hours
            TOTP_ALGORITHM="${TOTP_ALGORITHM:-SHA256}"
            TOTP_HMAC="${TOTP_HMAC:-python}"
            ;;
        publish)
            local peer_id="${1}" && shift

            totp_digest "${action}" | "${TOTP_TOKEN}"
            ;;
        subscribe)
            local peer_id="${1}" && shift

            totp_digest "${action}" | "${TOTP_TOKEN}"
            ;;
    esac
}

# wirething hacks

WT_INTERFACE_TYPE="${WT_INTERFACE_TYPE:-wireproxy}"
WT_PUNCH_TYPE="${WT_PUNCH_TYPE:-stun}"
WT_PUBSUB_TYPE="${WT_PUBSUB_TYPE:-ntfy}"
WT_ENCRYPTION_TYPE="${WT_ENCRYPTION_TYPE:-gpg_ephemeral}"
WT_TOPIC_TYPE="${WT_TOPIC_TYPE:-totp}"

alias interface="${WT_INTERFACE_TYPE}_interface"
alias punch="${WT_PUNCH_TYPE}_punch"
alias pubsub="${WT_PUBSUB_TYPE}_pubsub"
alias encryption="${WT_ENCRYPTION_TYPE}_encryption"
alias topic="${WT_TOPIC_TYPE}_topic"

interface ""    || die "invalid WT_INTERFACE_TYPE *${WT_INTERFACE_TYPE}*, options: $(options interface)"
punch ""        || die "invalid WT_PUNCH_TYPE *${WT_PUNCH_TYPE}*, options: $(options punch)"
pubsub ""       || die "invalid WT_PUBSUB_TYPE *${WT_PUBSUB_TYPE}*, options: $(options pubsub)"
encryption ""   || die "invalid WT_ENCRYPTION_TYPE *${WT_ENCRYPTION_TYPE}*, options: $(options encryption)"
topic ""        || die "invalid WT_TOPIC_TYPE *${WT_TOPIC_TYPE}*, options: $(options topic)"

# wirething

function wirething() {
    local action="${1}" && shift

    case "${action}" in
        deps)
            echo "mkdir cat hexdump"
            ;;
        init)
            info
            WT_HOST_PORT_FILE="${WT_STATE_PATH}/host_port"
            WT_HOST_ENDPOINT_FILE="${WT_STATE_PATH}/host_endpoint"
            WT_PEER_ENDPOINT_PATH="${WT_STATE_PATH}/peer_endpoint"
            WT_PEER_LAST_KEEPALIVE_PATH="${WT_STATE_PATH}/peer_last_keepalive"
            ;;
        up)
            info
            punch_protocol="$(punch protocol)"
            interface_protocol="$(interface protocol)"

            if [ "${punch_protocol}" != "${interface_protocol}" ]
            then
                die "punch *${WT_PUNCH_TYPE}=${punch_protocol}* and interface *${WT_INTERFACE_TYPE}=${interface_protocol}* protocol differ"
            fi

            mkdir -p "${WT_PEER_ENDPOINT_PATH}"
            mkdir -p "${WT_PEER_LAST_KEEPALIVE_PATH}"

            if [ ! -f "${WT_HOST_PORT_FILE}" ]
            then
                echo "0" > "${WT_HOST_PORT_FILE}"
            fi

            if [ ! -f "${WT_HOST_ENDPOINT_FILE}" ]
            then
                echo "" > "${WT_HOST_ENDPOINT_FILE}"
            fi
            ;;
        up_host)
            info "${config["host_name"]}"

            local value="${WT_PID}"

            {
                encryption encrypt "${value}" 2>&${WT_LOG_DEBUG} \
                    || die "host could not encrypt data"
            } | {
                read encrypted_value

                encryption decrypt "${encrypted_value}" 2>&${WT_LOG_DEBUG} \
                    || die "host could not decrypt data"
            } | {
                read decrypted_value

                if [ "${value}" != "${decrypted_value}" ]
                then
                    die "host could not encrypt and decrypt data"
                else
                    info "host could encrypt and decrypt data"
                fi
            }

            {
                wirething get host_port
            } | {
                read host_port

                if [ "${host_port}" != "" ]
                then
                    interface set host_port "${host_port}"
                else
                    info "host_port is '${host_port:-''}'"
                fi
            }

            {
                wirething get host_endpoint
            } | {
                read host_endpoint

                info "host_endpoint is ${host_endpoint:-''}"
            }
            ;;
        up_peer)
            local peer_id="${1}" && shift
            info "$(short "${peer_id}")"

            local value="${WT_PID}"

            {
                encryption encrypt "${value}" "${peer_id}" 2>&${WT_LOG_DEBUG} \
                    || die "peer could not encrypt data"
            } | {
                read encrypted_value

                encryption decrypt "${encrypted_value}" 2>&${WT_LOG_DEBUG} \
                    || die "host could not decrypt peer data"
            } | {
                read decrypted_value

                if [ "${value}" != "${decrypted_value}" ]
                then
                    die "host could not encrypt and decrypt peer data"
                else
                    info "host could encrypt and decrypt peer data"
                fi
            }

            {
                wirething get peer_endpoint "${peer_id}"
            } | {
                read peer_endpoint

                if [ "${peer_endpoint}" != "" ]
                then
                    interface set peer_endpoint "${peer_id}" "${peer_endpoint}"
                else
                    info "peer_endpoint is ${peer_endpoint:-''}"
                fi
            }
            ;;
        set)
            local name="${1}" && shift
            case "${name}" in
                host_port)
                    local port="${1}" && shift
                    info "host_port ${port}"
                    echo "${port}" > "${WT_HOST_PORT_FILE}"

                    interface set host_port "${port}"
                    ;;
                host_endpoint)
                    local endpoint="${1}" && shift
                    info "host_endpoint ${endpoint}"
                    echo "${endpoint}" > "${WT_HOST_ENDPOINT_FILE}"
                    ;;
                peer_endpoint)
                    local peer_id="${1}" && shift
                    local endpoint="${1}" && shift
                    info "peer_endpoint $(short "${peer_id}") ${endpoint}"
                    echo "${endpoint}" > "${WT_PEER_ENDPOINT_PATH}/$(hash_id "${peer_id}")"

                    interface set peer_endpoint "${peer_id}" "${new_peer_endpoint}"
                    ;;
            esac
            ;;
        get)
            local name="${1}" && shift
            case "${name}" in
                host_port)
                    local port="$(cat "${WT_HOST_PORT_FILE}" 2>&${WT_LOG_DEBUG})"
                    debug "host_port ${port:-''}"
                    echo "${port}"
                    ;;
                host_endpoint)
                    local endpoint="$(cat "${WT_HOST_ENDPOINT_FILE}" 2>&${WT_LOG_DEBUG} || echo)"
                    debug "host_endpoint ${endpoint:-''}"
                    echo "${endpoint}"
                    ;;
                peer_endpoint)
                    local peer_id="${1}" && shift
                    local endpoint="$(cat "${WT_PEER_ENDPOINT_PATH}/$(hash_id "${peer_id}")" 2>&${WT_LOG_DEBUG} || echo)"
                    debug "peer_endpoint $(short "${peer_id}") ${endpoint:-''}"
                    echo "${endpoint}"
                    ;;
            esac
            ;;
        punch_host_endpoint)
            debug

            if punch open
            then
                {
                    punch get port
                    punch get endpoint
                } | {
                    read host_port
                    read host_endpoint

                    if [[ "${host_port}" != "" && "${host_endpoint}" != "" ]]
                    then
                        wirething set host_port "${host_port}"
                        wirething set host_endpoint "${host_endpoint}"
                    else
                        error "host_port='${host_port}' or host_endpoint='${host_endpoint}' are empty"
                        punch close
                        return 1
                    fi
                }
                punch close
            else
                return 1
            fi
            ;;
        broadcast_host_endpoint)
            debug

            for _peer_id in ${config["peer_id_list"]}
            do
                wirething publish_host_endpoint "${_peer_id}"
            done
            #for peer_name in ${config["peer_name_list"]}
            #do
            #done
            ;;
        publish_host_endpoint)
            debug
            local peer_id="${1}" && shift

            {
                wirething get host_endpoint
            } | {
                read host_endpoint
                echo "${host_endpoint}" | hexdump -C | raw_trace

                if [ "${host_endpoint}" != "" ]
                then
                    info "${host_endpoint}"

                    {
                        topic publish "${peer_id}"
                    } | {
                        read topic
                        {
                            encryption encrypt "${host_endpoint}" "${peer_id}"
                        } | {
                            read encrypted_host_endpoint

                            if [ "${encrypted_host_endpoint}" != "" ]
                            then
                                pubsub publish "${topic}" "${encrypted_host_endpoint}"
                            else
                                error "empty encrypted_host_endpoint"
                            fi
                        }
                    }
                fi
            }
            ;;
        poll_encrypted_host_endpoint)
            debug
            local peer_id="${1}" && shift
            local since="${1}" && shift

            {
                topic publish "${peer_id}"
            } | {
                read topic
                pubsub poll "${topic}" "${since}"
            }
            ;;
        poll_encrypted_peer_endpoint)
            debug
            local peer_id="${1}" && shift
            local since="${1}" && shift

            {
                topic subscribe "${peer_id}"
            } | {
                read topic
                pubsub poll "${topic}" "${since}"
            }
            ;;
        on_new_peer_endpoint)
            debug
            local peer_id="${1}" && shift

            while read new_peer_endpoint
            do
                info "${new_peer_endpoint}"

                local current_peer_endpoint="$(wirething get peer_endpoint "${peer_id}")"

                if [[ "${new_peer_endpoint}" != "${current_peer_endpoint}" ]]
                then
                    wirething set peer_endpoint "${peer_id}" "${new_peer_endpoint}"
                fi
            done
            ;;
        ensure_host_endpoint_is_published)
            info
            local peer_id="${1}" && shift
            local since="all"

            {
                wirething poll_encrypted_host_endpoint "${peer_id}" "${since}"
            } | {
                read encrypted_host_endpoint

                case "${encrypted_host_endpoint}" in
                    "error")
                        return 1
                        ;;
                    *)
                        {
                            if [[ "${encrypted_host_endpoint}" != "" ]]
                            then
                                encryption decrypt "${encrypted_host_endpoint}"
                            else
                                echo ""
                            fi
                        } | {
                            read published_host_endpoint

                            debug "published_host_endpoint ${published_host_endpoint}"

                            echo "${published_host_endpoint}" | hexdump -C | raw_trace

                            {
                                wirething get host_endpoint
                            } | {
                                read host_endpoint

                                if [ "${published_host_endpoint}" != "${host_endpoint}" ]
                                then
                                    wirething publish_host_endpoint "${peer_id}"
                                fi
                            }
                        }
                esac
            }
            ;;
        fetch_peer_endpoint)
            debug
            local peer_id="${1}" && shift
            local since="${1}" && shift

            {
                wirething poll_encrypted_peer_endpoint "${peer_id}" "${since}"
            } | {
                read encrypted_peer_endpoint

                case "${encrypted_peer_endpoint}" in
                    "")
                        ;;
                    "error")
                        return 1
                        ;;
                    *)
                        {
                            encryption decrypt "${encrypted_peer_endpoint}"
                        } | {
                            read new_peer_endpoint

                            echo "${new_peer_endpoint}" | hexdump -C | raw_trace

                            if [ "${new_peer_endpoint}" != "" ]
                            then
                                echo "${new_peer_endpoint}"
                            fi
                        } | {
                            wirething on_new_peer_endpoint "${peer_id}"
                        }
                esac
            }
            ;;
    esac
}

# host status usecase

function host_status_usecase() {
    local action="${1}" && shift

    case "${action}" in
        deps)
            echo "sleep"
            ;;
        init)
            info
            WT_HOST_OFFLINE_ENABLED="${WT_HOST_OFFLINE_ENABLED:-true}"
            WT_HOST_OFFLINE_START_DELAY="${WT_HOST_OFFLINE_START_DELAY:-20}" # 20 seconds
            WT_HOST_OFFLINE_INTERVAL="${WT_HOST_OFFLINE_INTERVAL:-30}" # 30 seconds
            WT_HOST_OFFLINE_ENSURE_INTERVAL="${WT_HOST_OFFLINE_ENSURE_INTERVAL:-60}" # 1 minute
            WT_HOST_OFFLINE_PUNCH_PID_FILE="${WT_EPHEMERAL_PATH}/host_status_usecase.pid"
            ;;
        start)
            local log_id="${config["host_log_id"]}"
            local log_name="${config["host_log_name"]}"

            info "${config["host_name"]}"

            if [[ "${WT_HOST_OFFLINE_ENABLED}" == "true" ]]
            then
                info "enabled"
                host_status_usecase loop &
                echo "${!}" > "${WT_HOST_OFFLINE_PUNCH_PID_FILE}"
            else
                info "disabled"
            fi
            ;;
        online)
            info
            while [ "$(interface get host_status)" == "online" ]
            do
                debug "pause: ${WT_HOST_OFFLINE_INTERVAL} seconds"
                sleep "${WT_HOST_OFFLINE_INTERVAL}"
            done
            ;;
        offline)
            info

            local next_ensure="0"

            while [ "$(interface get host_status)" == "offline" ]
            do
                if [[ $(epoch) -gt ${next_ensure} ]]
                then
                    local status="online"

                    if [ "$(pubsub status)" == "offline" ]
                    then
                        info "pubsub status: offline"
                        status="offline"
                    else
                        read host_endpoint < <(wirething get host_endpoint)
                        read host_port < <(wirething get host_port)

                        wirething set host_port "0"

                        if [[ "${host_port}" != "0" && "$(punch status "${host_port}" "${host_endpoint}")" == "online" ]]
                        then
                            wirething set host_port "${host_port}"
                        else
                            info "punch status: offline"
                            status="offline"

                            if wirething punch_host_endpoint
                            then
                                wirething broadcast_host_endpoint &
                                status="online"
                            else
                                wirething set host_port "${host_port}"
                            fi
                        fi
                    fi

                    if [ "${status}" == "online" ]
                    then
                        for _peer_id in ${config["peer_id_list"]}
                        do
                            if ! wirething ensure_host_endpoint_is_published "${_peer_id}"
                            then
                                status="offline"
                            fi
                        done
                    fi

                    if [ "${status}" == "online" ]
                    then
                        next_ensure="$(($(epoch) + "${WT_HOST_OFFLINE_ENSURE_INTERVAL}"))"
                        info "next ensure_host_endpoint_is_published in $((${next_ensure} - $(epoch))) seconds"
                    fi

                    if [ "${status}" == "offline" ]
                    then
                        info "pause after error: ${WT_PAUSE_AFTER_ERROR} seconds"
                        sleep "${WT_PAUSE_AFTER_ERROR}"
                        continue
                    fi
                fi

                debug "pause: ${WT_HOST_OFFLINE_INTERVAL} seconds"
                sleep "${WT_HOST_OFFLINE_INTERVAL}"
            done
            ;;
        loop)
            info "pause before start: ${WT_HOST_OFFLINE_START_DELAY} seconds"
            sleep "${WT_HOST_OFFLINE_START_DELAY}"

            PUNCH_PID="$(cat "${WT_HOST_OFFLINE_PUNCH_PID_FILE}")"

            while true
            do
                case "$(interface get host_status)" in
                    online)
                        host_status_usecase online
                        ;;
                    offline)
                        host_status_usecase offline
                        ;;
                    *)
                        error "invalid host status"
                esac

            done

            info "end"
            ;;
    esac
}

# peer

function peer_context() {
    local action="${1}" && shift

    case "${action}" in
        set)
            local peer_name="${1}" && shift

            peer_id="${config["peer_id_${peer_name}"]}"
            log_id="${config["peer_log_id_${peer_name}"]}"
            log_name="${config["peer_log_name_${peer_name}"]}"
            ;;
        unset)
            unset peer_id
            log_id=""
            log_name=""
            ;;
    esac
}

function peer_state() {
    local action="${1}" && shift

    case "${action}" in
        init)
            info

            declare -g -A _peer_state

            declare -g -A _peer_event_transitions=(
                ["peer_start_start"]="on_peer_start"
                ["peer_wait_wait"]=""
                ["peer_wait_offline"]="on_peer_offline"
                ["peer_wait_online"]=""
                ["peer_online_online"]=""
                ["peer_online_offline"]="on_peer_offline"
                ["peer_offline_offline"]=""
                ["peer_offline_online"]="on_peer_online"
                ["peer_stop_stop"]="on_peer_stop"
            )

            declare -g -A _peer_status_transitions=(
                ["peer_start_start"]=""
                ["peer_wait_wait"]=""
                ["peer_wait_offline"]="offline"
                ["peer_wait_online"]="online"
                ["peer_online_online"]=""
                ["peer_online_offline"]="offline"
                ["peer_offline_offline"]=""
                ["peer_offline_online"]="online"
                ["peer_stop_stop"]=""
            )
            ;;
        start_peer)
            local peer_name="${1}" && shift
            info "${peer_name}"

            _peer_state["current_status_${peer_name}"]="start"
            _peer_state["polled_status_${peer_name}"]="start"

            peer_state transition "${peer_name}"

            _peer_state["current_status_${peer_name}"]="wait"
            _peer_state["polled_status_${peer_name}"]="wait"
            ;;
        stop_peer)
            local peer_name="${1}" && shift
            info "${peer_name}"

            _peer_state["current_status_${peer_name}"]="stop"
            _peer_state["polled_status_${peer_name}"]="stop"

            peer_state transition "${peer_name}"
            ;;
        transition)
            local peer_name="${1}" && shift

            local current_status="${_peer_state["current_status_${peer_name}"]}"
            local polled_status="${_peer_state["polled_status_${peer_name}"]}"
            local transition="peer_${current_status}_${polled_status}"

            local new_event="${_peer_event_transitions["${transition}"]}"

            peer on_event "${peer_name}" "${new_event}"

            local new_status="${_peer_status_transitions["${transition}"]}"

            case "${new_status}" in
                wait|stop|offline|online)
                    info "${peer_name} status from ${current_status} to ${new_status}"
                    _peer_state["current_status_${peer_name}"]="${new_status}"
                    ;;
            esac
            ;;
        set_polled_status)
            local peer_name="${1}" && shift
            local status="${1}" && shift

            _peer_state["polled_status_${peer_name}"]="${status}"
            ;;
    esac
}

function peer_task() {
    local action="${1}" && shift

    case "${action}" in
        interface_get_peer_status)
            local peer_name="${1}" && shift

            peer_context set "${peer_name}"

            interface get peer_status "${peer_id}"

            peer_context unset
            ;;
        fetch_peer_endpoint_since_all)
            local peer_name="${1}" && shift

            peer_context set "${peer_name}"

            info "${peer_name}"
            wirething fetch_peer_endpoint "${peer_id}" "all" || true

            peer_context unset
            ;;
        fetch_peer_endpoint)
            local peer_name="${1}" && shift

            peer_context set "${peer_name}"

            info "${peer_name}"
            wirething fetch_peer_endpoint "${peer_id}" "${WT_PEER_OFFLINE_FETCH_SINCE}s" || true

            peer_context unset
            ;;
        ensure_host_endpoint_is_published)
            local peer_name="${1}" && shift

            peer_context set "${peer_name}"

            info "${peer_name}"
            wirething ensure_host_endpoint_is_published "${peer_id}" || true

            peer_context unset
            ;;
        register)
            local task="${1}" && shift
            local peer_name="${1}" && shift

            case "${task}" in
                peer_poll_endpoint)
                    tasks register name "peer_poll_endpoint_${peer_name}" \
                        frequency "${WT_PEER_OFFLINE_FETCH_INTERVAL}" \
                        start now \
                        stop never \
                        task "peer_task fetch_peer_endpoint ${peer_name}"
                    ;;
                peer_ensure_host_endpoint)
                    tasks register name "peer_ensure_host_endpoint_${peer_name}" \
                        frequency "${WT_PEER_OFFLINE_ENSURE_INTERVAL}" \
                        start now \
                        stop never \
                        task "peer_task ensure_host_endpoint_is_published ${peer_name}"
                    ;;
            esac
            ;;
        unregister)
            local task="${1}" && shift
            local peer_name="${1}" && shift

            case "${task}" in
                peer_poll_endpoint)
                    tasks unregister name "peer_poll_endpoint_${peer_name}"
                    ;;
                peer_ensure_host_endpoint)
                    tasks unregister name "peer_ensure_host_endpoint_${peer_name}"
                    ;;
            esac
    esac
}

function peer() {
    local action="${1}" && shift

    case "${action}" in
        deps)
            echo "sleep"
            ;;
        init)
            info
            WT_PEER_OFFLINE_START_DELAY="${WT_PEER_OFFLINE_START_DELAY:-10}" # 10 seconds
            WT_PEER_OFFLINE_FETCH_SINCE="${WT_PEER_OFFLINE_FETCH_SINCE:-60}" # 1 minute
            WT_PEER_OFFLINE_FETCH_INTERVAL="${WT_PEER_OFFLINE_FETCH_INTERVAL:-45}" # 45 seconds
            WT_PEER_OFFLINE_ENSURE_INTERVAL="${WT_PEER_OFFLINE_ENSURE_INTERVAL:-900}" # 15 minutes

            peer_context init
            peer_state init
            ;;
        start)
            info
            local peer_name

            for peer_name in ${config["peer_name_list"]}
            do
                peer_state start_peer "${peer_name}"
            done
            ;;
        stop)
            info
            local peer_name

            for peer_name in ${config["peer_name_list"]}
            do
                peer_state stop_peer "${peer_name}"
            done
            ;;
        poll_status)
            local peer_name="${1}" && shift
            local status="$(peer_task interface_get_peer_status "${peer_name}")"

            peer_context set "${peer_name}"

            debug "${peer_name} ${status}"

            peer_state set_polled_status "${peer_name}" "${status}"

            peer_context unset
            ;;
        on_event)
            local peer_name="${1}" && shift
            local new_event="${1}" && shift

            case "${new_event}" in
                on_peer_start)
                    info "${new_event}"

                    tasks register name "peer_poll_status_${peer_name}" \
                        frequency "${WT_PEER_OFFLINE_FETCH_INTERVAL}" \
                        start "+${WT_PEER_OFFLINE_START_DELAY}" \
                        stop never \
                        task "peer poll_status ${peer_name}"
                    ;;
                on_peer_stop)
                    info "${new_event}"

                    tasks unregister name "peer_poll_status_${peer_name}"
                    ;;
                on_peer_offline)
                    info "${new_event}"

                    peer_task fetch_peer_endpoint_since_all "${peer_name}"

                    peer_task register "peer_poll_endpoint" "${peer_name}"
                    peer_task register "peer_ensure_host_endpoint" "${peer_name}"
                    ;;
                on_peer_online)
                    info "${new_event}"

                    peer_task unregister "peer_poll_endpoint" "${peer_name}"
                    peer_task unregister "peer_ensure_host_endpoint" "${peer_name}"
                    ;;
            esac
            ;;
        run)
            local peer_name

            for peer_name in ${config["peer_name_list"]}
            do
                peer_context set "${peer_name}"

                peer_state transition "${peer_name}"

                peer_context unset
            done
            ;;
    esac
}

# wirething main

wt_type_list=(
    interface
    punch
    pubsub
    encryption
    topic
)

wt_optional_list=(
    wg_interface
    wg_quick_interface
    udphole_punch
)

wt_others_list=(
    bash_compat
    utils
    udp
    wirething
    host_status_usecase
    peer
)

function wt_get_alias() {
    alias ${wt_type} | cut -f 2 -d "'"
}

function wt_type_for_each() {
    for wt_type in "${wt_type_list[@]}"
    do
        "$(wt_get_alias "${wt_type}")" "${1}"
    done
}

function wt_optional_for_each() {
    for wt_optional in "${wt_optional_list[@]}"
    do
        "${wt_optional}" "${1}"
    done
}

function wt_others_for_each() {
    for wt_other in "${wt_others_list[@]}"
    do
        "${wt_other}" "${1}"
    done
}

function wirething_main() {
    local action="${1}" && shift

    case "${action}" in
        deps)
            local option="${1}" && shift

            {
                echo "mkdir rm sed sort uniq wc"

                wt_type_for_each deps
                wt_others_for_each deps
                wt_optional_for_each deps
            } | sed "s, ,\n,g" | sort | uniq | {
                while read dep
                do
                    case "${option}" in
                        check)
                            if ! type -P "${dep}" > /dev/null
                            then
                                wirething_main deps list
                                die "check missing dependency: ${dep}"
                            fi
                            ;;
                        list)
                            printf "%-13s" "${dep}"
                            echo "$(readlink -f "$(type -P "${dep}")" || echo "not found")"
                            ;;
                        *)
                            die "invalid option *${option}*, options: check list"
                    esac
                done
            }
            ;;
        init)
            info

            set_pid
            WT_PID="${PID}"

            WT_CONFIG_PATH="${WT_CONFIG_PATH:-${PWD}}"
            WT_STATE_PATH="${WT_CONFIG_PATH}/state"

            if [ "$(id -u)" != 0 ]
            then
                WT_RUN_PATH="${WT_RUN_PATH:-${WT_CONFIG_PATH}/run}"
            else
                WT_RUN_PATH="${WT_RUN_PATH:-/var/run/wirething}"
            fi

            WT_EPHEMERAL_PATH="${WT_RUN_PATH}/${WT_PID}"
            WT_PAUSE_AFTER_ERROR="${WT_PAUSE_AFTER_ERROR:-30}" # 30 seconds

            info "WT_PID=${WT_PID}"

            wirething_main deps check

            config init
            tasks init

            wt_type_for_each init
            wt_others_for_each init
            ;;
        signal)
            info "${@}"

            local signal="${1:-}" && shift
            local result="${1:-}" && shift
            local lineno="${1:-}" && shift
            local funcname="${1:-}" && shift

            case "${signal}" in
                ERR)
                    error "signal=${signal} result=${result} lineno=${lineno} funcname=${funcname}"
                    ;;
                EXIT)
                    # Set trap to empty to run only once
                    trap "" ${signal}
                    info "pkill -term -g ${WT_PID}"
                    pkill -TERM -g "${WT_PID}" || true
                    wirething_main down
                    ;;
            esac
            return 0
            ;;
        trap)
            for signal in EXIT ERR SIGTERM
            do
                trap "wirething_main signal \"${signal}\" \"${?:-null}\" \"\${LINENO:-}\" \"\${FUNCNAME[0]:-}\"" "${signal}"
            done
            ;;
        up)
            info

            wirething_main trap

            mkdir -p "${WT_STATE_PATH}"
            mkdir -p "${WT_EPHEMERAL_PATH}"

            config up

            wt_type_for_each up
            wt_others_for_each up

            wirething up_host

            for _peer_id in ${config["peer_id_list"]}
            do
                wirething up_peer "${_peer_id}"
            done
            ;;
        down)
            wt_type_for_each down
            wt_others_for_each down

            info
            if rm -rf "${WT_EPHEMERAL_PATH}"
            then
                info "*${WT_EPHEMERAL_PATH}* was deleted"
            else
                error "*${WT_EPHEMERAL_PATH}* delete error"
            fi
            ;;
        start)
            info

            host_status_usecase start

            peer start
            ;;
        loop)
            info "start"

            while true
            do
                peer run
                tasks run
                sleep 5
            done

            info "end"
            ;;
        wait)
            info
            wait $(jobs -p) || true
            info "end"
            ;;
    esac
}

# main

function main() {
    wirething_main init
    wirething_main up
    wirething_main start
    wirething_main loop
    wirething_main wait
}

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
            local host_peer_file="${1:-${PWD}/${hostname}.peer}" && shift || true

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

# args

case "${1:-${WT_ACTION:-}}" in
    cli)
        shift || true
        cli init
        cli ${@}
        ;;
    deps)
        wirething_main deps list
        ;;
    test)
        ;;
    *)
        main
esac
