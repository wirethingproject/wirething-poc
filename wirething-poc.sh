#!/usr/bin/env bash

# basic

umask 077

export LC_ALL=C

# bash

## changelog:    https://github.com/bminor/bash/blob/master/NEWS
## bash changes: https://web.archive.org/web/20230401195427/https://wiki.bash-hackers.org/scripting/bashchanges
## ${EPOCHSECONDS} requires bash 5.0

if ! [[ (${BASH_VERSINFO[0]} -gt 5) ||
        (${BASH_VERSINFO[0]} -eq 5 && ${BASH_VERSINFO[1]} -ge 0) ]]
then
    local version="${BASH_VERSINFO[@]}"
    echo "bash ${version// /.}"
    echo "bash < 5.0 not supported"
    exit 1
fi

## set: http://redsymbol.net/articles/unofficial-bash-strict-mode/

set -o errexit  # -e Exit immediately if any command returns a non-zero status
set -o errtrace # -E Make ERR trap work with shell functions
set -o nounset  # -u Treat unset variables as an error
set -o pipefail # Return non-zero if any command in a pipeline fails

shopt -s expand_aliases  # Aliases are expanded on non interactive shell
shopt -s inherit_errexit # Command substitution inherits the value of the errexit option
shopt -s execfail        # Don't exit if exec cannot execute the file

# io

exec {null}<>/dev/null
exec {err}>&2

if [[ "${JOURNAL_STREAM:-}" != "" || "${SVDIR:-}" != "" ]]
then
    LOG_TIME="false"
else
    LOG_TIME="true"
fi

if [ "${LOG_TIME}" == "true" ]
then
    alias sys_log='printf "%(%FT%T%z)T ${BASHPID} %s\n" "${EPOCHSECONDS}"'
else
    alias sys_log='echo'
fi

# base

function os() {
    local die_action="${action:-}"
    local action="${1}" && shift

    case "${action}" in
        deps)
            echo "base64 ping pkill"
            ;;
        optional)
            case "${OSTYPE}" in
                darwin*)
                    echo "osascript"
                    ;;
                linux*)
                    if [ -v TERMUX_VERSION ]
                    then
                        echo "termux-notification"
                    fi
                    ;;
            esac
            ;;
        init)
            OS_PID="${BASHPID}"
            OS_LOCALE="C"

            alias die="os die"

            case "${OSTYPE}" in
                darwin*)
                    alias os_ping="ping -c 1 -t 5"
                    alias os_ping_quick="ping -c 1 -t 1"
                    alias os_base64='base64'

                    if type -a osascript >&${null} 2>&${null}
                    then
                        alias os_ui="os darwin ui"
                    else
                        alias os_ui=":"
                    fi
                    ;;
                linux*)
                    alias os_ping="ping -c 1 -W 5"
                    alias os_ping_quick="ping -c 1 -W 1"
                    alias os_base64='os linux base64'

                    case "${OSTYPE}" in
                        linux-android)
                            ANDROID_VERSION="$(getprop ro.build.version.release)"
                            ANDROID_SDK="$(getprop ro.build.version.sdk)"
                            ANDROID_MIN_SDK="$(getprop ro.build.version.min_supported_target_sdk)"

                            OS_LOCALE="UTF-8"

                            if [ -v TERMUX_VERSION ] &&
                                type -a termux-notification >&${null} 2>&${null}
                            then
                                alias os_ui="os termux ui"
                            else
                                alias os_ui=":"
                            fi
                            ;;
                        *)
                            alias os_ui=":"
                            ;;
                    esac
                    ;;
                *)
                    os die "OS *${OSTYPE}* not supported"
            esac
            ;;
        die)
            echo "ERROR [---------] ${FUNCNAME[1]:-} ${die_action:-} ${*}" >&${err}
            os terminate
            exit 1
            ;;
        terminate)
            pkill -TERM -g "${OS_PID}"
            ;;
        linux)
            local command="${1}" && shift

            case "${command}" in
                base64)
                    base64 -w 0 ${1:-}

                    if [ "${1:-}" == "" ]
                    then
                        echo ""
                    fi
                    ;;
            esac
            ;;
        termux)
            local command="${1}" && shift

            case "${command}" in
                ui)
                    local type="${1}" && shift
                    local title="${1}" && shift
                    local text="${1}" && shift

                    case "${type}" in
                        log)
                            termux-notification -t "${title}" -c "${text}"
                            ;;
                        status)
                            local group="${1}" && shift

                            termux-notification --group "${group}" -t "${title}" -c "${text}" \
                                 --id "${group}" --ongoing --alert-once
                            ;;
                    esac
                    ;;
            esac
            ;;
        darwin)
            local command="${1}" && shift

            case "${command}" in
                ui)
                    local type="${1}" && shift
                    local title="${1}" && shift
                    local text="${1}" && shift

                    case "${type}" in
                        log)
                            osascript -e "display notification \"${text}\" with title \"${title}\""
                            ;;
                        status)
                            local group="${1}" && shift

                            osascript -e "display notification \"${text}\" with title \"${title}\""
                            ;;
                    esac
                    ;;
            esac
            ;;
    esac
}

function sys() {
    local sig_action="${action:-}"
    local action="${1}" && shift

    case "${action}" in
        deps)
            echo "cat id mktemp mv pkill"
            ;;
        init)
            SYS_PID="${BASHPID}"
            sys start_sleep
            ;;
        start_sleep)
            exec {sleep_input_fd}< <(echo "${BASHPID}" && kill -STOP "${BASHPID}")
            read -u "${sleep_input_fd}" sleep_input_pid
            ;;
        stop_sleep)
            kill -CONT "${sleep_input_pid}" || true
            exec {sleep_input_fd}>&-
            unset -v sleep_input_fd
            unset -v sleep_input_pid
            ;;
        sleep)
            if { read -t "${1}" -u "${sleep_input_fd}" || test "${?}" -le 128; }
            then
                return 1
            else
                return 0
            fi
            ;;
        buffer_to_file)
            local file="${1}"
            buffer="$(mktemp -p "${_sys_tmp_path}")"
            cat -u > "${buffer}"
            mv -f "${buffer}" "${file}"
            ;;
        shutdown)
            sys terminate_from_group "${SYS_PID}"
            ;;
        terminate)
            local pid="${1}"
            kill -TERM "${pid}" 2>&${null}
            ;;
        terminate_from_group)
            local gpid="${1}"
            pkill -TERM -g "${gpid}" 2>&${null}
            ;;
        terminate_from_parent_pid)
            local ppid="${1}"
            pkill -TERM -P "${ppid}" 2>&${null}
            ;;
        is_running)
            if [ "${_sys_running}" == "true" ]
            then
                return 0
            else
                return 1
            fi
            ;;
        is_root)
            if [ "$(id -u)" == 0 ]
            then
                return 1
            else
                return 0
            fi
            ;;
        trap)
            trap "sys signal \"${1}\" \"\${LINENO:-}\" \"\${FUNCNAME[0]:-}\" \"\${?:-null}\"" "${1}"
            ;;
        set_error_path)
            _sys_error_path="${1}"
            ;;
        set_log_path)
            _sys_log_path="${1}"
            ;;
        set_tmp_path)
            _sys_tmp_path="${1}"
            ;;
        set_on_exit)
            _sys_on_exit="${@}"
            ;;
        start)
            if [[ ! -v _sys_error_path ]]
            then
                os die "'sys set_error_path' was not called"
            fi

            if [[ ! -v _sys_log_path ]]
            then
                os die "'log set_log_path' was not called"
            fi

            if [[ ! -v _sys_tmp_path ]]
            then
                os die "'sys set_tmp_path' was not called"
            fi

            if [[ ! -v _sys_on_exit ]]
            then
                os die "'sys set_on_exit' was not called"
            fi

            _sys_running="true"

            for _signal in EXIT ERR SIGTERM SIGINT SIGHUP SIGPIPE
            do
                sys trap "${_signal}"
            done
            ;;
        signal)
            trap "" SIGPIPE
            trap "" ERR

            local signal="${1}" && shift
            local lineno="${1:-''}    " && shift
            local funcname="${1:-funcname=''}" && shift
            local result="${1:-''}" && shift
            local action="${sig_action:-${action:-action=''}}"
            local was_running="${_sys_running}"
            local signal_str="${signal}    "

            case "${signal}" in
                SIGTERM|SIGHUP)
                    trap "" ${signal}
                    _sys_running="false"
                    ;;
                SIGINT)
                    trap "" ${signal}
                    _sys_running="false"

                    if [ -t 0 ]
                    then
                        echo "" >&0 2>&${null} || true
                    fi
                    ;;
            esac

            if ! sys signal_log >&${err} 2>&${null}
            then
                local err_file="${_sys_error_path}/$(date -I).log"

                sys signal_log >> "${err_file}"

                if [ -t 0 ]
                then
                    sys signal_stderr_msg "tty" >> "${err_file}"
                    exec {tty}>&0
                else
                    sys signal_stderr_msg "${err_file}" >> "${err_file}"
                    exec {tty}>> "${err_file}"
                fi

                exec {err}>&-
                exec {err}>&${tty}
            fi

            case "${signal}" in
                EXIT)
                    trap "" ${signal}
                    sys stop_sleep
                    ${_sys_on_exit}
                    ;;
            esac

            sys trap SIGPIPE
            sys trap ERR

            return 0
            ;;
        signal_log)
            local level="INFO "

            if [ "${signal}" == "ERR" ]
            then
                level="ERROR"
            fi

            printf "%(%FT%T%z)T %s\n" "${EPOCHSECONDS}" "${level} signal=${signal_str::7} was_running=${was_running/true/true } is_running=${_sys_running/true/true } lineno=${lineno::4} ${funcname} ${sig_action} result=${result}"
            ;;
        signal_stderr_msg)
            printf "%(%FT%T%z)T %s\n" "${EPOCHSECONDS}" "ERROR Error writing to stderr fd=${err}, redirecting stderr to ${1}"
            ;;
    esac
}

function log() {
    local log_action="${1}" && shift

    case "${log_action}" in
        deps)
            echo "timeout tee"
            ;;
        init)
            WT_LOG_LEVEL="${WT_LOG_LEVEL:-info}"

            log_prefix=""

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
                    os die "invalid WT_LOG_LEVEL *${WT_LOG_LEVEL}*, options: trace, debug, info, error"
            esac

            declare -g -A _fd_from_level=(
                ["trace"]="${WT_LOG_TRACE}"
                ["debug"]="${WT_LOG_DEBUG}"
                ["info"]="${WT_LOG_INFO}"
                ["error"]="${WT_LOG_ERROR}"
            )

            alias short="log short"
            alias short4="log short4"
            alias format_time="log format_time"

            alias trace="log trace"
            alias debug="log debug"
            alias info="log info"
            alias error="log error"

            alias custom_log="log custom_log"
            ;;
        short4)
            echo "${1::4}"
            ;;
        short)
            echo "${1::9}"
            ;;
        format_time)
            local seconds="${1}" && shift
            shift # var_name
            local var_name="${1}"

            local hours

            ((hours = seconds / 3600)) || true
            ((seconds %= 3600)) || true

            printf -v "${var_name}" "%.2u:%(%M:%S)T" "${hours}" "${seconds}"
            ;;
        trace)
            sys_log "TRACE ${log_prefix:-[---------]} ${FUNCNAME[1]:-} ${action:-} ${*}" >&${WT_LOG_DEBUG} || true
            ;;
        debug)
            sys_log "DEBUG ${log_prefix:-[---------]} ${FUNCNAME[1]:-} ${action:-} ${*}" >&${WT_LOG_DEBUG} || true
            ;;
        info)
            sys_log "INFO  ${log_prefix:-[---------]} ${FUNCNAME[1]:-} ${action:-} ${*}" >&${WT_LOG_INFO} || true
            ;;
        error)
            sys_log "ERROR ${log_prefix:-[---------]} ${FUNCNAME[1]:-} ${action:-} ${*}" >&${WT_LOG_ERROR} || true
            ;;
        custom_log)
            local line="${1}" && shift
            local app="${1}" && shift
            local level="${1}" && shift
            local start_index="${1:-0}"

            local level_name="${level/info/info }"

            sys_log "${level_name^^} [${app}] ${line:${start_index}}" >&${_fd_from_level[${level}]} || true
            ;;
        file)
            local name="${1}" && shift
            local period="86400" # 1 day

            set +o errexit  # +e Don't exit immediately if any command returns a non-zero status

            while true
            do
                log_date="$(date -u -I)"
                log_file="${_sys_log_path}/${name}-${log_date}.log"

                log_now="${EPOCHSECONDS}"
                log_timeout="$(( ((${log_now} / ${period} + 1) * ${period}) - ${log_now} + 10 ))"

                timeout "${log_timeout}s" tee -a "${log_file}"
                if [[ ${?} -ne 124 ]]
                then
                    break
                fi
            done
            ;;
    esac
}

os init
sys init
log init

# utils

function options() {
    set | grep "_${1} ()" | sed "s,_${1} (),," | tr -d "\n"
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

            unset -v UDP_SOCKET
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
            config["host_log_prefix"]="[$(short4 "${host_name}----")-$(short4 "${host_wg_pub}----")]"
            config["host_wg_pub"]="${host_wg_pub}"
            config["host_gpg_id"]="${host_wg_pub}@${gpg_domain_name}"
            config["host_totp_id"]="${host_wg_pub}"

            config["peer_name_list"]=""
            config["peer_wg_pub_list"]=""

            for _peer_wg_pub_file in ${peer_wg_pub_file_list}
            do
                if [ ! -f "${config_path}/${_peer_wg_pub_file}" ]
                then
                    die "file in WGQ_PEER_PUBLIC_KEY_FILE_LIST not found *${config_path}/${_peer_wg_pub_file}*"
                fi

                local peer_wg_pub="$(cat "${config_path}/${_peer_wg_pub_file}")"

                if [ "${peer_wg_pub}" == "${host_wg_pub}" ]
                then
                    continue
                fi

                local peer_name="${_peer_wg_pub_file##*/}" # remove path
                peer_name="${peer_name%.pub}" # remove extension

                config["peer_log_prefix_${peer_name}"]="[$(short4 "${peer_name}----")-$(short4 "${peer_wg_pub}----")]"

                config["peer_wg_pub_${peer_name}"]="${peer_wg_pub}"
                config["peer_gpg_id_${peer_name}"]="${peer_wg_pub}@${gpg_domain_name}"
                config["peer_totp_id_${peer_name}"]="${peer_wg_pub}"

                config["peer_name_list"]+="${peer_name} "
                config["peer_wg_pub_list"]+="${peer_wg_pub} "

                WGQ_PEER_ALLOWED_IPS_VAR_NAME="WGQ_PEER_${peer_name^^}_ALLOWED_IPS"
                config["peer_wg_quick_allowed_ips_${peer_name}"]="${!WGQ_PEER_ALLOWED_IPS_VAR_NAME:?Variable not set}"

                WGQ_PEER_LOCAL_IPS_VAR_NAME="WGQ_PEER_${peer_name^^}_LOCAL_IPS"
                config["peer_wg_quick_local_ips_${peer_name}"]="${!WGQ_PEER_LOCAL_IPS_VAR_NAME:-}"
            done

            config["peer_name_list"]="${config["peer_name_list"]% }"
            config["peer_wg_pub_list"]="${config["peer_wg_pub_list"]% }"
            ;;
        up)
            info

            declare -r -g -A config
            ;;
    esac
}

WT_CONFIG_TYPE="${WT_CONFIG_TYPE:-env}"
alias config="${WT_CONFIG_TYPE}_config"
config ""        || die "invalid WT_CONFIG_TYPE *${WT_CONFIG_TYPE}*, options: $(options config)"

# event

function event() {
    local action="${1}" && shift

    case "${action}" in
        init)
            info

            EVENT_FIFO_FILE="${WT_EPHEMERAL_PATH}/event"
            ;;
        up)
            info

            mkfifo "${EVENT_FIFO_FILE}"
            exec {_event_fd}<> "${EVENT_FIFO_FILE}"
            ;;
        down)
            if [[ ! -v _event_fd ]]
            then
                return 0
            fi

            exec {_event_fd}>&-

            if rm -f "${EVENT_FIFO_FILE}"
            then
                info "'${EVENT_FIFO_FILE}' was successfully deleted"
            else
                error "'${EVENT_FIFO_FILE}' delete error"
            fi
            ;;
        fire)
            local len event="${FUNCNAME[1]} event ${@}"
            debug "len=${#event} '${event}'"

            printf -v "len" "%02X" "${#event}"
            if ! echo -ne "\x${len}${event}" >&${_event_fd}
            then
                info "error writing '${event}'"
            fi
            ;;
        run)
            local event hexlen len

            while read -t 0 -u "${_event_fd}"
            do
                read -N 1 -u "${_event_fd}" "hexlen" || break
                printf -v "len" "%d" "'${hexlen}"

                if read -N "${len}" -u "${_event_fd}" "event"
                then
                    debug "len=${len} '${event}'"
                    ${event}
                else
                    break
                fi
            done
            ;;
    esac
}

# tasks

function tasks() {
    local action="${1}" && shift

    case "${action}" in
        deps)
            :
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

            local now="${EPOCHSECONDS}"
            local max_now="(1<<63)-1"
            local start="$((${now} ${plus_start/now/+0}))"
            local stop="$((${now} ${plus_stop/never/+${max_now}-${now}}))"

            _tasks["${name}"]="${frequency} ${start} ${stop} ${task}"
            _tasks_next["${name}"]="${start}"

            debug "name=${name} now=${now} next=${_tasks_next["${name}"]} frequency start stop task=${_tasks["${name}"]}"
            ;;
        unregister)
            shift # name
            local name="${1}" && shift

            debug "name=${name} now=${EPOCHSECONDS} next=${_tasks_next["${name}"]} frequency start stop task=${_tasks["${name}"]}"

            unset -v _tasks["${name}"]
            unset -v _tasks_next["${name}"]
            ;;
        run)
            local _name frequency start stop task next now

            for _name in "${!_tasks[@]}"
            do
                local params=(${_tasks[${_name}]})

                frequency="${params[0]}"
                start="${params[1]}"
                stop="${params[2]}"
                task="${params[@]:3}"

                next="${_tasks_next[${_name}]}"
                now="${EPOCHSECONDS}"

                if [[ ${now} -ge ${start} && ${now} -ge ${next} && ${now} -lt ${stop} ]]
                then
                    _tasks_next["${_name}"]="$((${now} + ${frequency}))"
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
            echo "wg grep cut sed sort tail id"
            ;;
        init)
            info
            WG_INTERFACE="${WG_INTERFACE:?Variable not set}"
            WG_HANDSHAKE_TIMEOUT="${WG_HANDSHAKE_TIMEOUT:-125}" # 125 seconds
            info "WG_INTERFACE=${WG_INTERFACE}"

            declare -g -A wg_peer_status
            declare -g -A wg_peer_address
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

            for _peer_name in ${config["peer_name_list"]}
            do
                wg_peer_status["${_peer_name}"]="wait"
                wg_peer_address["${_peer_name}"]="$(wg_interface get peer_address "${_peer_name}")"
            done
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
                    local peer_name="${1}" && shift
                    local endpoint="${1}" && shift
                    info "peer_endpoint ${peer_name} ${endpoint}"
                    wg set "${WG_INTERFACE}" peer "${config["peer_wg_pub_${peer_name}"]}" endpoint "${endpoint}"
                    ;;
            esac
            ;;
        get)
            name="${1}" && shift
            case "${name}" in
                generates_status_events)
                    return 1
                    ;;
                is_peer_local)
                    local peer_name="${1}" && shift

                    return 1
                    ;;
                peer_address)
                    local peer_name="${1}" && shift

                    {
                        wg show "${WG_INTERFACE}" allowed-ips
                    } | {
                        grep "${config["peer_wg_pub_${peer_name}"]}" \
                            | cut -f 2 | sed "s,/32,,"
                    } | {
                        read address
                        debug "peer_address ${peer_name} ${address:-''}"
                        echo "${address}"
                    }
                    ;;
                peer_status)
                    local peer_name="${1}" && shift
                    shift # var_name
                    local var_name="${1}" && shift

                    local result="offline"

                    if os_ping "${wg_peer_address["${peer_name}"]}" 2>&${WT_LOG_TRACE} 1>&${WT_LOG_TRACE}
                    then
                        result="online"
                    fi

                    if [ "${wg_peer_status["${peer_name}"]}" != "${result}" ]
                    then
                        wg_peer_status["${peer_name}"]="${result}"
                    fi

                    debug "peer_status ${peer_name} ${result:-''}"

                    read -N "${#result}" "${var_name}" <<<"${result}"
                    ;;
                host_status)
                    shift # var_name
                    local var_name="${1}" && shift

                    local result="offline"

                    for _peer_name in ${config["peer_name_list"]}
                    do
                        if [ "${wg_peer_status["${_peer_name}"]}" == "online" ]
                        then
                            result="online"
                        fi
                    done

                    debug "host_status ${result}"

                    read -N "${#result}" "${var_name}" <<<"${result}"
                    ;;
            esac
            ;;
        status)
            local status="down"

            if [[ ! -v WG_INTERFACE ]]
            then
                info "WG_INTERFACE was not set"
            else
                if wg show "${WG_INTERFACE}" 2>&1  >&"${null}"
                then
                    status="up"
                fi
            fi

            info "${status}"
            echo "${status}"
            ;;
    esac
}

# wg quick interface

function wg_quick_update_location() {
    local action=""
    debug

    for _peer_name in ${config["peer_name_list"]}
    do
        local local_port="0" local_ip=""

        if [ -f "${WT_PEER_ENDPOINT_PATH}/${_peer_name}_local_port" ]
        then
            local_port="$(cat "${WT_PEER_ENDPOINT_PATH}/${_peer_name}_local_port" 2>&${WT_LOG_DEBUG})"
        fi

        if [ "${config["peer_wg_quick_local_ips_${_peer_name}"]}" != "" ]
        then
            local_ip="${config["peer_wg_quick_local_ips_${_peer_name}"]}"
        fi

        wg_quick_location["${_peer_name}"]="remote"

        if [[ "${local_port}" != "0" && "${local_ip}" != "" ]]
        then
            if os_ping_quick "${local_ip}" >&${null}
            then
                wg_quick_location["${_peer_name}"]="local"
            fi
        fi
    done
}

function wg_quick_generate_config_file() {
    local action=""
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

    for _peer_name in ${config["peer_name_list"]}
    do
        if [ "${config["peer_wg_pub_${_peer_name}"]}" == "${config["host_wg_pub"]}" ]
        then
            continue
        fi

        cat <<EOF

[Peer]
PublicKey = ${config["peer_wg_pub_${_peer_name}"]}
AllowedIPs = ${config["peer_wg_quick_allowed_ips_${_peer_name}"]}
PersistentKeepalive = ${WGQ_PEER_PERSISTENT_KEEPALIVE}
EOF

        local endpoint="" local_port="0" local_ip=""

        if [[ "${wg_quick_location["${_peer_name}"]}" == "local" ]]
        then
            local_port="$(cat "${WT_PEER_ENDPOINT_PATH}/${_peer_name}_local_port" 2>&${WT_LOG_DEBUG})"
            local_ip="${config["peer_wg_quick_local_ips_${_peer_name}"]}"
            endpoint="${local_ip}:${local_port}"
        fi

        if [[ "${endpoint}" == "" && -f "${WT_PEER_ENDPOINT_PATH}/${_peer_name}" ]]
        then
            endpoint=$(cat "${WT_PEER_ENDPOINT_PATH}/${_peer_name}" 2>&${WT_LOG_DEBUG} | cut -f 1 -d " ")
        else
        cat <<EOF
# Endpoint = $(cat "${WT_PEER_ENDPOINT_PATH}/${_peer_name}" 2>&${WT_LOG_DEBUG} | cut -f 1 -d " ")
EOF
        fi

        if [ "${endpoint}" != "" ]
        then
        cat <<EOF
Endpoint = ${endpoint}
EOF
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
            echo "wg-quick wg cat cut grep rm id"
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
            WGQ_PEER_PERSISTENT_KEEPALIVE="${WGQ_PEER_PERSISTENT_KEEPALIVE:-30}" # 30 seconds

            WGQ_LOG_LEVEL="${WGQ_LOG_LEVEL:-}"
            WGQ_USERSPACE="${WGQ_USERSPACE:-}"

            WGQ_INTERFACE="wth${WT_PID}"
            WGQ_CONFIG_FILE="${WT_EPHEMERAL_PATH}/${WGQ_INTERFACE}.conf"

            info "WGQ_INTERFACE=${WGQ_INTERFACE}"

            declare -g -A wg_quick_location

            for _peer_name in ${config["peer_name_list"]}
            do
                wg_quick_location["${_peer_name}"]="remote"
            done
            ;;
        up)
            info

            if [ "$(id -u)" != 0 ]
            then
                die "wg-quick must be run as root: user id $(id -u) != 0"
            fi

            wg_quick_update_location
            wg_quick_generate_config_file | sys buffer_to_file "${WGQ_CONFIG_FILE}"

            export WG_QUICK_USERSPACE_IMPLEMENTATION="${WGQ_USERSPACE}"
            export LOG_LEVEL="${WGQ_LOG_LEVEL}"

            info "wg-quick up ${WGQ_CONFIG_FILE}"
            wg-quick up "${WGQ_CONFIG_FILE}" 2>&${WT_LOG_DEBUG}

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
            wg_interface up
            ;;
        down)
            if [[ ! -v WGQ_CONFIG_FILE ]]
            then
                info "WGQ_CONFIG_FILE was not set"
                return 0
            fi

            if [ "$(wg_interface status)" == "up" ]
            then
                info "wg-quick down ${WGQ_CONFIG_FILE}"
                wg-quick down "${WGQ_CONFIG_FILE}"
            else
                info "wg-quick was not up"
            fi

            if rm -f "${WGQ_CONFIG_FILE}"
            then
                info "'${WGQ_CONFIG_FILE}' was successfully deleted"
            else
                error "'${WGQ_CONFIG_FILE}' delete error"
            fi
            ;;
        reload)
            info

            wg_quick_update_location
            wg_quick_generate_config_file | sys buffer_to_file "${WGQ_CONFIG_FILE}"
            wg syncconf "${WG_INTERFACE}" <(wg-quick strip "${WGQ_CONFIG_FILE}")
            wg set "${WG_INTERFACE}" private-key "${WT_CONFIG_PATH}/${WGQ_HOST_PRIVATE_KEY_FILE}"
            ;;
        on_location)
            local peer_name="${1}" && shift

            event fire location "${peer_name} ${wg_quick_location["${_peer_name}"]}"
            ;;
        event)
            local event="${1}" && shift

            case "${event}" in
                location)
                    local peer_name="${1}" && shift
                    local location="${1}" && shift

                    wg_quick_location["${peer_name}"]="${location}"
                    ;;
            esac
            ;;
        set)
            local name="${1}" && shift

            case "${name}" in
                host_port)
                    local port="${1}" && shift
                    info "host_port ${port:-''}"

                    if ! grep -q "ListenPort = ${port}" < "${WGQ_CONFIG_FILE}"
                    then
                        wg_quick_interface reload
                    fi
                    ;;
                peer_endpoint)
                    local peer_name="${1}" && shift
                    local endpoint="${1}" && shift
                    info "peer_endpoint ${peer_name} ${endpoint}"

                    if ! grep -q "Endpoint = ${endpoint}" < "${WGQ_CONFIG_FILE}"
                    then
                        wg_quick_interface reload
                    fi
                    ;;
                peer_local_port)
                    local peer_name="${1}" && shift
                    local local_port="${1}" && shift
                    info "peer_local_port ${peer_name} ${local_port}"

                    local endpoint="${config["peer_wg_quick_local_ips_${peer_name}"]}:${local_port}"

                    if ! grep -q "Endpoint = ${endpoint}" < "${WGQ_CONFIG_FILE}" &&
                        os_ping_quick "${config["peer_wg_quick_local_ips_${peer_name}"]}" >&${null}
                    then
                        wg_quick_interface reload
                    fi
                    ;;
            esac
            ;;
        get)
            local name="${1}" && shift

            case "${name}" in
                generates_status_events)
                    return 1
                    ;;
                is_peer_local)
                    local peer_name="${1}" && shift

                    if [ "${wg_quick_location[${peer_name}]}" == "local" ]
                    then
                        return 0
                    else
                        return 1
                    fi
                    ;;
                *)
                    wg_interface "${action}" "${name}" ${@}
            esac
            ;;
    esac
}

# wireproxy interface

function wireproxy_notify_location() {
    local action=""
    debug

    for _peer_name in ${config["peer_name_list"]}
    do
        wg_quick_interface on_location "${_peer_name}"
    done
}

function wireproxy_generate_config_file() {
    local action=""
    debug

    wg_quick_generate_config_file

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

    for _port in ${WIREPROXY_EXPOSE_PORT_LIST}
    do
        IFS=: read __port __ip <<<"${_port}"
        cat <<EOF

[TCPServerTunnel]
ListenPort = ${__port}
Target = ${__ip:-127.0.0.1}:${__port}
EOF
    done

    for _forward in ${WIREPROXY_FORWARD_PORT_LIST}
    do
        {
            echo "${_forward//:/ }"
        } | {
            read local_port remote_endpoint remote_port local_ip
            cat <<EOF

[TCPClientTunnel]
BindAddress = ${local_ip:-127.0.0.1}:${local_port}
Target = ${remote_endpoint}:${remote_port}
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
            echo "wg cat cut find grep rm sort tail touch sleep"
            ;;
        init)
            info

            WIREPROXY_COMMAND="${WIREPROXY_COMMAND:-wireproxy}"
            WIREPROXY_RELOAD_FILE="${WT_EPHEMERAL_PATH}/wireproxy.reload"
            WIREPROXY_READY_FILE="${WT_EPHEMERAL_PATH}/wireproxy.ready"
            WIREPROXY_HTTP_BIND="${WIREPROXY_HTTP_BIND:-disabled}" # 127.0.0.1:3128
            WIREPROXY_SOCKS5_BIND="${WIREPROXY_SOCKS5_BIND:-127.0.0.1:1080}"
            WIREPROXY_HEALTH_BIND="${WIREPROXY_HEALTH_BIND:-127.0.0.1:9080}"
            WIREPROXY_PEER_STATUS_TIMEOUT="${WIREPROXY_PEER_STATUS_TIMEOUT:-90}" # 35 seconds
            WIREPROXY_HOST_STATUS_TIMEOUT="${WIREPROXY_HOST_STATUS_TIMEOUT:-120}" # 45 seconds
            WIREPROXY_HANDSHAKE_TIMEOUT="${WIREPROXY_HANDSHAKE_TIMEOUT:-135}" # 135 seconds
            WIREPROXY_EXPOSE_PORT_LIST="${WIREPROXY_EXPOSE_PORT_LIST:-}"
            WIREPROXY_FORWARD_PORT_LIST="${WIREPROXY_FORWARD_PORT_LIST:-}"

            if [ "${OS_LOCALE}" == "UTF-8" ]
            then
                WIREPROXY_LOG_PEER_LEN="9"
            else
                WIREPROXY_LOG_PEER_LEN="11"
            fi

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

            declare -g -A wireproxy_name_table
            declare -g -A wireproxy_peer_status
            ;;
        up)
            info

            wg_quick_update_location
            wireproxy_generate_config_file | sys buffer_to_file "${WGQ_CONFIG_FILE}"

            local wg_pub="${config["host_wg_pub"]}"
            local index="${wg_pub::4}…${wg_pub:(-5):4}"
            wireproxy_name_table["${index}"]="${config["host_name"]}"

            for _peer_name in ${config["peer_name_list"]}
            do
                wg_pub="${config["peer_wg_pub_${_peer_name}"]}"
                index="${wg_pub::4}…${wg_pub:(-5):4}"
                wireproxy_name_table["${index}"]="${_peer_name}"
            done

            for _peer_name in ${config["peer_name_list"]}
            do
                wireproxy_peer_status["${_peer_name}"]="wait"
            done

            coproc WIREPROXY_BG (wireproxy_interface run)
            ;;
        down)
            if [[ ! -v WIREPROXY_BG_PID ]]
            then
                info "'wireproxy_bg' was not running"
            else
                if sys terminate "${WIREPROXY_BG_PID}"
                then
                    info "'wireproxy_bg' pid=${WIREPROXY_BG_PID} was successfully stopped"
                else
                    info "'wireproxy_bg' pid=${WIREPROXY_BG_PID} was not running"
                fi
            fi
            ;;
        start)
            info
            local wireproxy_params=""

            if timeout 2 nc -z ${WIREPROXY_HEALTH_BIND/:/ } 2>&${null}
            then
                error "health bind disabled, tcp ${WIREPROXY_HEALTH_BIND} address already in use"
            elif [ "${WIREPROXY_HEALTH_BIND}" != "disabled" ]
            then
                wireproxy_params="-i ${WIREPROXY_HEALTH_BIND}"
            fi

            local host_port="0"
            local host_endpoint=""

            if [ -f "${WT_HOST_PORT_FILE}" ]
            then
                host_port="$(cat "${WT_HOST_PORT_FILE}" 2>&${WT_LOG_DEBUG} || echo)"
            fi

            if [ -f "${WT_HOST_ENDPOINT_FILE}" ]
            then
                host_endpoint="$(cat "${WT_HOST_ENDPOINT_FILE}" 2>&${WT_LOG_DEBUG} || echo)"
            fi

            wg_quick_update_location
            wireproxy_generate_config_file | sys buffer_to_file "${WGQ_CONFIG_FILE}"

            exec {WIREPROXY_FD}< <({
                set +o errexit  # +e Don't exit immediately if any command returns a non-zero status
                "${WIREPROXY_COMMAND}" ${wireproxy_params} -c \
                    <(WGQ_USE_POSTUP_TO_SET_PRIVATE_KEY=false wireproxy_generate_config_file) 2>&1 \
                        | log file "wireproxy"
                wireproxy_interface _status "${?}" "${host_port}" "${host_endpoint}"
            })
            WIREPROXY_PPID="${!}"

            wireproxy_notify_location
            ;;
        _status)
            local exit_status="${1}" && shift
            local host_port="${1}" && shift
            local host_endpoint="${1}" && shift

            action="wireproxy" info "exit status: ${exit_status}"

            if [[ "${exit_status}" != "0" ]]
            then
                if [[ "${host_port}" != "0" && "${host_port}" != "" && "${host_endpoint}" != "" ]] &&
                    "${WT_PUNCH_TYPE}_punch" status "${host_port}" "${host_endpoint}"
                then
                    info "success"
                else
                    info "failed"
                    event fire punch
                fi
            fi
            ;;
        stop)
            info

            if rm -f "${WIREPROXY_READY_FILE}"
            then
                info "'${WIREPROXY_READY_FILE}' was successfully deleted"
            else
                error "'${WIREPROXY_READY_FILE}' delete error"
            fi

            if [[ ! -v WIREPROXY_PPID ]]
            then
                info "'wireproxy' was not running"
            else
                if sys terminate_from_parent_pid "${WIREPROXY_PPID}"
                then
                    info "'wireproxy' ppid=${WIREPROXY_PPID} was successfully stopped"
                else
                    info "'wireproxy' ppid=${WIREPROXY_PPID} was not running"
                fi
            fi

            while wireproxy_interface process_log
            do
                :
            done

            exec {WIREPROXY_FD}>&- || true

            unset -v WIREPROXY_FD
            ;;
        run)
            trap "wireproxy_interface stop" "EXIT"

            wireproxy_interface start

            while wireproxy_interface process_log
            do
                if [[ -f "${WIREPROXY_RELOAD_FILE}" && -f "${WIREPROXY_READY_FILE}" ]]
                then
                    if rm -f "${WIREPROXY_RELOAD_FILE}"
                    then
                        info "'${WIREPROXY_RELOAD_FILE}' was successfully deleted"
                    else
                        error "'${WIREPROXY_RELOAD_FILE}' delete error"
                    fi

                    wireproxy_interface stop
                    wireproxy_interface start
                fi
            done

            info "down"
            ;;
        process_log)
            local line

            if [[ ! -v WIREPROXY_FD ]]
            then
                return 1
            fi

            if ! read line <&"${WIREPROXY_FD}"
            then
                return 1
            fi

            local log_level="info"

            case "${line}" in
                *"Received"*)
                    log_level="trace"
                    ;;
                *"Receiving"*)
                    log_level="trace"
                    ;;
                *"Sending"*)
                    log_level="trace"
                    ;;
                *"Health metric request"*)
                    log_level="trace"
                    ;;
                *"Handshake did not complete after 5 seconds"*)
                    log_level="trace"
                    ;;
                "DEBUG: "*)
                    log_level="debug"
                    ;;
                "ERROR: "*)
                    log_level="error"
                    ;;
            esac

            local log_index=20

            case "${line}" in
                "DEBUG: "*)
                    log_index=27
                    ;;
                "ERROR: "*)
                    log_index=27
                    ;;
            esac

            custom_log "${line}" wireproxy "${log_level}" "${log_index}"

            local index="${line:32:${WIREPROXY_LOG_PEER_LEN}}"

            case "${line}" in
                *"Receiving keepalive packet")
                    local peer_name="${wireproxy_name_table["${index}"]}"

                    if [ "${wireproxy_peer_status["${peer_name}"]}" != "online" ]
                    then
                        wireproxy_peer_status["${peer_name}"]="online"
                        event fire peer_status "${peer_name} online"
                    fi
                    ;;
                *"Received handshake response")
                    local peer_name="${wireproxy_name_table["${index}"]}"

                    if [ "${wireproxy_peer_status["${peer_name}"]}" != "online" ]
                    then
                        wireproxy_peer_status["${peer_name}"]="online"
                        event fire peer_status "${peer_name} online"
                    fi
                    ;;
                *"Failed to send data packets"*)
                    local peer_name="${wireproxy_name_table["${index}"]}"

                    if [ "${wireproxy_peer_status["${peer_name}"]}" != "offline" ]
                    then
                        wireproxy_peer_status["${peer_name}"]="offline"
                        event fire peer_status "${peer_name} offline"
                    fi
                    ;;
                *"Failed to send handshake initiation"*)
                    local peer_name="${wireproxy_name_table["${index}"]}"

                    if [ "${wireproxy_peer_status["${peer_name}"]}" != "offline" ]
                    then
                        wireproxy_peer_status["${peer_name}"]="offline"
                        event fire peer_status "${peer_name} offline"
                    fi
                    ;;
                *"Handshake did not complete after"*)
                    local peer_name="${wireproxy_name_table["${index}"]}"

                    if [ "${wireproxy_peer_status["${peer_name}"]}" != "offline" ]
                    then
                        wireproxy_peer_status["${peer_name}"]="offline"
                        event fire peer_status "${peer_name} offline"
                    fi
                    ;;
                *"Interface state was Down, requested Up, now Up")
                    info "interface is ready"
                    touch "${WIREPROXY_READY_FILE}"
                    event fire ready
                    ;;
                "ERROR"*"IPC error -48: failed to set listen_port: listen udp4 :"*": bind: address already in use")
                    event fire punch
                    ;;
                *"IPC error -48: failed to set listen_port: listen udp4 :"*": bind: address already in use")
                    info "interface was failed"
                    sleep 10
                    ;;
                *"address already in use")
                    info "interface was failed"
                    touch "${WIREPROXY_READY_FILE}"
                    ;;
            esac
            ;;
        reload)
            info
            touch "${WIREPROXY_RELOAD_FILE}"
            ;;
        event)
            local event="${1}" && shift

            case "${event}" in
                peer_status)
                    local peer_name="${1}" && shift
                    local status="${1}" && shift

                    info "peer_status ${peer_name} ${status}"

                    wireproxy_peer_status["${peer_name}"]="${status}"
                    peer_state set_polled_status "${peer_name}" "${status}"
                    ;;
                punch)
                    if wirething punch_host_endpoint
                    then
                        info "punch succeeded"
                        wirething broadcast_host_endpoint
                    else
                        info "punch failed"
                    fi

                    touch "${WIREPROXY_READY_FILE}"
                    ;;
                ready)
                    ui after_status_changed
            esac
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
                    local peer_name="${1}" && shift
                    local endpoint="${1}" && shift
                    info "peer_endpoint ${peer_name} ${endpoint}"

                    if ! grep -q "Endpoint = ${endpoint}" < "${WGQ_CONFIG_FILE}"
                    then
                        wireproxy_interface reload
                    fi
                    ;;
                peer_local_port)
                    local peer_name="${1}" && shift
                    local local_port="${1}" && shift
                    info "peer_local_port ${peer_name} ${local_port}"

                    local endpoint="${config["peer_wg_quick_local_ips_${peer_name}"]}:${local_port}"

                    if ! grep -q "Endpoint = ${endpoint}" < "${WGQ_CONFIG_FILE}" &&
                        os_ping_quick "${config["peer_wg_quick_local_ips_${peer_name}"]}" >&${null}
                    then
                        wireproxy_interface reload
                    fi
                    ;;
            esac
            ;;
        get)
            local name="${1}" && shift

            case "${name}" in
                generates_status_events)
                    return 0
                    ;;
                is_peer_local)
                    wg_quick_interface "${action}" "${name}" ${@}
                    ;;
                peer_status)
                    local peer_name="${1}" && shift
                    shift # var_name
                    local var_name="${1}" && shift

                    local result="offline"

                    if [[ "${wireproxy_peer_status["${peer_name}"]}" == "online" ]]
                    then
                        result="online"
                    fi

                    read -N "${#result}" "${var_name}" <<<"${result}"
                    ;;
                host_status)
                    shift # var_name
                    local var_name="${1}" && shift

                    local all_local="true"
                    local has_online_peer="false"
                    local has_online_local_peer="false"

                    for _peer_name in ${config["peer_name_list"]}
                    do
                        if wireproxy_interface get is_peer_local "${_peer_name}"
                        then
                            if [[ "${wireproxy_peer_status["${_peer_name}"]}" == "online" ]]
                            then
                                has_online_local_peer="true"
                            fi
                        else
                            all_local="false"

                            if [[ "${wireproxy_peer_status["${_peer_name}"]}" == "online" ]]
                            then
                                has_online_peer="true"
                            fi
                        fi
                    done

                    if [ "${all_local}" == "true" ]
                    then
                        has_online_peer="${has_online_local_peer}"
                    fi

                    local result="offline"

                    if [[ "${has_online_peer}" == "true" ]]
                    then
                        result="online"
                    fi

                    debug "host_status ${result}"

                    read -N "${#result}" "${var_name}" <<<"${result}"
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
            ;;
        init)
            info
            UDPHOLE_HOSTNAME="${UDPHOLE_HOSTNAME:-udphole.wirething.org}" # udphole.wirething.org is a dns cname poiting to hdphole.fly.dev
            UDPHOLE_PORT="${UDPHOLE_PORT:-6094}"
            UDPHOLE_READ_TIMEOUT="${UDPHOLE_READ_TIMEOUT:-10}" # 10 seconds
            UDPHOLE_PUNCH_PID="${WT_PID}"
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
                    info "${result:-''}"
                    return 0
                fi

                info "${result:-''}"
                return 1
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
                        udp port ${UDPHOLE_HOSTNAME} ${UDPHOLE_PORT} ${UDPHOLE_PUNCH_PID}
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

            STUN_HOSTNAME="${STUN_HOSTNAME:-stunserver2024.stunprotocol.org}" # Stun service hosting the Stuntman
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

                stun_punch close

                debug "stun *${port}* *${endpoint}*"

                if [[ "${host_port}" == "${port}" && "${host_endpoint}" == "${endpoint}" ]]
                then
                    result="online"
                    info "${result:-''}"
                    return 0
                fi
            else
                debug "stun ** **"
            fi

            info "${result:-''}"
            return 1
            ;;
        open)
            debug "${STUN_HOSTNAME}" "${STUN_PORT}"
            local host_port="${1:-}"

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

            for _line in "${stun_buffer[@]}"
            do
                case "${_line}" in
                    "Binding test: success")
                        ;;
                    "Local address: "*)
                        STUN_LOCAL_PORT="${_line/*:/}"
                        ;;
                    "Mapped address: "*)
                        STUN_REMOTE_ENDPOINT="${_line/*: /}"
                        ;;
                    *)
                        error "${_line}"
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
            unset -v STUN_LOCAL_PORT
            unset -v STUN_REMOTE_ENDPOINT
            ;;
    esac
}

# ntfy pubsub

function ntfy_pubsub() {
    local action="${1}" && shift

    case "${action}" in
        deps)
            echo "curl sleep"
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
            local format="${1:-raw}"

            debug "curl ${NTFY_CURL_OPTIONS} --max-time \"${NTFY_POLL_TIMEOUT}\" --stderr - \"${NTFY_URL}/${topic}/${format}?poll=1&since=${since}\""
            {
                curl ${NTFY_CURL_OPTIONS} --max-time "${NTFY_POLL_TIMEOUT}" --stderr - \
                    "${NTFY_URL}/${topic}/${format}?poll=1&since=${since}" \
                    || true
            } | tail -n 1 | {
                read poll_response || true

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
        subscribe_start)
            local topic="${1}" && shift
            local since="${1}" && shift
            local format="${1:-json}"

            debug "${topic}"

            debug "curl ${NTFY_CURL_OPTIONS} --max-time "${NTFY_SUBSCRIBE_TIMEOUT}" --stderr - ${NTFY_URL}/${topic}/${format}?since=${since}"
            exec {NTFY_SUBSCRIBE_FD}< <(exec curl ${NTFY_CURL_OPTIONS} --max-time "${NTFY_SUBSCRIBE_TIMEOUT}" --stderr - \
                    "${NTFY_URL}/${topic}/${format}?since=${since}")
            NTFY_SUBSCRIBE_PID="${!}"
            ;;
        subscribe_stop)
            if [[ ! -v NTFY_SUBSCRIBE_PID ]]
            then
                info "'ntfy' was not running"
            else
                if sys terminate "${NTFY_SUBSCRIBE_PID}"
                then
                    info "'ntfy' pid=${NTFY_SUBSCRIBE_PID} was successfully stopped"
                else
                    info "'ntfy' pid=${NTFY_SUBSCRIBE_PID} was not running"
                fi

            fi
            ;;
        subscribe_run)
            while ntfy_pubsub subscribe_process
            do
                :
            done
            ;;
        subscribe_process)
            local subscribe_response

            if [[ ! -v NTFY_SUBSCRIBE_FD ]]
            then
                return 1
            fi

            if ! read -t 60 -u "${NTFY_SUBSCRIBE_FD}" subscribe_response
            then
                return 1
            fi

            case "${subscribe_response}" in
                "")
                    ;;
                "curl"*"timed out"*)
                    debug "$(short "${topic}") response: ${subscribe_response}"
                    echo '{"event":"timeout"}'
                    return 1
                    ;;
                "curl: (56) Recv failure: Software caused connection abort")
                    info "$(short "${topic}") response: ${subscribe_response}"
                    echo '{"event":"connection_lost"}'
                    return 1
                    ;;
                "curl"*)
                    error "$(short "${topic}") response: ${subscribe_response}"
                    echo '{"event":"error"}'
                    return 1
                    ;;
                "{"*"error"*)
                    error "$(short "${topic}") response: ${subscribe_response}"
                    echo '{"event":"error"}'
                    return 1
                    ;;
                *)
                    echo "${subscribe_response}"
            esac
            ;;
        subscribe)
            local topic="${1}" && shift
            local since="${1}" && shift
            local format="${1:-json}"

            debug "${topic} starting"

            debug "curl ${NTFY_CURL_OPTIONS} --max-time "${NTFY_SUBSCRIBE_TIMEOUT}" --stderr - ${NTFY_URL}/${topic}/${format}?since=${since}"

            {
                curl ${NTFY_CURL_OPTIONS} --max-time "${NTFY_SUBSCRIBE_TIMEOUT}" --stderr - \
                    "${NTFY_URL}/${topic}/${format}?since=${since}" \
                    || true
            } | {
                while read subscribe_response
                do
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
            echo "gpg mkdir grep cut sed gpgconf rm"
            ;;
        init)
            info

            export GNUPGHOME="${WT_EPHEMERAL_PATH}/gpg"

            GPG_FILE_LIST="${GPG_FILE_LIST:?Variable not set}"
            GPG_DOMAIN_NAME="${GPG_DOMAIN_NAME:-wirething.gpg}"
            GPG_OPTIONS="${GPG_OPTIONS:---disable-dirmngr --no-auto-key-locate --batch --no}"
            GPG_AGENT_CONF="${GPG_AGENT_CONF:-disable-scdaemon\nextra-socket /dev/null\nbrowser-socket /dev/null\n}" # Disabling scdaemon (smart card daemon) make gpg do not try to use your Yubikey

            for _gpg_file in ${GPG_FILE_LIST}
            do
                if [ ! -f "${WT_CONFIG_PATH}/${_gpg_file}" ]
                then
                    die "file in GPG_FILE_LIST not found *${WT_CONFIG_PATH}/${_gpg_file}*"
                fi
            done
            ;;
        up)
            info

            mkdir -p "${GNUPGHOME}"

            echo -ne "${GPG_AGENT_CONF}" > "${GNUPGHOME}/gpg-agent.conf"

            for _gpg_file in ${GPG_FILE_LIST}
            do
                gpg ${GPG_OPTIONS} --import "${WT_CONFIG_PATH}/${_gpg_file}" 2>&${WT_LOG_DEBUG}
                gpg ${GPG_OPTIONS} --show-keys --with-colons "${WT_CONFIG_PATH}/${_gpg_file}" 2>&${WT_LOG_DEBUG} \
                    | grep "fpr" | cut -f "10-" -d ":" | sed "s,:,:6:," \
                    | gpg ${GPG_OPTIONS} --import-ownertrust 2>&${WT_LOG_DEBUG}
            done
            ;;
        down)
            if [[ ! -v GNUPGHOME ]]
            then
                info "GNUPGHOME was not set"
                return 0
            fi

            if gpgconf --kill gpg-agent 2>&${null}
            then
                info "'gpg-agent' was successfully stopped"
            else
                info "'gpg-agent' was not running"
            fi

            if rm -rf "${GNUPGHOME}"
            then
                info "'${GNUPGHOME}' was successfully deleted"
            else
                error "'${GNUPGHOME}' delete error=${?}"
            fi
            ;;
        encrypt)
            debug
            local data="${1}" && shift

            if [[ ${#@} -gt 0 ]]
            then
                local peer_name="${1}" && shift
                local peer_recipient="--hidden-recipient ${config["peer_gpg_id_${peer_name}"]}"
            else
                local peer_recipient=""
            fi

            local host_recipient="--hidden-recipient ${config["host_gpg_id"]}"

            {
                echo "${data}"
            } | {
                gpg --encrypt ${GPG_OPTIONS} ${host_recipient} ${peer_recipient} --sign --armor \
                        2>&${WT_LOG_DEBUG}
            } | {
                os_base64
            }
            ;;
        decrypt)
            debug
            local data="${1}" && shift

            {
                echo "${data}"
            } | {
                os_base64 -d
            } | {
                capture start

                debug "gpg --decrypt ${GPG_OPTIONS} --local-user ${config["host_gpg_id"]}"

                gpg --decrypt ${GPG_OPTIONS} \
                    --local-user "${config["host_gpg_id"]}" \
                    2>&${capture[1]} \
                    || debug "gpg returns ${?}"

                capture stop

                readarray -u "${capture[0]}" gpg_buffer

                if grep -iq "Good signature" <<<"${gpg_buffer[*]}"
                then
                    return 0
                else
                    error "gpg 'Good signature' not found"
                    return 1
                fi
            }
            ;;
    esac
}

# totp topic

function totp_token() {
    read digest
    # Read the last 4 bits and convert it into an unsigned integer.
    local start="$(( 0x${digest:(-1)} * 2))"
    # Read a 32-bit positive integer and take at most six rightmost digits.
    local token="$(( ((0x${digest:${start}:8}) & 0x7FFFFFFF) % $((10 ** ${TOTP_DIGITS})) ))"
    # Pad the token number with leading zeros if needed.
    printf "%0${TOTP_DIGITS}d\n" "${token}"
}

function totp_interval() {
    {
        cat <<<"$((${EPOCHSECONDS} / ${TOTP_PERIOD}))"
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

function totp_hmac_digest_python_src() {
    cat <<EOF
import sys, hmac, hashlib

with open(sys.argv[1], mode="rb") as key:
    h = hmac.new(key.read(), sys.stdin.buffer.read(), hashlib.${TOTP_ALGORITHM,,})
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

function totp_secret() {
    local action="${1}" && shift
    local peer_name="${1}" && shift

    {
        case "${action}" in
            publish)
                os_base64 -d <<<"${config["host_totp_id"]}"
                os_base64 -d <<<"${config["peer_totp_id_${peer_name}"]}"
                ;;
            subscribe)
                os_base64 -d <<<"${config["peer_totp_id_${peer_name}"]}"
                os_base64 -d <<<"${config["host_totp_id"]}"
                ;;
            *)
                die "invalid action *${1}*, options: publish, subscribe"
                ;;
        esac
    } | openssl sha256 -binary
}


function totp_digest() {
    local action="${1}" && shift
    local peer_name="${1}" && shift

    totp_interval | "totp_hmac_digest_${TOTP_HMAC}" <(totp_secret "${action}" "${peer_name}")
}

function totp_topic() {
    local action="${1}" && shift

    case "${action}" in
        deps)
            echo "cat openssl sed python3"
            ;;
        init)
            info
            TOTP_TOKEN="${TOTP_TOKEN:-cat}"
            TOTP_DIGITS="${TOTP_DIGITS:-6}"
            TOTP_PERIOD="${TOTP_PERIOD:-28800}" # 8 hours
            TOTP_ALGORITHM="${TOTP_ALGORITHM:-SHA256}"
            TOTP_HMAC="${TOTP_HMAC:-python}"
            ;;
        next)
            echo "$(( ((${EPOCHSECONDS} / ${TOTP_PERIOD} + 1) * ${TOTP_PERIOD}) - ${EPOCHSECONDS} + 5))"
            ;;
        publish|subscribe)
            local peer_name="${1}" && shift

            totp_digest "${action}" "${peer_name}" | "${TOTP_TOKEN}"
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
            echo "mkdir cat cut jq sleep"
            ;;
        init)
            info
            WT_HOST_PORT_FILE="${WT_STATE_PATH}/host_port"
            WT_HOST_ENDPOINT_FILE="${WT_STATE_PATH}/host_endpoint"
            WT_PEER_ENDPOINT_PATH="${WT_STATE_PATH}/peer_endpoint"
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

            if [ ! -f "${WT_HOST_PORT_FILE}" ]
            then
                echo "0" > "${WT_HOST_PORT_FILE}"
            fi

            if [ ! -f "${WT_HOST_ENDPOINT_FILE}" ]
            then
                echo "" > "${WT_HOST_ENDPOINT_FILE}"
            fi

            for _peer_name in ${config["peer_name_list"]}
            do
                if [ ! -f "${WT_PEER_ENDPOINT_PATH}/${_peer_name}" ]
                then
                    echo "" > "${WT_PEER_ENDPOINT_PATH}/${_peer_name}"
                fi
            done

            coproc WIRETHING_SUBSCRIBE_BG (wirething subscribe_encrypted_peer_endpoint)
            ;;
        down)
            if [[ ! -v WIRETHING_SUBSCRIBE_BG_PID ]]
            then
                info "'wirething_subscribe_bg' was not running"
            else
                if sys terminate "${WIRETHING_SUBSCRIBE_BG_PID}"
                then
                    info "'wirething_subscribe_bg' pid=${WIRETHING_SUBSCRIBE_BG_PID} was successfully stopped"
                else
                    info "'wirething_subscribe_bg' pid=${WIRETHING_SUBSCRIBE_BG_PID} was not running"
                fi
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
            local peer_name="${1}" && shift

            info "${peer_name}"

            local value="${WT_PID}"

            {
                encryption encrypt "${value}" "${peer_name}" 2>&${WT_LOG_DEBUG} \
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
                wirething get peer_endpoint "${peer_name}"
            } | {
                read peer_endpoint

                if [ "${peer_endpoint}" != "" ]
                then
                    interface set peer_endpoint "${peer_name}" "${peer_endpoint}"
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
                    local peer_name="${1}" && shift
                    local endpoint="${1}" && shift
                    local timestamp="${1:-${EPOCHSECONDS}}"

                    info "peer_endpoint ${peer_name} ${endpoint}"
                    echo "${endpoint} ${timestamp}" > "${WT_PEER_ENDPOINT_PATH}/${peer_name}"

                    interface set peer_endpoint "${peer_name}" "${endpoint}"
                    ;;
                peer_local_port)
                    local peer_name="${1}" && shift
                    local local_port="${1}" && shift

                    info "peer_local_port ${peer_name} ${local_port}"
                    echo "${local_port}" > "${WT_PEER_ENDPOINT_PATH}/${peer_name}_local_port"

                    interface set peer_local_port "${peer_name}" "${local_port}"
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
                    local peer_name="${1}" && shift

                    local endpoint="$(cat "${WT_PEER_ENDPOINT_PATH}/${peer_name}" 2>&${WT_LOG_DEBUG} | cut -f 1 -d " ")"
                    debug "peer_endpoint ${peer_name} ${endpoint:-''}"
                    echo "${endpoint}"
                    ;;
                peer_endpoint_update_time)
                    local peer_name="${1}" && shift

                    local timestamp="$(cat "${WT_PEER_ENDPOINT_PATH}/${peer_name}" 2>&${WT_LOG_DEBUG} | cut -f 2 -d " ")"
                    debug "peer_endpoint_update_time ${peer_name} ${timestamp:-''}"
                    echo "${timestamp:-0}"
                    ;;
            esac
            ;;
        punch_host_endpoint)
            debug

            local host_endpoint host_port

            if punch open
            then
                read host_endpoint < <(punch get endpoint)
                read host_port < <(punch get port)

                punch close

                if [[ "${host_port}" != "" && "${host_endpoint}" != "" ]]
                then
                    wirething set host_endpoint "${host_endpoint}"
                    wirething set host_port "${host_port}"
                else
                    error "host_port='${host_port}' or host_endpoint='${host_endpoint}' are empty"
                    return 1
                fi
            else
                return 1
            fi
            ;;
        broadcast_host_endpoint)
            debug

            for _peer_name in ${config["peer_name_list"]}
            do
                wirething publish_host_endpoint "${_peer_name}"
            done
            ;;
        publish_host_endpoint)
            debug
            local peer_name="${1}" && shift

            read host_endpoint < <(wirething get host_endpoint)
            read host_port < <(wirething get host_port)

            if [ "${host_endpoint}" != "" ]
            then
                info "${host_endpoint} ${host_port}"

                {
                    topic publish "${peer_name}"
                } | {
                    read topic
                    {
                        encryption encrypt "${host_endpoint} ${host_port}" "${peer_name}"
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
            ;;
        poll_encrypted_host_endpoint)
            debug
            local peer_name="${1}" && shift
            local since="${1}" && shift

            {
                topic publish "${peer_name}"
            } | {
                read topic
                pubsub poll "${topic}" "${since}"
            }
            ;;
        subscribe_encrypted_peer_endpoint)
            info

            while true
            do
                declare -A topic_index

                for _peer_name in ${config["peer_name_list"]}
                do
                    local topic="$(topic subscribe "${_peer_name}")"
                    topic_index["${topic}"]="${_peer_name}"
                done

                topic_list="$(IFS=","; echo "${!topic_index[*]}")"

                wirething subscribe_encrypted_peer_endpoint_run

                unset -v topic_index
            done
            ;;
        subscribe_encrypted_peer_endpoint_run)
            trap "pubsub subscribe_stop" "EXIT"

            NTFY_SUBSCRIBE_TIMEOUT="$(topic next)"

            pubsub subscribe_start "${topic_list}" "all" "json"

            pubsub subscribe_run | {
                declare -A peer_endpoint_list

                for _peer_name in ${config["peer_name_list"]}
                do
                    peer_endpoint_list["${_peer_name}"]="$(wirething get peer_endpoint "${_peer_name}")"
                    peer_endpoint_list["${_peer_name}_update_time"]="$(wirething get peer_endpoint_update_time "${_peer_name}")"
                done

                while read line
                do
                    trace "${line}"

                    wirething subscribe_encrypted_peer_endpoint_process
                done
            }

            pubsub subscribe_stop

            trap "" "EXIT"
            ;;
        subscribe_encrypted_peer_endpoint_process)
            case "${line}" in
                *'"event":"keepalive"'*)
                    :
                    ;;
                *'"event":"message"'*)
                    local topic="$(echo "${line}" | jq -r ".topic")"
                    local event_time="$(echo "${line}" | jq -r ".time")"
                    local encrypted_message="$(echo "${line}" | jq -r ".message")"

                    local peer_name="${topic_index[${topic}]}"
                    local new_peer_endpoint new_local_port
                    read new_peer_endpoint new_local_port <<<"$(encryption decrypt "${encrypted_message}")"

                    if [ ${event_time} -gt ${peer_endpoint_list["${peer_name}_update_time"]} ]
                    then
                        debug "${peer_name} new published peer_endpoint=${new_peer_endpoint} local_port=${new_local_port} ${event_time} current=${peer_endpoint_list["${peer_name}"]} ${peer_endpoint_list["${peer_name}_update_time"]}"
                    else
                        debug "${peer_name} old published peer_endpoint=${new_peer_endpoint} local_port=${new_local_port} ${event_time} current=${peer_endpoint_list["${peer_name}"]} ${peer_endpoint_list["${peer_name}_update_time"]}"
                    fi

                    if [[ ${event_time} -gt ${peer_endpoint_list["${peer_name}_update_time"]} &&
                         "${new_peer_endpoint}" != "" &&
                         "${new_peer_endpoint}" != "${peer_endpoint_list["${peer_name}"]}" ]]
                    then
                        peer_endpoint_list["${peer_name}"]="${new_peer_endpoint}"
                        peer_endpoint_list["${peer_name}_update_time"]="${event_time}"

                        info "new peer endpoint ${peer_name} ${new_peer_endpoint}"
                        event fire new_peer_endpoint "${peer_name} ${new_peer_endpoint} ${new_local_port:-0} ${event_time}"
                    fi
                    ;;
                *'"event":"open"'*)
                    :
                    ;;
                *'"event":"timeout"'*)
                    info "event=timeout"
                    sleep "${WT_PAUSE_AFTER_ERROR}"
                    ;;
                *'"event":"connection_lost"'*)
                    info "event=connection_lost"
                    sleep "${WT_PAUSE_AFTER_CONNECTION_LOST}"
                    event fire punch
                    ;;
                *'"event":"error"'*)
                    info "event=error"
                    sleep "${WT_PAUSE_AFTER_ERROR}"
                    ;;
                *)
                    info "event=${line}"
            esac
            ;;
        event)
            local event="${1}" && shift

            case "${event}" in
                new_peer_endpoint)
                    local peer_name="${1}" && shift
                    local endpoint="${1}" && shift
                    local local_port="${1}" && shift
                    local event_time="${1}" && shift
                    wirething set peer_endpoint "${peer_name}" "${endpoint}" "${event_time}"

                    if [ "${local_port}" != "0" ]
                    then
                        wirething set peer_local_port "${peer_name}" "${local_port}"
                    fi
                    ;;
                punch)
                    if wirething punch_host_endpoint
                    then
                        info "punch succeeded"
                        wirething broadcast_host_endpoint
                    else
                        info "punch failed"
                    fi
            esac
            ;;
        poll_encrypted_peer_endpoint)
            debug
            local peer_name="${1}" && shift
            local since="${1}" && shift

            {
                topic subscribe "${peer_name}"
            } | {
                read topic
                pubsub poll "${topic}" "${since}"
            }
            ;;
        on_new_peer_endpoint)
            debug
            local peer_name="${1}" && shift

            while read new_peer_endpoint
            do
                info "${new_peer_endpoint}"

                local current_peer_endpoint="$(wirething get peer_endpoint "${peer_name}")"

                if [[ "${new_peer_endpoint}" != "${current_peer_endpoint}" ]]
                then
                    wirething set peer_endpoint "${peer_name}" "${new_peer_endpoint}"
                fi
            done
            ;;
        ensure_host_endpoint_is_published)
            info
            local peer_name="${1}" && shift
            local since="all"

            {
                wirething poll_encrypted_host_endpoint "${peer_name}" "${since}"
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

                            read host_endpoint < <(wirething get host_endpoint)
                            read host_port < <(wirething get host_port)

                            if [ "${published_host_endpoint}" != "${host_endpoint} ${host_port}" ]
                            then
                                wirething publish_host_endpoint "${peer_name}"
                            fi
                        }
                esac
            }
            ;;
        fetch_peer_endpoint)
            debug
            local peer_name="${1}" && shift
            local since="${1}" && shift

            {
                wirething poll_encrypted_peer_endpoint "${peer_name}" "${since}"
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

                            if [ "${new_peer_endpoint}" != "" ]
                            then
                                echo "${new_peer_endpoint}"
                            fi
                        } | {
                            wirething on_new_peer_endpoint "${peer_name}"
                        }
                esac
            }
            ;;
    esac
}

# ui

function ui() {
    local action="${1}" && shift

    case "${action}" in
        init)
            info

            declare -g -A _ui_status_text=(
                ["empty"]="starting"
                ["start"]="starting"
                ["wait"]="waiting"
                ["offline"]="down"
                ["online"]="up"
                ["stop"]="stopped"
            )

            declare -g -A _ui_status_screen=(
                ["empty"]="🙏🏿"
                ["start"]="🙏🏿"
                ["wait"]="🙏🏿"
                ["offline"]="💔"
                ["online"]="💚"
                ["offline-local"]="🍎"
                ["online-local"]="🍏"
                ["offline-host"]="⛈️"
                ["online-host"]="🌈"
                ["stop"]="👋🏿"
            )

            _ui_last_status=""
            ;;
        before_status_changed)
            local device_name="${1}" && shift
            local new_status="${1}" && shift
            local previous_status="${1}" && shift
            local previous_status_timestamp="${1}" && shift

            if [ "${previous_status}" != "empty" ]
            then
                local previous_status_time="$((${EPOCHSECONDS} - ${previous_status_timestamp}))"
                local title="${device_name} is ${_ui_status_text[${new_status}]}"

                local formated_previous_status_time
                format_time "${previous_status_time}" var_name "formated_previous_status_time"
                local text="${_ui_status_text[${previous_status}]/ing/} time was ${formated_previous_status_time}"

                info "${title}, ${text}"

                os_ui log "${title}" "${text}"
            fi
            ;;
        after_status_changed)
            local host_status="$(host_state get_current_status)"

            case "${host_status}" in
                online|offline)
                    host_status+="-host"
                    ;;
            esac

            local group="wirething-host-status-${config["host_name"]}"
            local title="Wirething $(host_state get_host_state_text)"
            local text="${config["host_name"]} ${_ui_status_screen["${host_status}"]}  |  "

            local peer_status

            for _peer_name in ${config["peer_name_list"]}
            do
                peer_status="$(peer_state get_current_status "${_peer_name}")"

                case "${peer_status}" in
                    online|offline)
                        if interface get is_peer_local "${_peer_name}"
                        then
                            peer_status+="-local"
                        fi
                        ;;
                esac

                text+="${_peer_name} ${_ui_status_screen[${peer_status}]}  "
            done

            text="${text%  }"

            debug "${title} ${group}"
            debug "${text}"

            if [ "${title} ${text} ${group}" != "${_ui_last_status}" ]
            then
                os_ui status "${title}" "${text}" "${group}"
                _ui_last_status="${title} ${text} ${group}"
            fi
            ;;
    esac
}

# host status usecase

function host_context() {
    local action="${1}" && shift

    case "${action}" in
        set)
            log_prefix="${config["host_log_prefix"]}"
            ;;
        unset)
            log_prefix=""
            ;;
    esac
}

function host_state() {
    local action="${1}" && shift

    case "${action}" in
        init)
            info

            declare -g -A _host_event_transitions=(
                ["host_empty_start"]="on_host_start"
                ["host_start_wait"]=""
                ["host_wait_offline"]="on_host_offline"
                ["host_wait_online"]=""
                ["host_online_offline"]="on_host_offline"
                ["host_offline_online"]="on_host_online"
                ["host_wait_stop"]="on_host_stop"
                ["host_online_stop"]="on_host_stop"
                ["host_offline_stop"]="on_host_stop"
            )

            declare -g -A _host_status_transitions=(
                ["host_empty_start"]="start"
                ["host_start_wait"]="wait"
                ["host_wait_offline"]="offline"
                ["host_wait_online"]="online"
                ["host_online_offline"]="offline"
                ["host_offline_online"]="online"
                ["host_wait_stop"]="stop"
                ["host_online_stop"]="stop"
                ["host_offline_stop"]="stop"
            )

            declare -g -A _host_state

            host_state set_current_status "empty"
            ;;
        start_host)
            info

            host_state set_polled_status "start"

            host_state transition

            host_state set_polled_status "wait"
            ;;
        stop_host)
            info

            if [[ ! -v _host_state["current_status"] ]]
            then
                return 0
            fi

            case "${_host_state["current_status"]}" in
                empty|start)
                    return 0
                    ;;
            esac

            host_state set_polled_status "stop"

            host_state transition
            ;;
        transition)
            local host_name="${config["host_name"]}"

            local current_status="${_host_state["current_status"]}"
            local polled_status="${_host_state["polled_status"]}"

            if [[ "${current_status}" == "${polled_status}" ]]
            then
                return 0
            fi

            local transition="host_${current_status}_${polled_status}"

            trace "${transition}"

            local new_event="${_host_event_transitions["${transition}"]}"

            host on_event "${new_event}" "${host_name}"

            local new_status="${_host_status_transitions["${transition}"]}"

            case "${new_status}" in
                start|wait|offline|online|stop)
                    ui before_status_changed "${host_name}" "${new_status}" "${current_status}" \
                        "${_host_state["current_status_timestamp"]}"

                    host_state set_current_status "${new_status}"

                    ui after_status_changed
                    ;;
            esac
            ;;
        get_host_state_text)
            if ! sys is_running && [ "${_host_state["current_status"]}" != "stop" ]
            then
                echo "is stopping"
            else
                echo "${_host_state["state_text"]}"
            fi
            ;;
        get_current_status)
            echo "${_host_state["current_status"]:-start}"
            ;;
        set_current_status)
            local status="${1}" && shift

            _host_state["current_status_timestamp"]="${EPOCHSECONDS}"
            _host_state["current_status"]="${status}"

            case "${status}" in
                empty|start)
                    _host_state["state_text"]="is starting"
                    ;;
                stop)
                    _host_state["state_text"]="was shutdown"
                    ;;
                *)
                    _host_state["state_text"]="is running"
                    ;;
            esac
            ;;
        set_polled_status)
            local status="${1}" && shift

            _host_state["polled_status"]="${status}"
            ;;
    esac
}

function host_task() {
    local action="${1}" && shift

    case "${action}" in
        ensure_host_endpoint_is_published)
            host_context set

            info

            local status="online"

            if [ "$(pubsub status)" == "offline" ]
            then
                info "pubsub status: offline"
                status="offline"
            else
                read host_endpoint < <(wirething get host_endpoint)
                read host_port < <(wirething get host_port)

                local new_punch="failed"

                if wirething punch_host_endpoint
                then
                    new_punch="success"
                fi

                if [[ "${host_port}" != "0" && "${host_port}" != "" && "${host_endpoint}" != "" ]] &&
                    punch status "${host_port}" "${host_endpoint}"
                then
                    wirething set host_endpoint "${host_endpoint}"
                    wirething set host_port "${host_port}"
                else
                    info "punch status: offline"
                    status="offline"

                    if [ "${new_punch}" == "success" ]
                    then
                        wirething broadcast_host_endpoint
                        status="online"
                    else
                        wirething set host_endpoint "${host_endpoint}"
                        wirething set host_port "${host_port}"
                    fi
                fi
            fi

            host_context unset
            ;;
        register)
            local task="${1}" && shift

            case "${task}" in
                host_ensure_host_endpoint)
                    tasks register name "host_ensure_host_endpoint" \
                        frequency "${WT_HOST_OFFLINE_ENSURE_INTERVAL}" \
                        start now \
                        stop never \
                        task "host_task ensure_host_endpoint_is_published"
                    ;;
            esac
            ;;
        unregister)
            local task="${1}" && shift

            case "${task}" in
                host_ensure_host_endpoint)
                    tasks unregister name "host_ensure_host_endpoint"
                    ;;
            esac
    esac
}

function host() {
    local action="${1}" && shift

    case "${action}" in
        deps)
            :
            ;;
        init)
            info
            WT_HOST_OFFLINE_START_DELAY="${WT_HOST_OFFLINE_START_DELAY:-20}" # 20 seconds
            WT_HOST_OFFLINE_PULL_STATUS_INTERVAL="${WT_HOST_OFFLINE_PULL_STATUS_INTERVAL:-30}" # 30 seconds
            WT_HOST_OFFLINE_ENSURE_INTERVAL="${WT_HOST_OFFLINE_ENSURE_INTERVAL:-600}" # 10 minute

            host_context init
            host_state init
            ;;
        start)
            info

            host_state start_host
            ;;
        stop)
            info

            host_state stop_host
            ;;
        poll_status)
            host_context set

            local status

            interface get host_status var_name "status"

            debug "${status}"

            host_state set_polled_status "${status}"

            host_context unset
            ;;
        on_event)
            local new_event="${1}" && shift
            local host_name="${1}" && shift

            case "${new_event}" in
                on_host_start)
                    info "${new_event}"

                    tasks register name "host_poll_status" \
                        frequency "${WT_HOST_OFFLINE_PULL_STATUS_INTERVAL}" \
                        start "+${WT_HOST_OFFLINE_START_DELAY}" \
                        stop never \
                        task "host poll_status"
                    ;;
                on_host_stop)
                    info "${new_event}"

                    tasks unregister name "host_poll_status"
                    ;;
                on_host_offline)
                    info "${new_event}"

                    host_task register "host_ensure_host_endpoint"
                    ;;
                on_host_online)
                    info "${new_event}"

                    host_task unregister "host_ensure_host_endpoint"
                    ;;
            esac
            ;;
        run)
            host_context set

            host_state transition

            host_context unset
            ;;
    esac
}

# peer

function peer_context() {
    local action="${1}" && shift

    case "${action}" in
        set)
            local peer_name="${1}" && shift

            log_prefix="${config["peer_log_prefix_${peer_name}"]}"
            ;;
        unset)
            log_prefix=""
            ;;
    esac
}

function peer_state() {
    local action="${1}" && shift

    case "${action}" in
        init)
            info

            declare -g -A _peer_event_transitions=(
                ["peer_empty_start"]="on_peer_start"
                ["peer_start_wait"]=""
                ["peer_start_offline"]="on_peer_offline"
                ["peer_start_online"]=""
                ["peer_wait_offline"]="on_peer_offline"
                ["peer_wait_online"]=""
                ["peer_online_offline"]="on_peer_offline"
                ["peer_offline_online"]="on_peer_online"
                ["peer_wait_stop"]="on_peer_stop"
                ["peer_online_stop"]="on_peer_stop"
                ["peer_offline_stop"]="on_peer_stop"
            )

            declare -g -A _peer_status_transitions=(
                ["peer_empty_start"]="start"
                ["peer_start_wait"]="wait"
                ["peer_start_offline"]="offline"
                ["peer_start_online"]="online"
                ["peer_wait_offline"]="offline"
                ["peer_wait_online"]="online"
                ["peer_online_offline"]="offline"
                ["peer_offline_online"]="online"
                ["peer_wait_stop"]="stop"
                ["peer_online_stop"]="stop"
                ["peer_offline_stop"]="stop"
            )

            declare -g -A _peer_state
            ;;
        start_peer)
            local peer_name="${1}" && shift
            info "${peer_name}"

            peer_state set_current_status "${peer_name}" "empty"
            peer_state set_polled_status "${peer_name}" "start"

            peer_state transition "${peer_name}"

            peer_state set_polled_status "${peer_name}" "wait"
            ;;
        stop_peer)
            local peer_name="${1}" && shift
            info "${peer_name}"

            if [[ ! -v _peer_state["current_status_${peer_name}"] ]]
            then
                return 0
            fi

            case "${_peer_state["current_status_${peer_name}"]}" in
                empty|start)
                    return 0
                    ;;
            esac

            peer_state set_polled_status "${peer_name}" "stop"

            peer_state transition "${peer_name}"
            ;;
        transition)
            local peer_name="${1}" && shift

            local current_status="${_peer_state["current_status_${peer_name}"]}"
            local polled_status="${_peer_state["polled_status_${peer_name}"]}"

            if [[ "${current_status}" == "${polled_status}" ]]
            then
                return 0
            fi

            local transition="peer_${current_status}_${polled_status}"

            trace "${transition}"

            local new_event="${_peer_event_transitions["${transition}"]}"

            peer on_event "${new_event}" "${peer_name}"

            local new_status="${_peer_status_transitions["${transition}"]}"

            case "${new_status}" in
                offline|online|stop)
                    ui before_status_changed "${peer_name}" "${new_status}" "${current_status}" \
                        "${_peer_state["current_status_timestamp_${peer_name}"]}"
                    ;;
            esac

            case "${new_status}" in
                start|wait|offline|online|stop)
                    peer_state set_current_status "${peer_name}" "${new_status}"

                    ui after_status_changed
                    ;;
            esac
            ;;
        get_current_status)
            local peer_name="${1}" && shift
            echo "${_peer_state["current_status_${peer_name}"]:-start}"
            ;;
        set_current_status)
            local peer_name="${1}" && shift
            local status="${1}" && shift

            _peer_state["current_status_timestamp_${peer_name}"]="${EPOCHSECONDS}"
            _peer_state["current_status_${peer_name}"]="${status}"
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
        fetch_peer_endpoint_since_all)
            local peer_name="${1}" && shift

            peer_context set "${peer_name}"

            info "${peer_name}"
            wirething fetch_peer_endpoint "${peer_name}" "all" || true

            peer_context unset
            ;;
        fetch_peer_endpoint)
            local peer_name="${1}" && shift

            peer_context set "${peer_name}"

            info "${peer_name}"
            wirething fetch_peer_endpoint "${peer_name}" "${WT_PEER_OFFLINE_FETCH_SINCE}s" || true

            peer_context unset
            ;;
        ensure_host_endpoint_is_published)
            local peer_name="${1}" && shift

            peer_context set "${peer_name}"

            info "${peer_name}"
            wirething ensure_host_endpoint_is_published "${peer_name}" || true

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
            :
            ;;
        init)
            info
            WT_PEER_OFFLINE_START_DELAY="${WT_PEER_OFFLINE_START_DELAY:-5}" # 10 seconds
            WT_PEER_OFFLINE_FETCH_SINCE="${WT_PEER_OFFLINE_FETCH_SINCE:-60}" # 1 minute
            WT_PEER_OFFLINE_PULL_STATUS_INTERVAL="${WT_PEER_OFFLINE_PULL_STATUS_INTERVAL:-30}" # 30 seconds
            WT_PEER_OFFLINE_FETCH_INTERVAL="${WT_PEER_OFFLINE_FETCH_INTERVAL:-45}" # 45 seconds
            WT_PEER_OFFLINE_ENSURE_INTERVAL="${WT_PEER_OFFLINE_ENSURE_INTERVAL:-900}" # 15 minutes

            peer_context init
            peer_state init
            ;;
        start)
            info

            for _peer_name in ${config["peer_name_list"]}
            do
                peer_state start_peer "${_peer_name}"
            done
            ;;
        stop)
            info

            if [[ ! -v config["peer_name_list"] ]]
            then
                return 0
            fi

            for _peer_name in ${config["peer_name_list"]}
            do
                peer_state stop_peer "${_peer_name}"
            done
            ;;
        poll_status)
            local peer_name="${1}" && shift

            peer_context set "${peer_name}"

            local status

            interface get peer_status "${peer_name}" var_name "status"

            debug "${peer_name} ${status}"

            peer_state set_polled_status "${peer_name}" "${status}"

            peer_context unset
            ;;
        on_event)
            local new_event="${1}" && shift
            local peer_name="${1}" && shift

            case "${new_event}" in
                on_peer_start)
                    info "${new_event}"

                    if ! interface get generates_status_events
                    then
                        tasks register name "peer_poll_status_${peer_name}" \
                            frequency "${WT_PEER_OFFLINE_PULL_STATUS_INTERVAL}" \
                            start "+${WT_PEER_OFFLINE_START_DELAY}" \
                            stop never \
                            task "peer poll_status ${peer_name}"
                    fi
                    ;;
                on_peer_stop)
                    info "${new_event}"

                    if ! interface get generates_status_events
                    then
                        tasks unregister name "peer_poll_status_${peer_name}"
                    fi
                    ;;
                on_peer_offline)
                    info "${new_event}"

                    peer_task register "peer_ensure_host_endpoint" "${peer_name}"
                    ;;
                on_peer_online)
                    info "${new_event}"

                    peer_task unregister "peer_ensure_host_endpoint" "${peer_name}"
                    ;;
            esac
            ;;
        run)
            for _peer_name in ${config["peer_name_list"]}
            do
                peer_context set "${_peer_name}"

                peer_state transition "${_peer_name}"

                peer_context unset
            done
            ;;
    esac
}

# wirething main

function wirething_main() {
    local action="${1}" && shift

    case "${action}" in
        deps)
            local option="${1}" && shift

            {
                echo "mkdir rm sed sort uniq wc"

                os deps
                sys deps
                log deps

                udp deps
                # event deps
                tasks deps

                config deps

                wireproxy_interface deps
                ntfy_pubsub deps
                gpg_ephemeral_encryption deps
                totp_topic deps

                wirething deps
                host deps
                peer deps

                # Optional

                os optional

                wg_interface deps
                wg_quick_interface deps
                # wg_quick_interface: wg_interface

                udphole_punch deps
                # udphole_punch: udp

                # stun_punch deps # TODO: optional

            } | sed "s, ,\n,g" | sort | uniq | {
                while read dep
                do
                    case "${option}" in
                        check)
                            if ! type -P "${dep}" >&${null}
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

            WT_PID="${OS_PID}"

            WT_CONFIG_PATH="${WT_CONFIG_PATH:-${PWD}}"
            WT_STATE_PATH="${WT_CONFIG_PATH}/state"
            WT_ERROR_PATH="${WT_CONFIG_PATH}/error"
            WT_LOG_PATH="${WT_CONFIG_PATH}/log"

            if sys is_root
            then
                WT_RUN_PATH="${WT_RUN_PATH:-/var/run/wirething}"
            else
                WT_RUN_PATH="${WT_RUN_PATH:-${WT_CONFIG_PATH}/run}"
            fi

            WT_EPHEMERAL_PATH="${WT_RUN_PATH}/${WT_PID}"
            WT_PAUSE_AFTER_ERROR="${WT_PAUSE_AFTER_ERROR:-30}" # 30 seconds
            WT_PAUSE_AFTER_CONNECTION_LOST="${WT_PAUSE_AFTER_CONNECTION_LOST:-10}" # 10 seconds

            WT_TMP_PATH="${WT_EPHEMERAL_PATH}/tmp"

            info "WT_PID=${WT_PID}"

            wirething_main deps check

            sys set_error_path "${WT_ERROR_PATH}"
            sys set_log_path "${WT_LOG_PATH}"
            sys set_tmp_path "${WT_TMP_PATH}"
            sys set_on_exit "wirething_main down"
            sys start

            config init
            event init
            tasks init

            interface init
            punch init
            pubsub init
            encryption init
            topic init

            wirething init
            ui init
            host init
            peer init
            ;;
        up)
            info

            mkdir -p "${WT_STATE_PATH}"
            mkdir -p "${WT_ERROR_PATH}"
            mkdir -p "${WT_LOG_PATH}"
            mkdir -p "${WT_TMP_PATH}"
            mkdir -p "${WT_EPHEMERAL_PATH}"

            config up
            event up

            interface up

            # punch up
            # pubsub up
            encryption up
            # topic up

            wirething up
            wirething up_host

            for _peer_name in ${config["peer_name_list"]}
            do
                wirething up_peer "${_peer_name}"
            done

            peer start
            host start
            ;;
        down)
            info

            peer stop
            host stop

            wirething down || true

            # topic down || true
            encryption down || true
            # pubsub down || true
            # punch down || true
            interface down || true

            event down || true

            if [[ ! -v WT_EPHEMERAL_PATH ]]
            then
                info "WT_EPHEMERAL_PATH was not set"
                return 0
            fi

            if rm -rf "${WT_EPHEMERAL_PATH}"
            then
                info "'${WT_EPHEMERAL_PATH}' was successfully deleted"
            else
                error "'${WT_EPHEMERAL_PATH}' delete error"
            fi

            wait
            info "exiting..."
            ;;
        loop)
            info "start"

            while sys is_running
            do
                if ! sys sleep 5
                then
                    break
                fi

                event run
                peer run
                host run
                tasks run
            done

            info "end"
            ;;
    esac
}

# main

function main() {
    wirething_main init
    wirething_main up
    wirething_main loop
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
