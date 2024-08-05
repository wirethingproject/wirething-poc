# svc

function svc() {
    local action="${1}" && shift

    case "${action}" in
        deps)
            :
            ;;
        init)
            ;;
        mod)
            local mod_action="${1}" && shift

            local _svc_module="${FUNCNAME[1]}"

            info "${mod_action}"

            case "${mod_action}" in
                init)
                    :
                    ;;
                *)
                    error "Invalid mod action"
                    ;;
            esac
            ;;
        "${_svc_module}")
            action="${_svc_module}" info "${@} ${_svc_current_state}"

            "${_svc_module}" "${@}"
            ;;
        set)
            # set PID
            ;;
        signal|event)
            # kill
            ;;
        *)
            error "Invalid action"
            ;;
    esac
}

# svc_transitions

function svc_transitions() {
    local action="${1}" && shift

    case "${action}" in
        deps)
            :
            ;;
        init)
            info

            declare -g -a _svc_state_list=(
                "initial"
                "starting"
                "running"
                "stopping"
                "stopped"
                "reloading"
                "exiting"
                "terminating"
                "terminated"
            )

            declare -g -a _svc_event_list=(
                "start"
                "started"
                "stop"
                "stopped"
                "reload"
                "reloaded"
                "exit"
                "shutdown"
            )

            declare -g -A _svc_transitions=(
                ["initial_start"]="starting"
                ["starting_started"]="running"
                ["starting_exit"]="exiting"
                ["running_stop"]="stopping"
                ["running_reload"]="reloading"
                ["running_exit"]="exiting"
                ["stopping_stopped"]="stopped"
                ["stopped_start"]="starting"
                ["reloading_reloaded"]="running"
                ["reloading_exit"]="exiting"
                ["exiting_stopped"]="stopped"
                ["initial_shutdown"]="terminating"
                ["starting_shutdown"]="terminating"
                ["running_shutdown"]="terminating"
                ["stopping_shutdown"]="terminating"
                ["stopped_shutdown"]="terminating"
                ["exiting_shutdown"]="terminating"
                ["terminating_shutdown"]="noop"
                ["terminated_shutdown"]="noop"
                ["terminating_terminated"]="terminated"
            )

            for state in ${_svc_state_list[@]}
            do
                for event in ${_svc_event_list[@]}
                do
                    if [[ ! -v _svc_transitions["${state}_${event}"] ]]
                    then
                        _svc_transitions["${state}_${event}"]="noop"
                    fi
                done
            done
            ;;
        up)
            info

            declare -r -g -a _svc_state_list
            declare -r -g -a _svc_event_list
            declare -r -g -A _svc_transitions
            ;;
    esac
}

# svc_run

function svc_run() {
    local action="${1}" && shift

    case "${action}" in
        deps)
            :
            ;;
        init)
            info

            _svc_module="${FUNCNAME[1]}"
            _svc_current_state="initial"

            trap "svc_run start"    "SIGUSR1"
            trap "svc_run stop"     "SIGUSR2"
            trap "svc_run reload"   "SIGHUP"
            trap "svc_run shutdown" "SIGTERM"

            if [[ -v _svc_on_exit ]]
            then
                trap "${_svc_on_exit}" "EXIT"
            else
                error "'svn_run set on_exit' was not called"
                # TODO sys terminate
            fi
            ;;
        terminate)
            info

            trap "" SIGUSR1
            trap "" SIGUSR2
            trap "" SIGTERM
            trap "" SIGHUP
            ;;
        start|started|stop|stopped|reload|reloaded|exit|shutdown|terminated)
            local new_state="${_svc_transitions["${_svc_current_state}_${action}"]:-}"

            info "[${_svc_module}] ${_svc_current_state} > ${new_state:-invalid}"

            case "${new_state}" in
                starting|running|stopping|stopped|reloading|reloaded|exiting|terminating|terminated)
                    _svc_current_state="${new_state}"
                    ;;
                noop)
                    error "NOOP transition from ${_svc_current_state} to ${new_state:-''}"
                    ;;
                *)
                    error "Invalid transition from ${_svc_current_state} to ${new_state:-''}"
                    ;;
            esac
            ;;
        idle)
            local seconds="${1}"
            # TODO use exec/read as sleep
            sleep "${seconds}"
            ;;
        set)
            local key="${1}" && shift
            local value="${1}"

            case "${key}" in
                on_exit)
                    _svc_on_exit="${value}"
                    ;;
                *)
                    error "Invalid key '${key}'"
                    ;;
            esac
            ;;
        get)
            local key="${1}" && shift
            shift # on
            local variable="${1}"

            case "${key}" in
                state)
                    read -N "${#_svc_current_state}" "${variable}" <<<"${_svc_current_state}"
                    ;;
                *)
                    error "Invalid key '${key}'"
                    ;;
            esac
            ;;
        *)
            error "Invalid action"
            ;;
    esac
}


