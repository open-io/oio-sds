#!/bin/bash
#set -x

systemctl="systemctl --no-pager --user"
systemd_dir="$HOME/.config/systemd/user"
if [ -v OIO_SYSTEMD_SYSTEM ]; then
    systemctl="systemctl --no-pager"
    systemd_dir="/etc/systemd/system"
    # force to run as root
    [ $(id -u) -ne 0 ] && exec sudo $0 "$@"
fi

groups=()
services=()
use_colour=0

function get_hash {
    echo "$1" | sha512sum | cut -c-8
}

function usage {
    echo "Query or send control commands to the system manager."
    echo
    echo "Syntax: $0 [-h|c] (status{,2,3}|start|stop|reload|repair) [IDS...]"
    echo "options:"
    echo "h     Print this help."
    echo "c     Activate coloured output."
    echo
    echo "command:"
    echo "status* : Displays the status of the given processes or groups"
    echo "start   : Starts the given processes or groups, even if broken"
    echo "kill    : Stops the given processes or groups, they won't be automatically"
    echo "          restarted even after a configuration reload"
    echo "stop    : Calls 'kill' until the children exit"
    echo "restart : Restarts the given processes or groups"
    echo "reload  : Reloads the configuration, stopping obsolete processes, starting"
    echo "          the newly discovered. Broken or stopped processes are not restarted"
    echo "repair  : Removes the broken flag set on a process. Start must be called to"
    echo "          restart the process."
    echo "with ID the key of a process, or '@GROUP', with GROUP the name of a process group"
}

# List all openio services and manage groups
for service_file in $systemd_dir/*.service; do
    [ -f "$service_file" ] || continue
    service="${service_file##*/}"
    service="${service%.service}"

    oio_groups="$(awk -F'=' '/^OioGroup=/{print $2}' $service_file)"
    [ -z "$oio_groups" ] && continue
    IFS=',' read -ra oio_groups <<< "$oio_groups"

    services+=( $service )
    service_hash=$(get_hash "$service")
    eval "service_${service_hash}=()"


    # extract group from service file
    # as it is not systemctl standard, let's use comments
    # do not use `awk ... | while read i`: because of the pipe
    # the while loop would be executed in a subshell and any variable
    # assignation would be useless (kind of out of scope)
    for group in "${oio_groups[@]}"; do
        [ -z "$group" ] && continue
        group_hash=$(get_hash "$group")
        add_group=1
        for i in "${groups[@]}"; do
            if [ "$i" == "$group_hash" ]; then
                add_group=0
                break
            fi
        done
        if [ $add_group -eq 1 ]; then
            groups+=( $group )
        fi
        eval "group_$group_hash+=( $service )"
        eval "service_${service_hash}+=( $group )"
    done
done

while getopts "hc" option; do
   case $option in
        h) # display Help
            usage
            exit;;
        c) # activate colour output
            use_colour=1
            ;;
        \?) # Invalid option
            echo "Error: Invalid option"
            usage
            exit;;
   esac
done
shift $((OPTIND-1))

if [ ${#services[@]} -eq 0 ]; then
    echo "Error no services found from $systemd_dir" >/dev/stderr
    exit 1
fi

# ensure the action is not missing
if [ $# -lt 1 ]; then
    usage
    exit 1
fi
action=$1
shift

# if there are no services in parameters, let's assume to set action to all services
# WARNING maybe this would require a force flag or something to prevent doing crappy stuff
if [ $# -lt 1 ]; then
    do_services=( ${services[@]} )
else
    do_services=()
    for service in "$@"; do
        # if service name start with @ it means it's a group name rather than a service name
        if [ "${service:0:1}" == "@" ]; then
            group=${service:1}
            group_hash=$(get_hash "$group")
            group_var="group_$group_hash"
            if [ -z "${!group_var}" ]; then
                echo "Error: group @$group does not exist"
                exit 1
            fi
            tmp=${group_var}[@]
            do_services+=( ${!tmp} )
            continue
        else
            service_hash=$(get_hash "$service")
            service_var="service_${service_hash}"
            if [ -z "${!service_var}" ]; then
                echo "Error: service \"$service\" not found"
                exit 1
            fi
            do_services+=( $service )
        fi
    done
fi

# remove duplicates in do_services
do_services=$(printf "%s\n" "${do_services[@]}" | sort -u)

# function to join element of array
function join_by {
    local d=$1
    shift
    local f=$1
    shift
    printf %s "$f" "${@/#/$d}"
}

# retrieve service status
get_status() {
    service=$1
    _ACTIVE=$($systemctl show ${service}.service -p ActiveState --value)

    if [ "$_ACTIVE" != "active" ]; then
        _STATUS="$_ACTIVE"
    else
        _STATUS=$($systemctl show ${service}.service -p SubState --value)
    fi

    if [ "$use_colour" -eq 1 ]; then
        GREEN=$'\e[1;32m'
        RED=$'\e[1;31m'
        GRAY=$'\e[1;37m'
        NC=$'\e[0m'
        case "$_STATUS" in
            active) _STATUS=$"${GREEN}$_STATUS${NC}";;
            failed) _STATUS="${RED}$_STATUS${NC}";;
            inactive) _STATUS=$"${GRAY}$_STATUS${NC}";;
        esac
    fi
    echo "$_STATUS"
}

#
# show status as gridinit would do
#
# KEY                      STATUS      PID GROUP
# OPENIO-conscienceagent-0 BROKEN       -1 OPENIO,conscienceagent,0
# OPENIO-grafana-0         UP       144084 OPENIO,grafana,0
action_status() {
    echo "KEY§STATUS§PID§GROUP"
    for service in $do_services; do
        _PID=$($systemctl show ${service}.service -p MainPID --value)
        service_hash=$(get_hash "$service")
        service_var="service_${service_hash}"
        tmp=${service_var}[@]
        _GROUPS="$(join_by , "${!tmp}")"
        _STATUS="$(get_status "$service")"
        echo "$service§$_STATUS§$_PID§${_GROUPS:- }"
    done
}

#
# show status2 as gridinit would do
#
# KEY                      STATUS     PID #START #DIED               SINCE                    GROUP CMD
# OPENIO-conscienceagent-0 BROKEN      -1     18    13 2020-12-31 09:34:04 OPENIO,conscienceagent,0 /usr/bin/oio-conscience-agent /etc/oio/OPENIO/conscienceagent-0/conscienceagent-0.yml
action_status2() {
    echo "KEY§STATUS§PID§#RESTART§SINCE§GROUP§CMD"
    for service in $do_services; do
        _PID=$($systemctl show ${service}.service -p MainPID --value)
        service_var="service_${service//[^0-9a-zA-Z_]/}"
        tmp=${service_var}[@]
        _GROUPS="$(join_by , "${!tmp}")"
        _STATUS="$(get_status "$service")"
        _SINCE=$($systemctl show ${service}.service -p ExecMainStartTimestamp --value)
        _RESTART=$($systemctl show ${service}.service -p NRestarts --value)
        file=$($systemctl show ${service}.service -p FragmentPath --value)
        _CMD=$(awk '/^ExecStart=/{gsub(/^ExecStart=/,"");print}' $file)

        echo "$service§$_STATUS§$_PID§$_RESTART§$_SINCE§${_GROUPS:- }§$_CMD"
    done
}

#
# show systemctl status
#
action_fullstatus() {
    for service in $do_services; do
        echo
        printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | sed -e 's/^./┏/' -e 's/ /━/g'
        script -q -c "$systemctl status -n 0 ${service}.service" /dev/null | sed -e 's/^/┃ /'
        printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | sed -e 's/^./┗/' -e 's/ /━/g'
    done
}

#
# generic systemctl action
#
action_generic() {
    action="$1"
    echo "KEY§RET§STATUS§PID"
    for service in $do_services; do
        $systemctl $action ${service}.service
        _RET=$?
        _STATUS="$(get_status "$service")"
        _PID=$($systemctl show ${service}.service -p MainPID --value)
        echo "$service§$_RET§$_STATUS§$_PID"
    done
}

#
# generic systemctl action
#
action_list_services() {
    for service in $do_services; do
        echo $service
    done
}

#
# Main switch
#
case "$action" in
    status)
        action_status | column -t -s '§'
        ;;
    status2)
        action_status2 | column -t -s '§'
        ;;
    full|fullstatus)
        action_fullstatus
        ;;
    start)
        action_generic "start" | column -t -s '§'
        ;;
    stop)
        action_generic "stop" | column -t -s '§'
        ;;
    restart)
        action_generic "restart" | column -t -s '§'
        ;;
    reload)
        action_generic "reload" | column -t -s '§'
        ;;
    list-services)
        action_list_services
        ;;
    *)
        echo "Error: command unknown"
        exit 1
        ;;
esac