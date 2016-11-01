#! /bin/bash

# A script monitoring useractivity
# inspired by https://github.com/murukeshm/scratchpad/tree/master/linux/idlekiller

# kill user-sessions if they idle and start docker-containers if
# all are idleing and no one is active

# Width of username column in w's output
export PROCPS_USERLEN=32

IDLE=$((20*60))	# 20 minutes
GRACE=10m			# 10 minutes
TIMEOUT=5s
# set to 1 to kill processes of idle users
KILL_IDLE=0

# The Docker-container to stop or start
# leave empty for doing nothing
DOCKER_CONTAINER=

IDLE_MESSAGE="You have been idle for more than $(($IDLE / 60)) minutes. \
You will be logged out in $GRACE if no activity is detected."

[ -f /etc/default/idlekiller ] && . /etc/default/idlekiller

declare -gA watched_users
declare -gA idle_time
declare -gA idle_seat

# Log to syslog with tag "IDLEKILLER"
log ()
{
	logger -t "IDLEKILLER" -i -- "$@"
}

# converts a time expression to seconds
convert_to_seconds ()
{
	local timeexp=$1
	case $timeexp in
		*days)
			awk '{print $1*86400}' <<< ${idle%days}
			;;
		*s)
			awk -F'.' '{print $1}' <<<${idle%s}
			;;
		*m)
			awk -F':' '{print $1*60*60 + $2*60}' <<<${idle%m}
			;;
		*:*)
			awk -F':' '{print $1*60 + $2}' <<<${idle}
			;;
		*)
			echo $(($IDLE - 1))
	esac
}

# For a console user, `w` prints IDLE time in as:
# "DDdays, HH:MMm, MM:SS or SS.CC if the times are
# greater than 2 days, 1hour, or 1 minute respectively."
# For the X session, `w` reports an IDLE time of ?xdm?,
# so we use the `xprintidle` command, which returns idle
# time in milliseconds. We convert all this to seconds.
parse_idle ()
{
	local user=$1
	local tty=$2 # don't need the tty but that's the format of "w -hs"
	local seat=$3
	local idle=$4

	if [[ $seat =~ :[0-9]+ ]]
	then
		xidle=$(/usr/bin/sudo -u $user DISPLAY=$seat xprintidle)
		echo $(($xidle / 1000))
	else
		echo $(convert_to_seconds $idle)
	fi
}

# Given an idle user and session, notify the user in *that session*
# and go to sleep for the grace period. Then check if the user had
# made any activity in *that session*. If not, kill them all.
grace ()
{
	local user=$1
	local seat=$2
	local idle=$3

	notify_user $user $seat $idle
	# we could simply do a "sleep $GRACE"
	# but we want to get the user out of the wartched_users array as
	# fast as possible because we might want to stop the idle-processes
	COUNTER=0
	GRACESECONDS=$(convert_to_seconds $GRACE)
  while [[ $COUNTER -lt $GRACESECONDS ]]; do
    let COUNTER=COUNTER+1
		new_idle=$(parse_idle $(w -hs $user | awk '{if ($3 == "'$seat'"){print}}'))
		if [[ $new_idle -lt $IDLE ]]; then
			echo " --> User $user get active again"
			break
		fi
		sleep 1
  done

	# Get the new idle time for this session.
	new_idle=$(parse_idle $(w -hs $user | awk '{if ($3 == "'$seat'"){print}}'))
	if [[ $new_idle -gt $IDLE ]]
	then
		# For root, special considerations. :)
		if [[ $user == root ]]
		then
			if [[ $seat =~ :[0-9]+ ]]
			then
				if [[ $KILL_IDLE == 1 ]]; then
					DISPLAY=$seat gnome-session-quit --logout --no-prompt
				fi
			else
				if [[ $KILL_IDLE == 1 ]]; then
					pkill -u $user -t $seat
				fi
			fi
		else
			# Everyone else can die.
			if [[ $KILL_IDLE == 1 ]]; then
				echo " --> killing processes from $user"
				pkill -KILL -u $user
			else
				echo " --> not killing processes from $user"
			fi
		fi


	fi
	echo " --> Idle session of $user at $seat has been terminated."
}

# Use `notify-send` for the GUI and `write` for the TTYs.
notify_user ()
{
	local user=$1
	local seat=$2
	local idle=$3

	if [[ $seat =~ :[0-9]+ ]]
	then
		/usr/bin/sudo -u $user DISPLAY=$seat \
			notify-send --urgency critical "$IDLE_MESSAGE"
	else
		write $user $pts <<< "$IDLE_MESSAGE"
	fi
	log "Notifying $user at $seat."
}

start_idle_job ()
{
	if [[ -n $DOCKER_CONTAINER ]]; then
		# defines what to do if all users are ideling
		RUNNING=$(docker inspect --format="{{ .State.Running }}" $DOCKER_CONTAINER 2> /dev/null)
		if [ $? -eq 1 ]; then
	  	echo "UNKNOWN - $DOCKER_CONTAINER does not exist."
		fi
		if [ "$RUNNING" == "false" ]; then
	  	echo " --> $DOCKER_CONTAINER is not running, starting up ..."
	  	docker start $DOCKER_CONTAINER
		fi
	fi
}

stop_idle_job ()
{
	if [[ -n $DOCKER_CONTAINER ]]; then
		# defines what to do if all users are ideling
		RUNNING=$(docker inspect --format="{{ .State.Running }}" $DOCKER_CONTAINER 2> /dev/null)
		if [ $? -eq 1 ]; then
	  	echo "UNKNOWN - $DOCKER_CONTAINER does not exist."
		fi
		if [ "$RUNNING" == "true" ]; then
	  	echo " --> $DOCKER_CONTAINER is running, shutting down in 10 seconds ..."
			sleep 10 && docker stop $DOCKER_CONTAINER &
			while kill -0 $! 2> /dev/null; do
	    	printf '.' > /dev/tty
	    sleep 2
			done
		fi
	fi
}

while sleep $TIMEOUT # Loop indefinitely.
do
	# If the terminal is a pts (pseudo-terminal), then the user is
	# actually logged in from either X, or from SSH. We will leave
	# SSH sessions alone (to be handled by SSHD configuration, and
	# only look at TTY sessions and X sessions.

	while read user tty seat w_idle what
	do
		# If the user has already been recorded as idle, continue.
		[[ -n ${watched_users["$user"]} ]] && continue

		idle=$(parse_idle $user $tty $seat $w_idle)
		[[ -z ${idle_time["$user"]} ]] && idle_time["$user"]=$idle

		# Store the smallest idle time for each user.
		if [[ $idle -le ${idle_time["$user"]} ]]
		then
			idle_time["$user"]=$idle
			idle_seat["$user"]=$seat
		fi
	done < <(w -hs | grep -v pts)

	echo Idle users: ${!watched_users[@]}

	# Loop over the minimum idle time of each user
	at_least_one_user_active=0
	for user in "${!idle_time[@]}"
	do
		idle=${idle_time["$user"]}
		seat=${idle_seat["$user"]}
		unset -v idle_seat["$user"]
		unset -v idle_time["$user"]
		# If the user has already been recorded as idle, continue.
		[[ -n ${watched_users["$user"]} ]] && continue

		if [[ $idle -gt $IDLE ]]
		then
			grace $user $seat $idle &
			watched_users["$user"]=$!
			echo " --> $user has been idle for over $idle seconds - kill job: " ${watched_users["$user"]}
		else
			echo "Non idle user: $user"
			at_least_one_user_active=1
		fi
	done

	if [ $at_least_one_user_active == 1 ]; then
		stop_idle_job
	else
		start_idle_job
	fi

	# Check if kill jobs have ended.
	for user in ${!watched_users[@]}
	do
		if ! kill -0 ${watched_users["$user"]}  2>/dev/null
		then
			echo " --> watched user process finished, unwatching user $user"
			unset -v watched_users["$user"]
		fi
	done
done
