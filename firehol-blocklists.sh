#!/bin/bash

## Based on the spamhaus-drop script by wallyhall, improved and tailored for Synology DSM 7.2
## Credit: https://github.com/wallyhall/spamhaus-drop

## Intially forked from cowgill, extended and improved for our mailserver needs.
## Credit: https://github.com/cowgill/spamhaus/blob/master/spamhaus.sh

# based off the following two scripts
# http://www.theunsupported.com/2012/07/block-malicious-ip-addresses/
# http://www.cyberciti.biz/tips/block-spamming-scanning-with-iptables.html

# Thanks to Daniel Hansson for providing a PR motivating bringing v2 of this script.
# https://github.com/enoch85

# path to iptables
IPTABLES="/sbin/iptables"
IPTABLES_RESTORE="/sbin/xtables-legacy-multi iptables-restore"

# list of known spammers
# URLS="https://www.spamhaus.org/drop/drop.lasso https://www.spamhaus.org/drop/edrop.lasso"
URLS="https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset"

# local cache copy
CACHE_FILE="/tmp/firehol.blocklist.cache"

# use local block list file or option -m
# file must start with '/etc/firehol/blocklist' to prevent misuse
LOCAL_BLACKLIST_FILE="/etc/firehol/blocklist"

# use white list file or option -w
# file must start with '/etc/firehol/whitelist' to prevent misuse
LOCAL_WHITELIST_FILE="/etc/firehol/whitelist"

# iptables custom chain name
CHAIN="firehol-blocklist"

# (don't) skip failed blocklist downloads
SKIP_FAILED_DOWNLOADS=0

# log blocklist hits in iptables
LOG_BLOCKLIST_HITS=0

INDEX=1

error() {
	echo "$1" 1>&2
}

die() {
	if [ -n "$1" ]; then
		error "$1"
	fi
	exit 1
}

usage() {
	echo "Basic usage: $(basename $0) <-u>

Additional options and arguments:
  -u                   Download blocklists and update iptables, falling back to cache file unless -s is specified
  -c=CHAIN_NAME        Override default iptables chain name
  -l=URL_LIST          Override default block list URLs [careful!]
  -f=CACHE_FILE_PATH   Override default cache file path
  -m=LOCAL_BLOCKLIST   Override default local block list file
  -w=WHITELIST         Override default white list file
  -s                   Skip failed blocklist downloads, continuing instead of aborting
  -z                   Update the blocklist from the local cache, don't download new entries
  -d                   Delete the iptables chain (removing all blocklists)
  -o                   Only download the blocklists, don't update iptables
  -t                   Enable logging of blocklist hits in iptables
  -h                   Display this help message
"
	exit $EXIT_CODE
}

set_mode() {
	if [ -n "$MODE" ]; then
		die "You must only specify one of -u/-o/-d/-z"
	fi
	MODE="$1"
}

delete_chain_reference() {
	$IPTABLES -L "$1" | tail -n +3 | grep -e "^$CHAIN " > /dev/null && $IPTABLES -D "$1" -j "$CHAIN"
}

delete_chain() {
	if $IPTABLES -L "$CHAIN" -n &> /dev/null; then
#               delete_chain_reference INPUT
                # delete reference from DEFAULT_INPUT chain instead of INPUT (thanks Synology, WTF?!)
                delete_chain_reference DEFAULT_INPUT
#		delete_chain_reference FORWARD
		if $IPTABLES -F "$CHAIN" && $IPTABLES -X "$CHAIN"; then
			echo "'$CHAIN' chain removed from iptables."
		else
#			echo "'$CHAIN' chain NOT removed, please report this issue to https://github.com/wallyhall/spamhaus-drop/"
			echo "'$CHAIN' chain NOT removed from iptables."
		fi
	else
		echo "'$CHAIN' does not exist, nothing to delete."
	fi
}

download_rules() {
	local TMP_FILE="$(mktemp)"
	local WHITELIST_TMP_FILE="$(mktemp)"
	
	for URL in $URLS; do
		# get a copy of the spam list
		echo "Fetching '$URL' ..."
		curl -Ss "$URL" | grep -e "" | tee -a "$TMP_FILE" > /dev/null 2>&1
		if [ ${PIPESTATUS[0]} -ne 0 ]; then
			if [ $SKIP_FAILED_DOWNLOADS -eq 1 ]; then
				echo "Failed to download '$URL' while skipping is enabled - so continuing."
				cat "$CACHE_FILE" >> "$TMP_FILE"
			else
#				rm -f "$TMP_FILE"
#				die "Failed to download '$URL', aborting."
				die "Failed to download '$URL', falling back to cache file instead."
			fi
		fi
	done

	if [ -n "$LOCAL_BLACKLIST_FILE" ]; then
		if [ -e "$LOCAL_BLACKLIST_FILE" ]; then
			echo "Fetching '$LOCAL_BLACKLIST_FILE' ..."
			if [[ $LOCAL_BLACKLIST_FILE == /etc/firehol/blocklist* ]] ; then
				grep -v "^#" "$LOCAL_BLACKLIST_FILE" | tee -a "$TMP_FILE" > /dev/null 2>&1
			else
				echo Local file does not start with "/etc/firehol/blocklist"
			fi
		else
			echo Local file does not exist: "$LOCAL_BLACKLIST_FILE"
		fi
	fi

	echo "Removing comments (#,;) from the downloaded IP blacklist..."
	sed -i 's/\s*\(#\|;\).*$//' "$TMP_FILE"
	sed -i '/^\s*$/d' "$TMP_FILE"

	echo "Removing whitelisted IPs from the downloaded IP blacklist..."
	IPWHITELIST=`cat $LOCAL_WHITELIST_FILE`
	IPWHITELISTREGEX=""
	while IFS= read -r WHITELISTEDIP
	do
		IPWHITELISTREGEX+="(${WHITELISTEDIP})|"
	done <<< ${IPWHITELIST}
	## Clean the bounce variable (remove all line-breaks)
	IPWHITELISTREGEX="${IPWHITELISTREGEX//$'\n'/ }"
	IPWHITELISTREGEX=$(perl -pe "s/(.*)\|/\1/gms" <<< ${IPWHITELISTREGEX}) ## Remove all IPs listed in the whitelist file
	grep -v -E ${IPWHITELISTREGEX} ${TMP_FILE} > ${WHITELIST_TMP_FILE}
	cp -f ${WHITELIST_TMP_FILE} ${TMP_FILE}
	rm -f ${WHITELIST_TMP_FILE}

	echo "Removing duplicate IPs from the list ..."
	sort -o "$TMP_FILE" -u "$TMP_FILE" > /dev/null 2>&1

	mv -f "$TMP_FILE" "$CACHE_FILE"
#	rm -f "$TMP_FILE"
}

update_iptables() {
	local TMP_FILE="$(mktemp)"

	# refuse to run if the cache file looks insane
	if [ ! -r "$CACHE_FILE" ]; then
		die "Cannot read cache file '$CACHE_FILE'"
	elif [ "$(stat -c '%U' "$CACHE_FILE")" != "root" ]; then
		die "Cache file '$CACHE_FILE' is not owned by root.  Refusing to load it."
	fi

        # check to see if the chain already exists
        if $IPTABLES -L "$CHAIN" -n &> /dev/null; then
		echo "Deleting old chain $CHAIN..."
		delete_chain
	fi

	# prepare header
	echo "*filter" > "$TMP_FILE"
	echo ":$CHAIN -" >> "$TMP_FILE"
	echo "-I INPUT -j $CHAIN" >> "$TMP_FILE"

	# iterate through all known spamming hosts
#	for IP in $( cat "$CACHE_FILE" | grep -e "^\([0-9]\{1,3\}\.\)\{3\}[0-9]\{1,3\}\/[0-9]\{1,2\} " | cut -d' ' -f1 ); do
	for IP in $( cat "$CACHE_FILE" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}(/[1-2][0-9]|3[0-2]|[0-9])?' ); do
		if [ $LOG_BLOCKLIST_HITS -eq 1 ]; then
			# add the ip address log rule to the chain
			echo "-A $CHAIN $IP -j LOG --log-prefix [FIREHOL BLOCKLIST] -m limit --limit 3/min --limit-burst 10" >> "$TMP_FILE"
		fi

		# add the ip address to the chain
		echo "-A $CHAIN -s $IP -j DROP" >> "$TMP_FILE"
	done

	echo "-A $CHAIN -j RETURN" >> "$TMP_FILE"
	echo -e "COMMIT" >> "$TMP_FILE"

	$IPTABLES_RESTORE -n -T filter < "$TMP_FILE"
	echo "'$CHAIN' chain updated with latest rules."

#	rm -f $TMP_FILE
}

download_rules_and_update_iptables() {
	download_rules
	update_iptables
}

if [ "$(whoami)" != "root" ]; then
	die "You must run this command as root."
fi

while getopts "c:l:f:m:w:usodtzhn" option; do
	case "$option" in
		c)	# override chain name
			CHAIN="$OPTARG"
			;;
		
		l)  # override list of block list URLs
			URLS="$OPTARG"
			;;

		f)  # override rule cache file path
			CACHE_FILE="$OPTARG"
			;;

		m)  # my own block list file
			LOCAL_BLACKLIST_FILE="$OPTARG"
			;;
		
		w)  # my own white list file
			LOCAL_WHITELIST_FILE="$OPTARG"
			;;
		
		u)  # update block list
			set_mode download_rules_and_update_iptables
			;;
		
		s)  # skip failed blocklist downloads
			SKIP_FAILED_DOWNLOADS=1
			;;
		
		o)  # download the rules to the cache file, and don't update iptables
			set_mode download_rules
		    ;;
		
		d)  # delete the iptables chain
			set_mode delete_chain
		    ;;

		t)  # enable iptables logging
			LOG_BLOCKLIST_HITS=1
			;;
		
		z)  # update iptables from local cache without downloading
		    set_mode update_iptables
			;;

		h)  # show usage information
		    usage
		    ;;
		
		:)
			error "Error: -${OPTARG} requires an argument."
			usage
			die
			;;
		
		*)
			error "Invalid argument -${OPTARG} supplied."
			usage
			die
			;;
	esac
done

if [ ! -n "$MODE" ]; then
	usage 1
fi
$MODE
