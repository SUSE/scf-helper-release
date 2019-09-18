#!/bin/sh
# Readiness probe script for the mysql-proxy role

K=/var/vcap/packages/kubectl/bin/kubectl
N="$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)"
H="${HOSTNAME}"
S="<%= p('gp.switchboard.service') %>"
D="<%= p('gp.switchboard.renewal') %>"
A=skiff-leader

# Clear log.
rm /tmp/log-ready-switchboard

log () { echo "$@" >> /tmp/log-ready-switchboard }

now () {
    # timestamp, seconds of the epoch.
    date '+%s'
}

get_claim () {
    log retrieval ${N}:${S} :: $A
    export CLAIM=$($K get service -n $N $S -o "jsonpath={.metadata.annotations.$A}")
    # CLAIM='claimant:claimtime' -- claimtime unit is [epoch].
    log claim: $CLAIM
    test -n "${CLAIM}"
}

our_claim () {
    CLAIMANT=$(echo $CLAIM | awk -F: '{ print $1 }')
    log self? $H :: $CLAIMANT
    test "${CLAIMANT}" == "${H}"
}

is_expired () {
    CLAIMSEC=$(echo $CLAIM | awk -F: '{ print $2 }')
    NOW="$(now)"
    log expired? $NOW :: $CLAIMSEC
    test -z "${CLAIMSEC}" || test "$(( ${CLAIMSEC} + $D ))" -lt "$NOW"
}

make_claim () {
    C=${H}:$(now)
    log make first claim $C
    $K annotate service -n $N $S $A=$C
}

extend_claim () {
    C=${H}:$(now)
    log extend claim $C
    $K annotate --overwrite service -n $N $S $A=$C
}

clear_claims() {
    log clear expired claim
    $K annotate service -n $N $S ${A}-
}

claim () {
    if ! get_claim ; then
	log no claims
	make_claim || return 1
	return 0
    fi
    log verify claim
    if our_claim ; then
	# (x) Extending the claim strongly relies on a D a good deal
	# longer than the healthcheck interval. This gives the current
	# claimant a high chance of extending its claim without
	# contest from other pods as they see it as 'not expired'.
	# That said given that here uses --overwrite we may very well
	# run over such a contesting attempt.
	extend_claim && return 0
    fi
    if is_expired ; then
	clear_claims
	# note, somebody else can claim it here before we manage to.
	# note 2: while --overwrite would allow us to contest that it
	# becomes a hassle to then detect who has ultimately won.
	make_claim || return 1
	# the previous claimer's extend_claim may run us over here as
	# it uses --overwrite if timing lines up that:
	# - it verified its claim,
	# - we deleted and wrote our claim and
	# - it then overwrites it with its extension.
	# For that to happen the previous claimer's check has to be
	# delayed by pretty exactly (D - check interval) seconds.
	# See (x). So, perform a second check to see if our claim stuck.
	sleep 1
	get_claim && our_claim || return 1
	return 0
    fi
    log standby
    return 1
}

present() {
    head -c0 </dev/tcp/${HOSTNAME}/1936
}

# -------------------------------------------------------------

if present ; then
    log listener present
    if claim ; then
	log OK
	exit 0
    fi
else
    log listener dead
    if get_claim && our_claim ; then
	clear_claims
    fi
fi
log DEFER
exit 1
