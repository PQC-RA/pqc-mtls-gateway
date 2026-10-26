#!/bin/sh
# Edge box entrypoint: nginx in the foreground, plus a watcher that reloads it
# when the CRL of the central side's CA or allowed-clients.txt changes.
#
# A reload alone does not end sessions already open: old workers keep them until
# worker_shutdown_timeout (nginx.conf), and then close them. The clients reconnect
# and every new handshake is checked against the new CRL. That is how a revocation
# reaches a Modbus session that has been open for days.
set -eu
DIR=/etc/pqc-edge
WATCH="$DIR/central-crl.pem $DIR/allowed-clients.txt"
INTERVAL=${EDGE_RELOAD_POLL_INTERVAL:-1}
mkdir -p /var/log/nginx

state() { cat $WATCH 2>/dev/null | cksum; }

nginx -c "$DIR/nginx.conf" -g "daemon off;" &
NGINX=$!
trap 'kill -QUIT $NGINX 2>/dev/null; wait $NGINX; exit 0' TERM INT

last=$(state)
while kill -0 $NGINX 2>/dev/null; do
	sleep "$INTERVAL"
	now=$(state)
	[ "$now" = "$last" ] && continue
	if nginx -t -c "$DIR/nginx.conf" -q; then
		nginx -c "$DIR/nginx.conf" -s reload && echo "[edge] reloaded: CRL or allowed clients changed"
		last=$now
	else
		echo "[edge] ERROR: new configuration does not test; not reloaded" >&2
		# retried on the next tick until the files test or change again
	fi
done
wait $NGINX
