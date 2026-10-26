#!/bin/sh
# Edge box entrypoint: nginx in the foreground, plus a watcher that reloads it
# when the CRL of the central side's CA or allowed-clients.txt changes.
#
# A reload alone does not end sessions already open: old workers keep them until
# worker_shutdown_timeout (nginx.conf), and then close them. The clients reconnect
# and every new handshake is checked against the new CRL. That is how a revocation
# reaches a Modbus session that has been open for days.
#
# Mount /etc/pqc-edge as a DIRECTORY: a file bind-mounted on its own keeps its
# old content when the host replaces it (mv), and the change is never seen.
set -eu
DIR=/etc/pqc-edge
WATCH="$DIR/central-crl.pem $DIR/allowed-clients.txt"
INTERVAL=${EDGE_RELOAD_POLL_INTERVAL:-1}
mkdir -p /var/log/nginx

state() { cat $WATCH 2>/dev/null | cksum; }

NGINX=
trap '[ -n "$NGINX" ] && kill -QUIT $NGINX 2>/dev/null; [ -n "$NGINX" ] && wait $NGINX; exit 0' TERM INT
nginx -c "$DIR/nginx.conf" -g "daemon off;" &
NGINX=$!

last=$(state)
failed=
while kill -0 $NGINX 2>/dev/null; do
	sleep "$INTERVAL"
	now=$(state)
	[ "$now" = "$last" ] && continue
	# A change that does not test (a half-delivered CRL, a typo) is retried every
	# tick, and reported once per distinct content.
	if nginx -t -q -c "$DIR/nginx.conf" 2>/dev/null && nginx -c "$DIR/nginx.conf" -s reload; then
		echo "[edge] reloaded: CRL or allowed clients changed"
		last=$now; failed=
	elif [ "$failed" != "$now" ]; then
		echo "[edge] ERROR: changed CRL or allowed clients do not load; NOT reloaded, retrying" >&2
		nginx -t -c "$DIR/nginx.conf" >&2 || true
		failed=$now
	fi
done
wait $NGINX
