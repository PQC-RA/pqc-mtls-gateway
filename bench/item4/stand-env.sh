# stand-env.sh: sourced by every bench/item4 test. Names the ISOLATED stand the
# tests run against: source STAND_DIR/stand.env (written by scripts/stand-up.sh)
# before running any of them.
#
#   STAND_PROJECT      compose project; containers are <project>-<service>
#   STAND_DIR          stand directory: pki/, ssl/, admin/, env, compose wrapper
#   STAND_TLS_PORT     loopback port of the mTLS listener (:443 in the container)
#   STAND_ENROLL_PORT  loopback port of the enrollment listener (:8443)
#   STAND_API_PORT     loopback port of management-api (:3000), health only
#   STAND_ADMIN_CERT / STAND_ADMIN_KEY   the stand's admin identity
#   STAND_COMPOSE      the stand's compose wrapper (refuses live paths and ports)
: "${STAND_PROJECT:?source STAND_DIR/stand.env (scripts/stand-up.sh writes it) first}"
: "${STAND_DIR:?source STAND_DIR/stand.env first}"
: "${STAND_TLS_PORT:?}" "${STAND_ENROLL_PORT:?}" "${STAND_API_PORT:?}"
STAND_ADMIN_CERT=${STAND_ADMIN_CERT:-$STAND_DIR/admin/stand-admin.crt}
STAND_ADMIN_KEY=${STAND_ADMIN_KEY:-$STAND_DIR/admin/stand-admin.key}
STAND_COMPOSE=${STAND_COMPOSE:-$STAND_DIR/compose}
# Compose projects of production deployments on this host, never touched.
LIVE_PROJECTS=${LIVE_PROJECTS:-pqc-gw pqc-mtls-gateway}
STAND_HOST=pqc-gw.local
export STAND_PROJECT STAND_DIR STAND_TLS_PORT STAND_ENROLL_PORT STAND_API_PORT

. "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../scripts/lib" && pwd)/pq-openssl.sh"

GW=$STAND_PROJECT-gateway; CUST=$STAND_PROJECT-ca-custodian; API=$STAND_PROJECT-management-api
REDIS=$STAND_PROJECT-redis; RENEWER=$STAND_PROJECT-crl-renewer
CA=$STAND_DIR/pki/ca-chain.crt; LIVE_CA=/etc/pki/pqc-ca/ca-chain.crt
DB=$STAND_DIR/pki/intermediate/db; IDX=$DB/index.txt
ADM_C=$STAND_ADMIN_CERT; ADM_K=$STAND_ADMIN_KEY
ADMIN=https://$STAND_HOST:$STAND_TLS_PORT; URL=$ADMIN; ENROLL=https://$STAND_HOST:$STAND_ENROLL_PORT/enroll
RES=(--resolve $STAND_HOST:$STAND_TLS_PORT:127.0.0.1 --resolve $STAND_HOST:$STAND_ENROLL_PORT:127.0.0.1)
VOL=/var/lib/docker/volumes/${STAND_PROJECT}_
MGMT_LOG=${VOL}pqc-mgmt-data/_data/admin-actions.log
NGINX_LOGS=${VOL}pqc-logs-nginx/_data

# stand_guard WORKDIR: refuse unless both ports are the stand's gateway and its
# server certificate chains to the stand's throwaway CA and NOT to the live CA.
stand_guard() {
	local w=$1 p
	case " $LIVE_PROJECTS " in *" $STAND_PROJECT "*) echo "GUARD ABORT: project '$STAND_PROJECT' is live"; exit 90 ;; esac
	[ -n "$STAND_PROJECT" ] || { echo "GUARD ABORT: empty project"; exit 90; }
	for p in "$STAND_TLS_PORT" "$STAND_ENROLL_PORT" "$STAND_API_PORT"; do
		case "$p" in 443|8443|3000|80|8081) echo "GUARD ABORT: port $p is a live port"; exit 90 ;; esac
	done
	for p in "$STAND_TLS_PORT" "$STAND_ENROLL_PORT"; do
		echo | timeout 8 "$O" s_client -connect 127.0.0.1:$p -servername $STAND_HOST -showcerts 2>/dev/null | sed -n '/BEGIN CERT/,/END CERT/p' > "$w/srv-$p.pem"
		"$O" verify -CAfile "$CA" -untrusted "$w/srv-$p.pem" "$w/srv-$p.pem" >/dev/null 2>&1 || { echo "GUARD ABORT: $p does not chain to the stand CA"; exit 90; }
		if "$O" verify -CAfile "$LIVE_CA" "$w/srv-$p.pem" >/dev/null 2>&1; then echo "GUARD ABORT: $p chains to LIVE"; exit 90; fi
	done
	[ "$(docker port "$GW" 443/tcp)" = "127.0.0.1:$STAND_TLS_PORT" ] || { echo "GUARD ABORT: $STAND_TLS_PORT is not $GW"; exit 90; }
	[ "$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' "$CUST" 2>/dev/null)" = "$STAND_PROJECT" ] || { echo "GUARD ABORT: $CUST is not in project $STAND_PROJECT"; exit 90; }
	echo "GUARD OK ($STAND_PROJECT, ports $STAND_TLS_PORT/$STAND_ENROLL_PORT)"
}

# Refused at source time, before any script touches a container: a project whose
# containers are the live ones (by name or by compose label) or a live port.
stand_refuse_live() {
	local c lab p
	case " $LIVE_PROJECTS pqc " in *" $STAND_PROJECT "*|"  ") echo "GUARD ABORT: project '$STAND_PROJECT' names live containers"; exit 90 ;; esac
	[ -n "$STAND_PROJECT" ] || { echo "GUARD ABORT: empty project"; exit 90; }
	for c in "$GW" "$CUST" "$API" "$REDIS" "$RENEWER"; do
		lab=$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' "$c" 2>/dev/null || true)
		case " $LIVE_PROJECTS " in *" $lab "*) [ -n "$lab" ] && { echo "GUARD ABORT: $c belongs to the live project $lab"; exit 90; } ;; esac
	done
	for p in "$STAND_TLS_PORT" "$STAND_ENROLL_PORT" "$STAND_API_PORT"; do
		case "$p" in 443|8443|3000|80|8081) echo "GUARD ABORT: port $p is a live port"; exit 90 ;; esac
	done
	return 0
}
stand_refuse_live

