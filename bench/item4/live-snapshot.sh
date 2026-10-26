#!/usr/bin/env bash
# live-snapshot.sh: read-only snapshot of the LIVE gateway's counters on this host,
# so a stand run can show it left live untouched. Prints "no live gateway" on a
# machine without one (a stand made elsewhere by scripts/stand-up.sh).
# Log lines are split by source: "local" = 127.0.0.1, 172.16/12 (this host and its
# containers, where every stand test runs) vs other clients.
if ! docker inspect pqc-gateway >/dev/null 2>&1 || [ ! -f /etc/pki/pqc-ca/intermediate/db/index.txt ]; then
	echo "no live gateway on this host"; exit 0
fi
I=/etc/pki/pqc-ca/intermediate/db/index.txt
echo "live index $(wc -l < $I) $(sha256sum $I | cut -c1-16)"
echo "live attr $(sha256sum /etc/pki/pqc-ca/intermediate/db/index.txt.attr | cut -c1-16) serial $(cat /etc/pki/pqc-ca/intermediate/db/serial)"
docker exec pqc-gateway sh -c 'for f in pqc-mtls-access pqc-enroll-access; do
  printf "%s total %s local %s\n" $f $(wc -l < /var/log/nginx/$f.log) $(grep -cE "\"ip\":\"(127\.|172\.(1[6-9]|2[0-9]|3[01])\.)" /var/log/nginx/$f.log); done
for f in pqc-mtls-handshake pqc-enroll-handshake; do
  printf "%s total %s local %s\n" $f $(wc -l < /var/log/nginx/$f.log) $(grep -cE "client: (127\.|172\.(1[6-9]|2[0-9]|3[01])\.)" /var/log/nginx/$f.log); done'
A=/var/lib/docker/volumes/$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' pqc-gateway)_pqc-logs-audit/_data
echo "audit enroll $(wc -l < $A/enroll-audit.log) njs $(wc -l < $A/njs-audit.log)"
docker ps --filter name=^pqc- --format '{{.Names}}' | sort | while read n; do echo "created $n $(docker inspect -f '{{.Created}}' $n)"; done
