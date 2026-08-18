#!/usr/bin/env bash
# memcheck.sh: is the gateway really using twice the memory, or is docker stats
# counting something the original figure did not?
#
# On cgroup v2, `docker stats` MemUsage reports memory.current, which INCLUDES
# page cache. A container that has served thousands of handshakes has read certs,
# CRLs, config and logs, and all of that sits in its cgroup's file cache. The
# anonymous working set (what "memory usage" normally means) is a different
# number and is what should be compared across hosts.
set -uo pipefail
H=$(hostname)
echo "===== $H ====="
C=pqc-gateway
docker inspect "$C" >/dev/null 2>&1 || { echo "  no $C container here"; exit 0; }

echo "  uptime: $(docker inspect -f '{{.State.StartedAt}}' $C)"
echo "  docker stats MemUsage: $(docker stats --no-stream --format '{{.MemUsage}} ({{.MemPerc}})' $C 2>/dev/null)"

CG=$(docker inspect -f '{{.Id}}' $C)
for base in /sys/fs/cgroup/system.slice/docker-$CG.scope /sys/fs/cgroup/docker/$CG /sys/fs/cgroup/memory/docker/$CG; do
  [ -r "$base/memory.stat" ] && { CGP="$base"; break; }
done
if [ -n "${CGP:-}" ]; then
  echo "  cgroup: $CGP"
  cur=$(cat $CGP/memory.current 2>/dev/null || echo 0)
  anon=$(awk '/^anon /{print $2}' $CGP/memory.stat 2>/dev/null || echo 0)
  file=$(awk '/^file /{print $2}' $CGP/memory.stat 2>/dev/null || echo 0)
  slab=$(awk '/^slab /{print $2}' $CGP/memory.stat 2>/dev/null || echo 0)
  sock=$(awk '/^sock /{print $2}' $CGP/memory.stat 2>/dev/null || echo 0)
  awk -v c="$cur" -v a="$anon" -v f="$file" -v s="$slab" -v k="$sock" 'BEGIN{
    printf "    memory.current : %8.1f MiB   <- what docker stats shows\n", c/1048576;
    printf "    anon (RSS)     : %8.1f MiB   <- the real working set\n", a/1048576;
    printf "    file (page cache): %6.1f MiB   <- reclaimable, grows with I/O\n", f/1048576;
    printf "    slab           : %8.1f MiB\n", s/1048576;
    printf "    sock           : %8.1f MiB\n", k/1048576;
  }'
else
  echo "  (cgroup path not found; falling back to RSS sum)"
fi

# nginx process RSS, independent of cgroup accounting
RSS=$(docker exec $C sh -c "awk '/^VmRSS/{s+=\$2} END{print s}' /proc/*/status 2>/dev/null" 2>/dev/null)
[ -n "${RSS:-}" ] && awk -v r="$RSS" 'BEGIN{printf "    sum of process VmRSS: %.1f MiB\n", r/1024}'
echo "  worker processes: $(docker exec $C sh -c 'ps ax 2>/dev/null | grep -c "[n]ginx: worker"' 2>/dev/null || echo '?')"
echo "  worker_processes directive: $(docker exec $C sh -c 'grep -h "^worker_processes" /usr/local/openresty/nginx/conf/nginx.conf /etc/nginx/nginx.conf 2>/dev/null | head -1' 2>/dev/null || echo '?')"
echo "  nproc visible: $(docker exec $C nproc 2>/dev/null || echo '?')"

# drop the page cache for this cgroup and re-read, to prove how much was cache
if [ -n "${CGP:-}" ] && [ -w /proc/sys/vm/drop_caches ]; then
  sync; echo 1 > /proc/sys/vm/drop_caches 2>/dev/null || true
  sleep 2
  cur2=$(cat $CGP/memory.current 2>/dev/null || echo 0)
  anon2=$(awk '/^anon /{print $2}' $CGP/memory.stat 2>/dev/null || echo 0)
  awk -v c="$cur2" -v a="$anon2" 'BEGIN{
    printf "  after dropping page cache:\n";
    printf "    memory.current : %8.1f MiB\n", c/1048576;
    printf "    anon (RSS)     : %8.1f MiB\n", a/1048576;
  }'
fi
