#!/usr/bin/env bash
set -uo pipefail
printf "%-22s %10s %10s %10s %10s  %s\n" CONTAINER "current" "anon" "cache" "limit" "role"
tot_cur=0; tot_anon=0
for c in $(docker ps --format '{{.Names}}' | sort); do
  id=$(docker inspect -f '{{.Id}}' "$c")
  P=/sys/fs/cgroup/system.slice/docker-$id.scope
  [ -r "$P/memory.stat" ] || continue
  cur=$(cat $P/memory.current 2>/dev/null||echo 0)
  anon=$(awk '/^anon /{print $2}' $P/memory.stat)
  file=$(awk '/^file /{print $2}' $P/memory.stat)
  lim=$(cat $P/memory.max 2>/dev/null||echo max)
  printf "%-22s %9.1fM %9.1fM %9.1fM %10s\n" "$c" \
    "$(echo "$cur/1048576"|bc -l)" "$(echo "$anon/1048576"|bc -l)" "$(echo "$file/1048576"|bc -l)" \
    "$( [ "$lim" = max ] && echo unlimited || echo "$(echo "$lim/1048576"|bc -l|cut -d. -f1)M")"
  tot_cur=$((tot_cur+cur)); tot_anon=$((tot_anon+anon))
done
echo
awk -v c=$tot_cur -v a=$tot_anon 'BEGIN{printf "  TOTAL  current %.1f MiB   anon %.1f MiB\n", c/1048576, a/1048576}'
echo
echo "  host: $(free -m | awk '/Mem:/{printf "%d MiB total, %d used, %d available", $2,$3,$7}')"
