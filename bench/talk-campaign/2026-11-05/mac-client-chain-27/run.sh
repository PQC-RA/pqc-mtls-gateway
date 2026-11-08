#!/bin/bash
# Mac client chain against the test stand .27 (s_server, OpenSSL 3.6.5, tickets off), 2026-11-05.
# Delay only on the test server's packets (sport 44330) on .27; arms interleaved; N per arm per phase.
cd "$(dirname "$0")"; CURL=/opt/homebrew/opt/curl/bin/curl; N=${N:-20}
H=192.168.1.27; S="ssh -o BatchMode=yes root@$H"
setdelay() { $S "tc qdisc del dev eth0 root 2>/dev/null; if [ $1 -gt 0 ]; then tc qdisc add dev eth0 root handle 1: prio && tc qdisc add dev eth0 parent 1:3 handle 30: netem delay ${1}ms && tc filter add dev eth0 protocol ip parent 1:0 prio 1 u32 match ip sport 44330 0xffff flowid 1:3; fi; tc qdisc show dev eth0 | head -2"; }
arm() { case $1 in
  leaf) $CURL -s -k --cert arm-leaf.pem --key mac.key https://$H:44330/x -o /dev/null -w "%{http_code}\t%{time_connect}\t%{time_appconnect}\t%{time_starttransfer}" ;;
  full) $CURL -s -k --cert arm-full.pem --key mac.key https://$H:44330/x -o /dev/null -w "%{http_code}\t%{time_connect}\t%{time_appconnect}\t%{time_starttransfer}" ;;
  auto) $CURL -s --cacert ca-chain.crt --resolve stand-27:44330:$H --cert arm-leaf.pem --key mac.key https://stand-27:44330/x -o /dev/null -w "%{http_code}\t%{time_connect}\t%{time_appconnect}\t%{time_starttransfer}" ;;
esac; }
{ echo "# $(date -u +%FT%TZ) $(sw_vers -productName) $(sw_vers -productVersion) $(sysctl -n hw.model); $($CURL -V | head -1)"
  echo "# utun: $(ifconfig | grep -A1 '^utun4' | tr '\n' ' ')"
  echo "# mac tcp: $(sysctl net.inet.tcp.mssdflt net.inet.tcp.sendspace net.inet.tcp.delayed_ack net.inet.tcp.slowstart_flightsize net.inet.tcp.local_slowstart_flightsize 2>/dev/null | tr '\n' ' ')"
  echo "# ping: $(ping -c 10 -i 0.2 -q $H | tail -1)"; } > env.txt
printf "phase\ti\tarm\thttp\tconnect_s\tappconnect_s\tstarttransfer_s\n" > samples.tsv
for phase in 0 28 64; do
  echo "# phase delay ${phase} ms: $(setdelay $phase | tr '\n' ' ')" >> env.txt; sleep 1
  for i in $(seq 1 $N); do for a in leaf full auto; do printf "%s\t%s\t%s\t%s\n" $phase $i $a "$(arm $a)" >> samples.tsv; done; done
done
setdelay 0 >> env.txt
cat env.txt; wc -l samples.tsv
