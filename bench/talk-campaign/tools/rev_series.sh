#!/bin/bash
P=$1; cd $P; export SSH_CTL=/tmp/pqc-rev-ssh-ctl; export CODES_OUT=$P/live/rev2/revocation-vpn-codes.tsv
ssh -o ControlMaster=yes -o ControlPath=$SSH_CTL -o ControlPersist=900 -fN root@192.168.1.99
OUT=$P/live/rev2/revocation-vpn.tsv; : > $CODES_OUT
printf 'run\tcn\tserial\tt0_unix\tfresh_conn_refused_s\tkeepalive_refused_s\tfresh_last_ok_s\tkeepalive_last_ok_s\tA_requests\tB_requests\trevoke_resp\n' > $OUT
for n in $(seq -w 1 20); do
  cn=talk-rev2-c$n; d=$P/device/rev2/$cn
  $P/tools/enroll.sh $cn client-30d $d > $P/live/rev2/enroll-$cn.log 2>&1 || { echo "c$n ENROLL FAILED" >> $OUT; sleep 13; continue; }
  serial=$(awk 'NR==2{print $3}' $d/enroll.tsv)
  python3 -I $P/tools/revoke_probe.py $cn $d $serial c$n >> $OUT 2>$P/live/rev2/probe-$cn.err
  sleep 13
done
ssh -o ControlPath=$SSH_CTL -O exit root@192.168.1.99 2>/dev/null
echo DONE >> $P/live/rev2/series.done
