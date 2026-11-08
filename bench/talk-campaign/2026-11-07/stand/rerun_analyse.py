"""Analyse the 2026-11-07 re-run: one stopwatch, the server-side capture.

Usage: rerun_analyse.py SAMPLES.tsv CAP0.txt CAP25.txt OUT.tsv
CAPn.txt = `tcpdump -nn -tt -r cap-delayN.pcap` (text). Server ports 31443 (post-quantum), 31444 (classical).

Per connection, all times at the server's interface:
  rtt        the client's SYN -> the client's ACK, both as they arrive (one round trip)
  t_ch       the ClientHello arrives (first client payload)
  t_c2       the client's second flight starts (first new client payload after the server's flight)
  t_s2       the server's first payload after the client's flight (session tickets): the handshake
             is complete at the server
  handshake  t_ch -> the last packet of the client's flight arrives (the capture on lo stamps a packet
             after its delay, i.e. on arrival, so only client-to-server packets are used for timing)
  srv_stall  the longest gap inside the server's flight (a pause waiting for an ACK)
  cli_stall  the longest gap inside the client's flight
"""
import collections
import csv
import re
import statistics as st
import sys

SAMPLES, CAP0, CAP25, OUT = sys.argv[1:5]
pat = re.compile(r'^(\d+\.\d+) IP (\S+)\.(\d+) > (\S+)\.(\d+): Flags \[([^\]]*)\](?:, seq (\d+):(\d+))?.*length (\d+)')
rows = list(csv.DictReader(open(SAMPLES), delimiter='\t'))


def conns(path):
    c = collections.OrderedDict()
    for line in open(path):
        m = pat.match(line)
        if not m:
            continue
        t, sp, dp, flags, a, b, ln = float(m[1]), m[3], m[5], m[6], m[7], m[8], int(m[9])
        if dp in ('31443', '31444'):
            key, frm, srv = sp, 'c', dp
        else:
            key, frm, srv = dp, 's', sp
        c.setdefault((srv, key), []).append((t, frm, flags, int(a) if a else None, int(b) if b else None, ln))
    return c


def measure(pk):
    syn = [p for p in pk if p[1] == 'c' and 'S' in p[2]]
    synack = [p for p in pk if p[1] == 's' and 'S' in p[2]]
    if not syn or not synack:
        return None
    t_syn, t_sa = syn[0][0], synack[0][0]
    ack = [p for p in pk if p[1] == 'c' and p[0] > t_sa and p[5] == 0 and 'S' not in p[2]]
    rtt = (ack[0][0] - t_syn) * 1e3 if ack else None     # both captured as they arrive at the server
    cl = [p for p in pk if p[1] == 'c' and p[5] > 0]
    sv = [p for p in pk if p[1] == 's' and p[5] > 0]
    if not cl or not sv:
        return None
    t_ch = cl[0][0]
    s0 = sv[0][0]
    ch_end = max(p[4] for p in cl if p[0] < s0)
    c2 = [p for p in cl if p[3] is not None and p[3] >= ch_end]
    if not c2:
        return None
    t_c2 = c2[0][0]
    flight = [p for p in sv if p[0] < t_c2]
    after = [p for p in sv if p[0] > t_c2]
    if not after:
        return None
    t_s2 = after[0][0]
    cflight = [p for p in c2 if p[0] < t_s2]
    t_c_end = cflight[-1][0]                                 # the client's flight (and its request) has arrived
    gaps = lambda seq: max([(b[0] - a[0]) * 1e3 for a, b in zip(seq, seq[1:])] or [0.0])
    srv_bytes = len({x for p in flight for x in range(p[3], p[4])})
    return dict(t_syn=t_syn, rtt=rtt, handshake=(t_c_end - t_ch) * 1e3, srv_stall=gaps(flight), cli_stall=gaps(cflight),
                srv_flight_bytes=srv_bytes, tickets_and_reply=sum(p[5] for p in after))


out = []
for delay, cap in (('0', CAP0), ('25', CAP25)):
    rs = [r for r in rows if r['delay_each_way_ms'] == delay]
    for (srv, port), pk in conns(cap).items():
        m = measure(pk)
        if not m:
            continue
        hit = [r for r in rs if float(r['start']) <= m['t_syn'] <= float(r['end'])]
        if len(hit) != 1:
            continue                                   # warm-up connections have no sample row
        r = hit[0]
        out.append(dict(delay_each_way_ms=delay, i=r['i'], arm=r['arm'], read=r['read'], written=r['written'],
                        verify=r['verify'], staple=r['staple'], rtt_ms=f"{m['rtt']:.3f}", handshake_ms=f"{m['handshake']:.3f}",
                        server_stall_ms=f"{m['srv_stall']:.3f}", client_stall_ms=f"{m['cli_stall']:.3f}",
                        server_flight_bytes=m['srv_flight_bytes'], after_handshake_bytes=m['tickets_and_reply']))
with open(OUT, 'w') as f:
    w = csv.DictWriter(f, fieldnames=list(out[0]), delimiter='\t')
    w.writeheader()
    w.writerows(out)

print('delay\tarm\tN\tread\twritten\trtt_med\thandshake_med\tp10\tp90\tsrv_stall_med\tcli_stall_med\tafter_hs_bytes')
for delay in ('0', '25'):
    for arm in ('pq-leaf', 'pq-leaf-staple', 'pq-trust', 'pq-full', 'cl-leaf', 'cl-leaf-staple', 'cl-trust', 'cl-full'):
        rr = [o for o in out if o['delay_each_way_ms'] == delay and o['arm'] == arm]
        if not rr:
            continue
        h = sorted(float(o['handshake_ms']) for o in rr)
        print(f"{delay}\t{arm}\t{len(rr)}\t{sorted({o['read'] for o in rr})}\t{sorted({o['written'] for o in rr})}\t"
              f"{st.median(float(o['rtt_ms']) for o in rr):.2f}\t{st.median(h):.2f}\t{h[len(h)//10]:.2f}\t{h[9*len(h)//10]:.2f}\t"
              f"{st.median(float(o['server_stall_ms']) for o in rr):.2f}\t{st.median(float(o['client_stall_ms']) for o in rr):.2f}\t"
              f"{st.median(int(o['after_handshake_bytes']) for o in rr):.0f}")
print('all verified OK:', all(o['verify'] == 'OK' for o in out), '| staple good on staple arms:',
      all(o['staple'] == 'good' for o in out if 'staple' in o['arm']))
