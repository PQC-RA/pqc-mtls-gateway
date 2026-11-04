"""Per-connection handshake timing from the server's own capture (tcpdump -tt text, relative seq).
t_ch   = first client payload (ClientHello)
ch_end = highest client seq sent before the server's first payload (end of ClientHello)
t_c2   = first client payload carrying NEW data (seq >= ch_end): the client's second flight,
         which it can send only after receiving the whole server flight
Retransmitted segments are ignored for byte counts (unique seq ranges only).
flight = unique server payload bytes before t_c2;  > 15000 B = stapled arm
stall  = largest gap between consecutive server payload segments inside the flight"""
import re, sys, statistics as st, collections
pat = re.compile(r'^(\d+\.\d+) IP (\S+)\.(\d+) > (\S+)\.(\d+): Flags \[[^\]]*\], seq (\d+):(\d+),.*length (\d+)')
conns = collections.OrderedDict()
for line in open(sys.argv[1]):
    m = pat.match(line)
    if not m: continue
    t, sp, dp, a, b = float(m[1]), m[3], m[5], int(m[6]), int(m[7])
    key, frm = (sp, 'c') if dp == '443' else (dp, 's')
    conns.setdefault(key, []).append((t, frm, a, b))
out = []
for k, pk in conns.items():
    cl = [p for p in pk if p[1] == 'c']; sv = [p for p in pk if p[1] == 's']
    if not cl or not sv: continue
    t_ch = cl[0][0]; s0 = sv[0][0]
    ch_end = max(p[3] for p in cl if p[0] < s0)
    c2 = [p for p in cl if p[2] >= ch_end]
    if not c2: continue
    t_c2 = c2[0][0]
    flight = [p for p in sv if p[0] < t_c2]
    uniq = set()
    for p in flight: uniq.update(range(p[2], p[3]))
    times = [p[0] for p in flight]
    gaps = [b - a for a, b in zip(times, times[1:])]
    retx = len(flight) - len({(p[2], p[3]) for p in flight})
    out.append((k, 'staple' if len(uniq) > 15000 else 'nostaple', len(uniq), (t_c2 - t_ch) * 1e3, max(gaps) * 1e3 if gaps else 0, retx))
print('port\tarm\tserver_flight_unique_bytes\thandshake_ms\tmax_gap_in_server_flight_ms\tserver_retransmits')
for r in out: print('%s\t%s\t%d\t%.3f\t%.3f\t%d' % r)
for arm in ('nostaple', 'staple'):
    rows = [r for r in out if r[1] == arm]
    v = sorted(r[3] for r in rows); g = sorted(r[4] for r in rows)
    if v: print('# %s N=%d median %.2f ms p25 %.2f p75 %.2f p95 %.2f | max-gap median %.2f ms | flight bytes %s | conns with server retransmit %d' % (arm, len(v), st.median(v), v[len(v)//4], v[3*len(v)//4], v[int(.95*len(v))-1], st.median(g), sorted(set(r[2] for r in rows)), sum(1 for r in rows if r[5])), file=sys.stderr)
