import subprocess, time, os, sys, statistics as st, csv
OSSL='/opt/openssl/bin/openssl'
PKI=sys.argv[1]; OUT=sys.argv[2]; N=int(sys.argv[3])
ENV=dict(os.environ, OPENSSL_CONF='/etc/ssl/openssl.cnf')
TMP=os.path.join(OUT,'work'); os.makedirs(TMP, exist_ok=True)
DN='/C=BG/O=PQC-GW/OU=M2M-Client/CN=bench-subject'

ARMS={
 'ML-DSA-65':  (os.path.join(PKI,'pqc'),           ['-algorithm','ML-DSA-65']),
 'ECDSA-P256': (os.path.join(PKI,'classical'),     ['-algorithm','EC','-pkeyopt','ec_paramgen_curve:P-256']),
 'RSA-2048':   (os.path.join(PKI,'classical-rsa'), ['-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048']),
}

def run(args):
    t=time.perf_counter()
    r=subprocess.run([OSSL]+args, env=ENV, capture_output=True)
    dt=(time.perf_counter()-t)*1000.0
    if r.returncode!=0: raise SystemExit(f'FAIL {args[:3]}: {r.stderr.decode()[:200]}')
    return dt

# instrument floor: what one openssl invocation costs before it does anything
floor=[run(['version']) for _ in range(N)]
print(f'instrument floor (openssl version): median {st.median(floor):.2f} ms  n={N}')

rows=[]
for arm,(cadir,keyopts) in ARMS.items():
    for i in range(N):
        k=os.path.join(TMP,f'{arm}-{i}.key'); c=os.path.join(TMP,f'{arm}-{i}.csr'); x=os.path.join(TMP,f'{arm}-{i}.crt')
        t_key = run(['genpkey']+keyopts+['-out',k])
        t_csr = run(['req','-new','-key',k,'-subj',DN,'-out',c])
        t_sgn = run(['x509','-req','-in',c,'-CA',os.path.join(cadir,'int.crt'),
                     '-CAkey',os.path.join(cadir,'int.key'),'-days','365',
                     '-set_serial',str(5000+i),'-out',x])
        rows.append(dict(arm=arm,repeat=i+1,keygen_ms=round(t_key,3),csr_ms=round(t_csr,3),
                         sign_ms=round(t_sgn,3),total_ms=round(t_key+t_csr+t_sgn,3),
                         cert_der=len(subprocess.run([OSSL,'x509','-in',x,'-outform','DER'],
                                      env=ENV,capture_output=True).stdout)))
        for f in (k,c,x):
            try: os.remove(f)
            except OSError: pass

with open(os.path.join(OUT,'issuance.csv'),'w',newline='') as fh:
    w=csv.DictWriter(fh, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)

def ci(v):
    return 1.96*st.stdev(v)/len(v)**0.5 if len(v)>1 else 0.0
print(f"\n{'arm':<11}{'phase':<9}{'median':>9}{'mean':>9}{'95% CI':>10}{'min':>8}{'max':>8}")
summary={}
for arm in ARMS:
    v=[r for r in rows if r['arm']==arm]
    summary[arm]={}
    for ph in ('keygen_ms','csr_ms','sign_ms','total_ms'):
        s=[r[ph] for r in v]
        summary[arm][ph]=(st.median(s), st.mean(s), ci(s))
        print(f"{arm:<11}{ph.replace('_ms',''):<9}{st.median(s):>9.2f}{st.mean(s):>9.2f}{'±'+format(ci(s),'.2f'):>10}{min(s):>8.2f}{max(s):>8.2f}")
    print(f"{'':<11}{'DER':<9}{v[0]['cert_der']:>9} B")
print(f'\nfloor median {st.median(floor):.2f} ms  (subtract 3x for a 3-step issuance)')
