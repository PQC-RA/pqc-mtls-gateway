#!/bin/bash
# Twin PKIs for the 2026-11-07 re-run: the live certificate profile (names, serials, extensions,
# lifetimes copied from the live certificates on .99), once with ML-DSA-65 and once with ECDSA P-256.
set -euo pipefail
export OPENSSL_CONF=/etc/ssl/openssl.cnf; O=/opt/openssl-3.6.5/bin/openssl
W=/root/cpusplit-20261107/pki; rm -rf $W; mkdir -p $W; cd $W
cat > ext.cnf <<"X"
[root]
subjectKeyIdentifier=hash
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
certificatePolicies=@pol_root
[pol_root]
policyIdentifier=1.3.6.1.4.1.99999.1.1.1
CPS.1="https://pki.qs-cap.bg/cps"
userNotice.1=@un_root
[un_root]
explicitText="UTF8:QS-CAP PQC Root CA \xe2\x80\x94 eIDAS compliant. CPS: https://pki.qs-cap.bg/cps"
[int]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer:always
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
certificatePolicies=@pol_int
crlDistributionPoints=URI:http://crl.pqc-gw.local/root-ca.crl
[pol_int]
policyIdentifier=1.3.6.1.4.1.99999.1.2.1
CPS.1="https://pki.qs-cap.bg/cps"
userNotice.1=@un_int
[un_int]
explicitText="UTF8:QS-CAP M2M Client Policy \xe2\x80\x94 ETSI EN 319 411 compliant"
[server]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer:always
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
certificatePolicies=@pol_srv
subjectAltName=DNS:pqc-gw.local,DNS:qs-cap.local,DNS:api.qs-cap.bg,DNS:localhost,IP:127.0.0.1,IP:203.0.113.99
crlDistributionPoints=URI:http://crl.pqc-gw.local/intermediate-ca.crl
authorityInfoAccess=OCSP;URI:http://ocsp.pqc-gw.local,caIssuers;URI:http://crt.pqc-gw.local/intermediate-ca.crt
[pol_srv]
policyIdentifier=1.3.6.1.4.1.99999.1.2.2
CPS.1="https://pki.qs-cap.bg/cps"
[ocsp]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer:always
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=OCSPSigning
noCheck=ignored
certificatePolicies=@pol_ocsp
[pol_ocsp]
policyIdentifier=1.3.6.1.4.1.99999.1.2.1
CPS.1="https://pki.qs-cap.bg/cps"
[device]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
X
# the explicit texts carry the live certificates own em dash; write it as real UTF-8
python3 - <<"PY"
p = "ext.cnf"; s = open(p, encoding="utf-8").read().replace("\\xe2\\x80\\x94", "—"); open(p, "w", encoding="utf-8").write(s)
PY
gen() { case $1 in pq) $O genpkey -algorithm ML-DSA-65 -out $2 ;; cl) $O ecparam -name prime256v1 -genkey -noout -out $2 ;; rs) $O genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out $2 ;; esac; }
for arm in pq cl rs; do mkdir -p $arm; ( cd $arm
  gen $arm root.key; $O req -new -key root.key -subj "/C=BG/O=QS-CAP/OU=Certificate Authority Operations/CN=QS-CAP PQC Root CA G1" -out root.csr
  $O x509 -req -in root.csr -signkey root.key -set_serial 0x3E0C7A51D9B2448F6A1E35C07D9F2B6481A3C5E7 -days 3650 -extfile ../ext.cnf -extensions root -out root.crt
  gen $arm int.key; $O req -new -key int.key -subj "/C=BG/O=QS-CAP/OU=M2M Certificate Issuing CA/CN=QS-CAP PQC Intermediate CA G1" -out int.csr
  $O x509 -req -in int.csr -CA root.crt -CAkey root.key -set_serial 0x1000 -days 1826 -extfile ../ext.cnf -extensions int -out int.crt
  gen $arm server.key; $O req -new -key server.key -subj "/C=BG/O=QS-CAP/OU=PQC-Gateway/CN=pqc-gw.local" -out server.csr
  $O x509 -req -in server.csr -CA int.crt -CAkey int.key -set_serial 0x1000 -days 365 -extfile ../ext.cnf -extensions server -out server.crt
  gen $arm ocsp.key; $O req -new -key ocsp.key -subj "/C=BG/O=QS-CAP/OU=OCSP Responder/CN=ocsp.pqc-gw.local" -out ocsp.csr
  $O x509 -req -in ocsp.csr -CA int.crt -CAkey int.key -set_serial 0x1001 -days 365 -extfile ../ext.cnf -extensions ocsp -out ocsp.crt
  gen $arm device.key; $O req -new -key device.key -subj "/CN=rerun-device1" -out device.csr
  $O x509 -req -in device.csr -CA int.crt -CAkey int.key -set_serial 0x108D -days 30 -extfile ../ext.cnf -extensions device -out device.crt
  cat int.crt root.crt > ca-chain.crt
  cat device.crt int.crt root.crt > device-full.crt
  $O verify -CAfile root.crt -untrusted int.crt server.crt device.crt ocsp.crt >/dev/null
  # OCSP response for the server certificate, signed by the responder, responder certificate included (as live)
  printf "V\t%s\t\t1000\tunknown\t/C=BG/O=QS-CAP/OU=PQC-Gateway/CN=pqc-gw.local\n" "$(date -u -d +365days +%y%m%d%H%M%SZ)" > index.txt
  $O ocsp -issuer int.crt -cert server.crt -no_nonce -reqout req.der >/dev/null
  $O ocsp -index index.txt -CA int.crt -rsigner ocsp.crt -rkey ocsp.key -reqin req.der -respout server-ocsp.der -ndays 30 >/dev/null 2>&1
  $O ocsp -respin server-ocsp.der -CAfile ca-chain.crt -issuer int.crt -cert server.crt 2>&1 | grep -E "server.crt|Response verify" | tr "\n" " "; echo
) 2>&1 | grep -v "^Certificate request self-signature ok\|^subject=\|^Signature ok"; done
for arm in pq cl rs; do for c in root int server ocsp device; do printf "%s %s %d\n" $arm $c $($O x509 -in $arm/$c.crt -outform DER | wc -c); done; printf "%s staple %d\n" $arm $(wc -c < $arm/server-ocsp.der); done
