#!/bin/bash
# Generates the test PKI under tests/pki/out/ with the openssl CLI only. Test keys, never installed anywhere.
# Idempotent: does nothing when out/.complete exists; remove tests/pki/out to regenerate.
set -eu
cd "$(dirname "$0")"
OUT=out
if [ -f "$OUT/.complete" ]; then
  echo "pki: already generated in tests/pki/$OUT"
  exit 0
fi
rm -rf "$OUT"
mkdir -p "$OUT"

EC="-algorithm EC -pkeyopt ec_paramgen_curve:P-256"
RSA2048="-algorithm RSA -pkeyopt rsa_keygen_bits:2048"
RSA1024="-algorithm RSA -pkeyopt rsa_keygen_bits:1024"

genkey() { # genkey KIND FILE
  case "$1" in
    ec) openssl genpkey $EC -out "$2" 2>/dev/null ;;
    rsa) openssl genpkey $RSA2048 -out "$2" 2>/dev/null ;;
    rsa1024) openssl genpkey $RSA1024 -out "$2" 2>/dev/null ;;
  esac
}

root() { # root NAME SUBJECT
  genkey ec "$OUT/$1.key"
  openssl req -x509 -new -key "$OUT/$1.key" -subj "$2" -days 3650 \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out "$OUT/$1.pem"
}

# leaf NAME KIND SUBJECT EXTENSIONS SIGNER [extra openssl x509 arguments]
# SIGNER is the base name of an issuer (key and certificate in $OUT)
leaf() {
  local name=$1 kind=$2 subj=$3 ext=$4 signer=$5
  shift 5
  genkey "$kind" "$OUT/$name.key"
  openssl req -new -key "$OUT/$name.key" -subj "$subj" -out "$OUT/$name.csr"
  printf '%s\n' "$ext" > "$OUT/$name.ext"
  openssl x509 -req -in "$OUT/$name.csr" -CA "$OUT/$signer.pem" -CAkey "$OUT/$signer.key" -CAcreateserial \
    -days 3650 -extfile "$OUT/$name.ext" -out "$OUT/$name.pem" "$@" 2>/dev/null
  rm -f "$OUT/$name.csr"
}

nl='
'
SAN="subjectAltName=DNS:localhost,DNS:test.example,IP:127.0.0.1"
SERVER_EXT="basicConstraints=CA:FALSE${nl}keyUsage=digitalSignature${nl}extendedKeyUsage=serverAuth${nl}${SAN}"
SERVER_RSA_EXT="basicConstraints=CA:FALSE${nl}keyUsage=digitalSignature,keyEncipherment${nl}extendedKeyUsage=serverAuth${nl}${SAN}"
base_ext() { # base_ext SAN-LINE-OR-EMPTY [EKU]
  local e="basicConstraints=CA:FALSE${nl}keyUsage=digitalSignature"
  if [ "${2-serverAuth}" != "none" ]; then e="${e}${nl}extendedKeyUsage=${2-serverAuth}"; fi
  if [ -n "$1" ]; then e="${e}${nl}$1"; fi
  printf '%s' "$e"
}

root ca "/CN=tls.c3l test CA"
root otherca "/CN=tls.c3l other CA"

# ---- the good server and client certificates
leaf server ec "/CN=localhost" "$SERVER_EXT" ca
leaf server-rsa rsa "/CN=localhost" "$SERVER_RSA_EXT" ca
leaf client ec "/CN=test client" "$(base_ext "" clientAuth)" ca
openssl pkey -in "$OUT/client.key" -aes256 -passout pass:x -out "$OUT/client-enc.key"
genkey ec "$OUT/key-mismatch.key"
leaf alt ec "/CN=alt.test" "$(base_ext "subjectAltName=DNS:alt.test")" ca

# ---- validity
leaf expired ec "/CN=localhost" "$SERVER_EXT" ca -not_before 20200101000000Z -not_after 20200102000000Z
leaf notyet ec "/CN=localhost" "$SERVER_EXT" ca -not_before 20990101000000Z -not_after 21000101000000Z

# ---- trust
leaf wronghost ec "/CN=other.test" "$(base_ext "subjectAltName=DNS:other.test")" ca
leaf untrusted ec "/CN=localhost" "$SERVER_EXT" otherca
cat "$OUT/untrusted.pem" "$OUT/otherca.pem" > "$OUT/untrusted-chain.pem"
genkey ec "$OUT/selfsigned.key"
openssl req -x509 -new -key "$OUT/selfsigned.key" -subj "/CN=localhost" -days 3650 \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" -addext "basicConstraints=CA:FALSE" -out "$OUT/selfsigned.pem"

# ---- certificate policy
leaf no-eku ec "/CN=localhost" "$(base_ext "$SAN" none)" ca
# an intermediate that is not a CA, and a leaf below it
genkey ec "$OUT/bad-intermediate.key"
openssl req -new -key "$OUT/bad-intermediate.key" -subj "/CN=not a CA" -out "$OUT/bad-intermediate.csr"
printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\n' > "$OUT/bad-intermediate.ext"
openssl x509 -req -in "$OUT/bad-intermediate.csr" -CA "$OUT/ca.pem" -CAkey "$OUT/ca.key" -CAcreateserial -days 3650 \
  -extfile "$OUT/bad-intermediate.ext" -out "$OUT/bad-intermediate.pem" 2>/dev/null
rm -f "$OUT/bad-intermediate.csr"
leaf bad-leaf ec "/CN=localhost" "$SERVER_EXT" bad-intermediate
cat "$OUT/bad-leaf.pem" "$OUT/bad-intermediate.pem" > "$OUT/bad-intermediate-chain.pem"
leaf rsa1024 rsa1024 "/CN=localhost" "$SERVER_RSA_EXT" ca
leaf sha1-signed ec "/CN=localhost" "$SERVER_EXT" ca -sha1

# ---- host name matching
leaf cn-only ec "/CN=test.example" "$(base_ext "")" ca
leaf cn-other ec "/CN=other" "$(base_ext "subjectAltName=DNS:test.example")" ca
leaf ip-only ec "/CN=localhost" "$(base_ext "subjectAltName=IP:127.0.0.1")" ca
leaf dns-only ec "/CN=localhost" "$(base_ext "subjectAltName=DNS:a.test")" ca
leaf wildcard ec "/CN=localhost" "$(base_ext "subjectAltName=DNS:*.test.example")" ca
leaf partial-wildcard ec "/CN=localhost" "$(base_ext "subjectAltName=DNS:foo*.test.example")" ca
# dNSName "evil.com\0.good.com": a GeneralNames SEQUENCE holding one [2] IA5String of 18 bytes with an embedded NUL
leaf nul-san ec "/CN=localhost" "$(base_ext "subjectAltName=DER:30:14:82:12:65:76:69:6c:2e:63:6f:6d:00:2e:67:6f:6f:64:2e:63:6f:6d")" ca

# ---- a hashed CA directory
mkdir "$OUT/hashed"
cp "$OUT/ca.pem" "$OUT/hashed/"
openssl rehash "$OUT/hashed" >/dev/null

# ---- a minimal OpenSSL configuration for peers started by tests (TLS 1.1 and lower security level where needed)
cat > "$OUT/openssl-test.cnf" <<CNF
openssl_conf = default_conf
[default_conf]
ssl_conf = ssl_sect
[ssl_sect]
system_default = system_default_sect
[system_default_sect]
MinProtocol = TLSv1.2
CipherString = DEFAULT:@SECLEVEL=2
CNF

# ---- self-checks
fail() { echo "pki: self-check failed: $1" >&2; exit 1; }
openssl verify -CAfile "$OUT/ca.pem" -purpose sslserver "$OUT/server.pem" >/dev/null || fail "server verifies"
openssl verify -CAfile "$OUT/ca.pem" -purpose sslserver "$OUT/server-rsa.pem" >/dev/null || fail "server-rsa verifies"
openssl verify -CAfile "$OUT/ca.pem" -purpose sslclient "$OUT/client.pem" >/dev/null || fail "client verifies"
if openssl verify -CAfile "$OUT/ca.pem" "$OUT/expired.pem" 2>&1 | grep -q "has expired"; then :; else fail "expired is rejected as expired"; fi
if openssl verify -CAfile "$OUT/ca.pem" -verify_hostname wrong.example "$OUT/server.pem" >/dev/null 2>&1; then fail "wrong host name is rejected"; fi
if openssl verify -CAfile "$OUT/ca.pem" "$OUT/untrusted.pem" >/dev/null 2>&1; then fail "untrusted is rejected"; fi
if openssl x509 -in "$OUT/nul-san.pem" -noout -checkhost good.com | grep -q "does match"; then fail "NUL name must not match good.com"; fi
if openssl x509 -in "$OUT/nul-san.pem" -noout -checkhost evil.com | grep -q "does match"; then fail "NUL name must not match evil.com"; fi

touch "$OUT/.complete"
echo "pki: self-checks ok"
