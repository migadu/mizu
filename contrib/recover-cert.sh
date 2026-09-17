#!/bin/sh
# recover-cert.sh - rebuild an autocert cache file from a certificate that was
# issued by Let's Encrypt but never stored.
#
# autocert's renewal reuses the private key of the cert being renewed, so a
# renewed cert that got discarded is still usable: its private key is the one in
# the existing cache file, and the cert itself is public in the CT logs.
#
# Usage:  recover-cert.sh <cache-file> <domain> <out-file>
#   e.g.  recover-cert.sh /usr/local/etc/mizu/cert-cache/mx.migadu.com mx.migadu.com /root/recovered/mx.migadu.com
#
# Only reads <cache-file>. Write <out-file> outside the cache directory, then
# install it on every node (owner mizu, mode 0600), upload it to the S3 cert
# prefix, and restart mizu. Needs sh, openssl and curl (or FreeBSD fetch). The
# private key never leaves this machine.
set -eu

[ $# -eq 3 ] || { echo "usage: $0 <cache-file> <domain> <out-file>" >&2; exit 2; }
file=$1
domain=$2
out=$3
[ "$(cd "$(dirname "$file")" && pwd -P)" != "$(cd "$(dirname "$out")" && pwd -P)" ] || { echo "write <out-file> outside the cache directory" >&2; exit 2; }
[ -r "$file" ] || { echo "cannot read $file" >&2; exit 1; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

get() { # get <url> <out>; crt.sh throttles bursts, so pace and retry
	for try in 1 2 3 4; do
		sleep 1
		if command -v curl >/dev/null 2>&1; then
			curl -fsS -m 60 "$1" -o "$2" 2>/dev/null && return 0
		else
			fetch -q -T 60 -o "$2" "$1" 2>/dev/null && return 0
		fi
		sleep $((try * 3))
	done
	echo "download failed: $1" >&2
	return 1
}
pubhash() { openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256 | sed 's/.*= *//'; }
is_pem() { openssl x509 -in "$1" -noout 2>/dev/null; }

# Split the cache file: block 1 is the private key, the rest is the chain.
awk -v d="$tmp" '/-----BEGIN /{n++} n{print > (d "/blk" n ".pem")}' "$file"
grep -q "PRIVATE KEY" "$tmp/blk1.pem" || { echo "$file: first PEM block is not a private key" >&2; exit 1; }
want=$(openssl pkey -in "$tmp/blk1.pem" -pubout 2>/dev/null | pubhash)
old_end=$(openssl x509 -in "$tmp/blk2.pem" -noout -enddate | cut -d= -f2)
echo "cache file key:  $want"
echo "current cert:    expires $old_end"

# Newest-first list of unexpired CT entries for the domain.
get "https://crt.sh/?q=$domain&output=json&exclude=expired" "$tmp/ct.json"
ids=$(tr ',{' '\n\n' <"$tmp/ct.json" | sed -n 's/^ *"id": *\([0-9][0-9]*\).*/\1/p' | sort -rn | uniq)
[ -n "$ids" ] || { echo "no unexpired CT entries for $domain" >&2; exit 1; }

leaf=
for id in $ids; do
	get "https://crt.sh/?d=$id" "$tmp/c.pem" || continue
	is_pem "$tmp/c.pem" || continue
	# A precertificate carries the CT poison extension and is not servable.
	if openssl x509 -in "$tmp/c.pem" -noout -text | grep -Eq '1\.3\.6\.1\.4\.1\.11129\.2\.4\.3|Precertificate Poison'; then
		continue
	fi
	# Exact name match only: the query also returns certs that merely contain it.
	openssl x509 -in "$tmp/c.pem" -noout -checkhost "$domain" | grep -q "does match" || continue
	[ "$(openssl x509 -in "$tmp/c.pem" -noout -pubkey | pubhash)" = "$want" ] || continue
	openssl x509 -in "$tmp/c.pem" -noout -checkend 604800 >/dev/null || continue
	leaf=$tmp/leaf.pem
	cp "$tmp/c.pem" "$leaf"
	echo "recovered cert:  crt.sh id $id, expires $(openssl x509 -in "$leaf" -noout -enddate | cut -d= -f2)"
	break
done
[ -n "$leaf" ] || { echo "no CT certificate matches the key in $file - nothing to recover, wait for the rate limit" >&2; exit 1; }

# Chain: reuse the file's existing intermediates when the issuer is unchanged,
# otherwise walk the AIA "CA Issuers" links.
cat "$tmp/blk1.pem" "$leaf" >"$out"
if [ "$(openssl x509 -in "$leaf" -noout -issuer_hash)" = "$(openssl x509 -in "$tmp/blk2.pem" -noout -issuer_hash)" ]; then
	n=3
	while [ -f "$tmp/blk$n.pem" ]; do cat "$tmp/blk$n.pem" >>"$out"; n=$((n + 1)); done
	echo "chain:           reused from existing file (same issuer)"
else
	cur=$leaf
	n=0
	while [ $n -lt 4 ]; do
		url=$(openssl x509 -in "$cur" -noout -text | sed -n 's/.*CA Issuers - URI:\(.*\)/\1/p' | head -1)
		[ -n "$url" ] || break
		get "$url" "$tmp/i$n.der"
		openssl x509 -inform DER -in "$tmp/i$n.der" -out "$tmp/i$n.pem" 2>/dev/null || cp "$tmp/i$n.der" "$tmp/i$n.pem"
		# Stop before a self-signed root; servers do not send those.
		[ "$(openssl x509 -in "$tmp/i$n.pem" -noout -subject_hash)" != "$(openssl x509 -in "$tmp/i$n.pem" -noout -issuer_hash)" ] || break
		cat "$tmp/i$n.pem" >>"$out"
		cur=$tmp/i$n.pem
		n=$((n + 1))
	done
	echo "chain:           rebuilt from AIA ($n intermediates)"
fi
chmod 600 "$out"

# Final check: the key in the new file must match its leaf.
got=$(awk '/-----BEGIN CERT/{n++} n==1' "$out" | openssl x509 -noout -pubkey | pubhash)
[ "$got" = "$want" ] || { echo "BUG: key/leaf mismatch in $out" >&2; rm -f "$out"; exit 1; }
echo "wrote $out"
