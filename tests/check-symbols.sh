#!/bin/sh
set -e

FILE="${1:-ossl.c3}"
if [ ! -f "$FILE" ]; then
    echo "Error: file not found: $FILE" >&2
    exit 1
fi

find_lib() {
    name="$1"
    # Try ldconfig
    if command -v ldconfig >/dev/null 2>&1; then
        p=$(ldconfig -p 2>/dev/null | grep -F "$name" | head -n1 | awk '{print $NF}')
        if [ -n "$p" ] && [ -f "$p" ]; then
            echo "$p"
            return 0
        fi
    fi
    if [ -x /sbin/ldconfig ]; then
        p=$(/sbin/ldconfig -p 2>/dev/null | grep -F "$name" | head -n1 | awk '{print $NF}')
        if [ -n "$p" ] && [ -f "$p" ]; then
            echo "$p"
            return 0
        fi
    fi
    # Search common directories
    for dir in /usr/lib/x86_64-linux-gnu /usr/lib/aarch64-linux-gnu /usr/lib64 /usr/lib /lib64 /lib; do
        if [ -f "$dir/$name" ]; then
            echo "$dir/$name"
            return 0
        fi
    done
    return 1
}

LIBSSL="${LIBSSL:-$(find_lib libssl.so.3)}"
LIBCRYPTO="${LIBCRYPTO:-$(find_lib libcrypto.so.3)}"

if [ -z "$LIBSSL" ] || [ ! -f "$LIBSSL" ]; then
    echo "Error: libssl.so.3 not found" >&2
    exit 1
fi

if [ -z "$LIBCRYPTO" ] || [ ! -f "$LIBCRYPTO" ]; then
    echo "Error: libcrypto.so.3 not found" >&2
    exit 1
fi

TMP_SYMS=$(mktemp)
trap 'rm -f "$TMP_SYMS"' EXIT

nm -D --defined-only "$LIBSSL" "$LIBCRYPTO" 2>/dev/null | \
    awk '{print $3}' | \
    sed 's/@@.*//; s/@.*//' | \
    sort -u > "$TMP_SYMS"

missing=0
# Extract symbols from @cname("...")
symbols=$(grep -o '@cname("[^"]*")' "$FILE" | sed 's/@cname("//;s/")//' | sort -u)

for sym in $symbols; do
    if ! grep -qx "$sym" "$TMP_SYMS"; then
        echo "Missing symbol: $sym" >&2
        missing=$((missing + 1))
    fi
done

echo "missing=$missing"
if [ "$missing" -ne 0 ]; then
    exit 1
fi
exit 0
