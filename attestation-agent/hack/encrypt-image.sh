#!/bin/bash

set -euo pipefail

usage="usage: $0 [-k <b64-encoded key>] [-i <key id>] [-s <source>] [-d <destination>]"

while getopts ":k:i:s:d:h" o; do
	case "${o}" in
	k)
		key=${OPTARG}
		if [ "$(echo "$key" | base64 -d | wc --bytes)" != "32" ]; then
			echo "key should be a b64-encoded 32 byte key" 1>&2; exit 1
		fi
		;;
	i)
		key_id=${OPTARG}
		;;
	s)
		src=${OPTARG}
		;;
	d)
		dst=${OPTARG}
		;;
	h)
		echo "$usage"; exit 0
		;;
	*)
		echo "$usage" 1>&2; exit 1
		;;
	esac
done
shift $((OPTIND-1))

if [ -z "${key-}" ] || [ -z "${key_id-}" ] || [ -z "${src-}" ] || [ -z "${dst-}" ]; then
	echo "$usage" 1>&2; exit 1
fi

key_path=/key
echo "$key" | base64 -d > "$key_path"

coco_keyprovider --socket 127.0.0.1:50000 &
sleep 1

params="provider:attestation-agent:keypath=${key_path}::keyid=${key_id}::algorithm=A256GCM"
skopeo copy --insecure-policy --encryption-key "$params" "$src" "$dst"
