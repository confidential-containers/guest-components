#!/bin/bash
set -eu
declare -A keys

create_keys() {
	for i in $(seq 1 "$1"); do
		keys[key_id$i]=$(dd if=/dev/random bs=32 count=1 2> /dev/null | base64)
	done
}

dump_keys() {
	for kid in "${!keys[@]}"; do
		printf "%s\n%s\n" "$kid" "${keys[$kid]}"
	done | jq -Rn 'reduce inputs as $kid ({}; . + {($kid): (input)})'
}

create_keys 10
dump_keys
