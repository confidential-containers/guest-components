#!/bin/bash
set -e
declare -A keys

usage() {
    cat << EOT
This script aims to generate a "aa-offline_fs_kbc-keys.json" for offline-fs-kbc,
or export a specific key in side "aa-offline_fs_kbc-keys.json" to binary for
image encryption.
	Usage:
		- ./generate_keys.sh generate
			Generate a "aa-offline_fs_kbc-keys.json" with randomly generated KEKs inside.
		- ./generate_keys.sh export <path-to-aa-offline_fs_kbc-keys.json> <key-uri> <output-path> [<key-repo>]
			Export the key of <key-uri> in the given "aa-offline_fs_kbc-keys.json". The result
			key will be exported to <output-path>
EOT
    exit
}

create_keys() {
	for i in $(seq 1 "$1"); do
		keys[$2/key/key_id$i]=$(head -c32 < /dev/random | base64)
	done
}

dump_keys() {
	for kid in "${!keys[@]}"; do
		printf "%s\n%s\n" "$kid" "${keys[$kid]}"
	done | jq -Rn 'reduce inputs as $kid ({}; . + {($kid): (input)})'
}

generate_keys() {
	repo=
	if [ -z $1 ]; then
		repo="default"
	else
		repo=$1
	fi

	create_keys 10 $repo
	dump_keys
}

export_key() {
	local json_file=$1
	local uri=$2
	local output_path=$3

	cat $json_file | jq ".\"$uri\"" -r | base64 -d > $output_path
}

main() {
    local dir=$(cd "$(dirname "$0")";pwd)
	local operation=$1
    if [ -z "$operation" ]; then 
        usage
    fi

    if [ "$operation" = "generate" ] ;then
        generate_keys $2
    elif [ "$operation" = "export" ] ;then
		if [ -z $4 ] ; then
			echo "[FAILED] Unmatched parameters"
			usage
		fi
        export_key $2 $3 $4
    else
		echo "[FAILED] Unknown operation $operation"
		usage
	fi
}

main "$@"