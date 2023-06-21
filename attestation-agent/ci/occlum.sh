rm -rf occlum_instance && mkdir occlum_instance && cd occlum_instance

occlum init && rm -rf image

# Set the kernel space heap size
jq '.resource_limits.kernel_space_heap_size="100MB"' Occlum.json > tmp.json
mv tmp.json Occlum.json
copy_bom -f ../occlum.yaml --root image --include-dir /opt/occlum/etc/template

occlum build
OCCLUM_LOG_LEVEL=trace occlum run /bin/occlum-attester