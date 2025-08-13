# CoCo Restful API Server

CoCo guest components use lightweight ttRPC for internal communication to reduce the memory footprint and dependency. But many internal services also needed by containers like `get_resource`, `get_evidence` and `get_token`, we export these services with restful API, now CoCo containers can easy access these API with http client. Here are some examples, for detail info, please refer [rest API](./openapi/api.json)

```bash
$ ./api-server-rest --features=all
Starting API server on 127.0.0.1:8006
API Server listening on http://127.0.0.1:8006

$ curl http://127.0.0.1:8006/cdh/resource/default/key/1
12345678901234567890123456xxxx

$ curl http://127.0.0.1:8006/aa/evidence\?runtime_data\=xxxx
{"svn":"1","report_data":"eHh4eA=="}

$ curl http://127.0.0.1:8006/aa/token\?token_type\=kbs
{"token":"eyJhbGciOiJFi...","tee_keypair":"-----BEGIN... "}

$ curl http://127.0.0.1:8006/aa/extend_runtime_measurement\?domain\=image-rs\&operation\=pull_image\&content\=docker.io\/library\/busybox@sha256:50aa4698fa6262977cff89181b2664b99d8a56dbca847bf62f2ef04854597cf8\&register_index=17
runtime measurement extend success

$ cat /run/attestation-agent/eventlog
INIT sha384/000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
image-rs pull_image docker.io/library/busybox@sha256:50aa4698fa6262977cff89181b2664b99d8a56dbca847bf62f2ef04854597cf8
```
