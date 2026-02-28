# CoCo RESTful API Server

CoCo guest components use lightweight ttRPC for internal communication to reduce the memory footprint and dependency. But many internal services also needed by containers like `get_resource`, `get_evidence` and `get_token`, we export these services with RESTful API, now CoCo containers can easily access these API with http client. Here are some examples, for detailed info, please refer [rest API](./openapi/api.json)

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

$ curl http://127.0.0.1:8006/info
{"version":"v1.0.0","tee":"tdx","additional_tees":[]}

$ curl -X POST http://127.0.0.1:8006/aa/aael \
     -H "Content-Type: application/json" \
     -d '{"domain":"test","operation":"test","content":"test"}'

```
