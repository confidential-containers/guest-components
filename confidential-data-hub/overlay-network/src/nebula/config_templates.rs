pub const WORKER_CONFIG_TEMPLATE: &str = "pki:
  ca: /tmp/nebula/ca.crt
  cert: /tmp/nebula/pod.crt
  key: /tmp/nebula/pod.key

static_host_map:
  _STATIC_HOST_MAP
lighthouse:
  am_lighthouse: false
  interval: 60
  serve_dns: false
  hosts:
    - _LIGHTHOUSE_HOST
listen:
  host: 0.0.0.0
  port: 4242
  batch: 256
  read_buffer: 419430400
  write_buffer: 419430400

routines: 1

punchy:
  punch: true

relay:
  am_relay: false
  use_relays: true

tun:
  disabled: false
  dev: nebula1
  drop_local_broadcast: false
  drop_multicast: false
  tx_queue: 500
  mtu: 1450

  routes:
  unsafe_routes:

logging:
  level: info
  format: text

firewall:
  outbound_action: drop
  inbound_action: drop

  conntrack:
    tcp_timeout: 12m
    udp_timeout: 3m
    default_timeout: 10m

  outbound:
    - port: any
      proto: any
      host: any

  inbound:
    - port: any
      proto: any
      host: any";
