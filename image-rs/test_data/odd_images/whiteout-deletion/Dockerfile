# Source image for ghcr.io/confidential-containers/test-container-image-rs:odd-whiteout-deletion
# Regression for guest-components#1210 / #1258 (deletion whiteout).
FROM debian:stable-slim@sha256:fbfb4059d2127120aa05b6e6064523d2102552f0cf0026ddf0701c12f1f8f3e0
RUN apt-get update && apt-get install -qy apache2
RUN rm -rf /etc/apache2
CMD ["find", "/etc/apache2"]
