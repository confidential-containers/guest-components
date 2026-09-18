# Source image for ghcr.io/confidential-containers/test-container-image-rs:odd-whiteout-deletion
# Regression for guest-components#1210 / #1258 (deletion whiteout).
FROM debian:stable-slim
RUN apt-get update && apt-get install -qy apache2
RUN rm -rf /etc/apache2
CMD ["find", "/etc/apache2"]
