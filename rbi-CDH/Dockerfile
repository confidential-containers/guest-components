FROM rust:1.80.0-bookworm as builder

# The list of build argument with docker build --build-arg NAME=VALUE
# Define the default commit of source code
ARG CDH_COMMIT=HEAD

# Set the working directory inside the container
WORKDIR /usr/src/guest-components

# Clone the specific commit from the GitHub repository
RUN apt-get update && apt-get install -y git=1:2.39.2-1.1 \
    && git clone https://github.com/confidential-containers/guest-components.git . \
    && git checkout ${CDH_COMMIT}

# Install additional build dependencies
RUN apt-cache madison protobuf-compiler
RUN apt-get install -y protobuf-compiler=3.21.12-3

# Build and install confidential-data-hub with specific configurations
RUN cd confidential-data-hub && make 

# Install ossfs, Gocryptofs and Runtime Dependencies
RUN apt-get update && apt-get install -y wget=1.21.3-1+b2 gdebi-core=0.9.5.7+nmu6 fuse=2.9.9-6+b1 gocryptfs=2.3-1+b4 && wget https://gosspublic.alicdn.com/ossfs/ossfs_1.91.2_ubuntu22.04_amd64.deb && gdebi -n ossfs_1.91.2_ubuntu22.04_amd64.deb && rm ossfs_1.91.2_ubuntu22.04_amd64.deb 


FROM ubuntu:jammy-20240627.1

LABEL org.opencontainers.image.source="https://github.com/inclavare-containers/confidential-data-hub"

# Copy ossfs
COPY --from=builder /usr/local/bin/ossfs /usr/local/bin/ossfs
# Copy gocryptfs
COPY --from=builder /usr/bin/gocryptfs /usr/local/bin/gocryptfs
# Copy confidential-data-hub binary
COPY --from=builder /usr/src/guest-components/target/x86_64-unknown-linux-gnu/release/confidential-data-hub /usr/local/bin/confidential-data-hub


# Default Config File Path (/etc/confidential-data-hub.toml)
VOLUME [ "/etc/confidential-data-hub.toml" ]

# Start confidential-data-hub listening to request: 127.0.0.1:50000
# CMD [ "confidential-data-hub" ]



EXPOSE 50000
