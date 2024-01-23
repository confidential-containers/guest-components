# eHSM-KMS

eHSM-KMS is a SGX-based Key Managment Service (KMS) that provides the near-equivalent hardware protection level of cryptographic functionalities including key generation, management inside the SGX enclave. More information about eHSM-KMS can be found [here](https://github.com/intel/ehsm).

In CDH, we provide the eHSM-KMS client to interact with the eHSM-KMS Server.

## eHSM-KMS Service

For eHSM-KMS client to run, you need to set up an eHSM-KMS service in advance. The following method is only a quick start, and you can find more deployment methods (e.g. with Kubernetes) at webpage of eHSM-KMS.

> Prerequisite: a sgx capable machine

* Install requirement tools
    ``` shell
    sudo apt update

    sudo apt install vim autoconf automake build-essential cmake curl debhelper git libcurl4-openssl-dev libprotobuf-dev libssl-dev libtool lsb-release ocaml ocamlbuild protobuf-compiler wget libcurl4 libssl1.1 make g++ fakeroot libelf-dev libncurses-dev flex bison libfdt-dev libncursesw5-dev pkg-config libgtk-3-dev libspice-server-dev libssh-dev python3 python3-pip  reprepro unzip libjsoncpp-dev uuid-dev liblog4cplus-1.1-9 liblog4cplus-dev dnsutils
    ```

* Install SGX SDK
    ```shell
    wget https://download.01.org/intel-sgx/sgx-linux/2.18/as.ld.objdump.r4.tar.gz
    tar -zxf as.ld.objdump.r4.tar.gz
    sudo cp external/toolset/{current_distr}/* /usr/local/bin

    wget https://download.01.org/intel-sgx/sgx-dcap/1.15/linux/distro/ubuntu20.04-server/sgx_linux_x64_sdk_2.18.100.3.bin

    #choose to install the sdk into the /opt/intel
    chmod a+x ./sgx_linux_x64_sdk_2.18.100.3.bin && sudo ./sgx_linux_x64_sdk_2.18.100.3.bin

    source /opt/intel/sgxsdk/environment
    ```

* Install DCAP required packages
    ```shell
    cd /opt/intel

    wget https://download.01.org/intel-sgx/sgx-dcap/1.15/linux/distro/ubuntu20.04-server/sgx_debian_local_repo.tgz

    tar xzf sgx_debian_local_repo.tgz

    echo 'deb [trusted=yes arch=amd64] file:///opt/intel/sgx_debian_local_repo focal main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list

    wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -

    sudo apt-get update

    sudo apt-get install -y libsgx-enclave-common-dev  libsgx-ae-qe3 libsgx-ae-qve libsgx-urts libsgx-dcap-ql libsgx-dcap-default-qpl libsgx-dcap-quote-verify-dev libsgx-dcap-ql-dev libsgx-dcap-default-qpl-dev libsgx-quote-ex-dev libsgx-uae-service libsgx-ra-network libsgx-ra-uefi
    ```

* Change PCCS server IP
    ``` shell
    vim /etc/sgx_default_qcnl.conf
    ```
    ``` vi
    # PCCS server address
    PCCS_URL=https://1.2.3.4:8081/sgx/certification/v3/ (your pccs IP)

    # To accept insecure HTTPS certificate, set this option to FALSE
    USE_SECURE_CERT=FALSE
    ```

* Either start eHSM-KMS on a single machine without remote attestation.
    ```
    # run eHSM-KMS
    ./run_with_single.sh
    ```

* Or build and run eHSM-KMS with docker-compose:
    ```shell
    # Download the current stable release (remove the "-x $http_proxy" if you don't behind the proxy)
    sudo curl -x $http_proxy -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
    sudo ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose
    docker-compose --version
    # docker-compose version 1.29.2, build 5becea4c

    # Download the ehsm code from github
    git clone --recursive https://github.com/intel/ehsm.git ehsm && cd ehsm
    vim docker/.env

    # Modify the docker/.env configurations
    HOST_IP=1.2.3.4               # MUST modify it to your host IP.
    PCCS_URL=https://1.2.3.4:8081 # MUST modify it to your pccs server url.
    DKEYSERVER_PORT=8888          # (Optional) the default port of dkeyserver, modify it if you want.
    KMS_PORT=9000                 # (Optional) the default KMS port, modify it if you want.
    TAG_VERSION=main              # (Optional) the default code base is using the main latest branch, modify it to specific tag if you want.

    # start to build and run the docker images (couchdb, dkeyserver, dkeycache, ehsm_kms_service)
    cd docker && docker-compose up -d
    ```

* Enrollment of the APPID and APIKey
    ```shell
    curl -v -k -G "https://<kms_ip>:<port>/ehsm?Action=Enroll"

    {"code":200,"message":"successful","result":{"apikey":"xbtXGHwBexb1pgnEz8JZWHLgaSVb1xSk","appid":"56c46c76-60e0-4722-a6ad-408cdd0c62c2"}}
    ```

* Run the unittest cases
    ``` shell
    cd test
    # run the unit testcases
    python3 test_kms_with_cli.py --url https://<ip_addr>:<port>
    ```

Congratulations! eHSM-KMS service should be ready by now.

# eHSM-KMS Client

eHSM-KMS client requires a credential file to run. The file name of the credential file is `credential.{your_app_id}.json`. The credential file need to be placed in `/run/confidential-containers/cdh/kms-credential/ehsm/`. And the structure of the credential file is shown in `ehsm/example_credential/` folder.

To test eHSM-KMS client, run
```bash
cargo test --features ehsm
```