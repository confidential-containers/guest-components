# EAA KBC module

## EAA Introduction

Enclave Attestation Architecture (EAA) is a general attestation architecture in the cloud native scenario. EAA uses the standard attestation process to establish a secure and trusted TLS channel between EAA KBC and EAA KBS, and uses the TLS channel to send the decryption key of the encryption container image.

EAA supports many different HW-TEE standard attestation processes, e.g: TDX, SEV .etc. (EAA KBC doesn't plan to handle pre-attestation in SEV(-ES). It should be covered by another KBC instance.)

## Dependencies

### rats-tls

Installing and deploying rats-tls: 

```
git clone https://github.com/alibaba/inclavare-containers.git
cd inclavare-containers/rats-tls
cmake -DBUILD_SAMPLES=on -H. -Bbuild
make -C build install
```

Or just make attestation-agent with EAA KBC, it will install and deploying rats-tls automatically:
```
cd attestation-agent 
make KBC=eaa_kbc
```

## EAA KBS

In EAA design, we usually call KBS "verdictd".

Installing and deploying EAA KBS (Verdictd): 

```
git clone https://github.com/alibaba/inclavare-containers.git
cd inclavare-containers/eaa
make && make install
```

Refer to [EAA KBS readme](https://github.com/inclavare-containers/verdictd) to run verdictd and start the KBS service. 

## Usage

Build and run attestation-agent with integrated EAA KBC module: 

```
make KBC=eaa_kbc && make install
RUST_LOG=attestation_agent attestation-agent --keyprovider_sock 127.0.0.1:47777 --getresource_sock 127.0.0.1:48888
```

Set KBC_NAME::KBS_URI pair in the following format: 

```
eaa_kbc::<IP>:<PORT>
```

e.g: EAA KBS address is 127.0.0.1:1122 :

```
eaa_kbc::127.0.0.1:1122
```



