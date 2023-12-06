# Trusted Device Manager Architecture

This is an architecture document for the Trusted Device Manager (TDM), a
confidential guest, userspace component for implementing trusted I/O.

## Goals

In order to achieve high performance Input/Output (I/O) operations, confidential
VMs must extend their trust boundary to include a composition of directly
assigned, TEE-IO-capable devices/functions. Without this ability, confidential
VMs have to resort to using para-virtualized I/O using non-confidential memory
regions, which has performance impacts due to memory copies and negates the use
of directly assigned devices.

Silicon vendors and device manufacturers provide TEE-IO compliant hardware
implementations. Intel TDX Connect, AMD SEV-TIO and RISC-V CoVE-IO for example,
rely on device manufacturers to support the TDISP, SPDM and PCIe IDE protocols
to give confidential guests access to trusted MMIO and secure DMA between them
and devices which trustworthiness is verifiable.

The TEE-IO security model is built on top of this hardware support but also on
the ability for confidential guests to ultimately decide if they accept or
reject TEE-IO compliant devices into their TCB. The TDM, as a confidential guest
user space component, supports the Linux guest kernel with making that decision
and then communicating it to the Trusted Security Manager (TSM).

Upon request from the guest kernel, the TDM will attest to the assigned device
trustworthiness through a remote or local attestation process. It then
communicates the attestation results back to the guest kernel, which can then
accept or reject the device respectively into or from its TCB. The kernel then
notifies the TSM about its decision, which implictly transitions the assigned
device into the next TDISP operational state.

## Scope

## Architectural Overview

High-level view:


<pre>
                                  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
                                  ┃             Confidential Guest              ┃
                                  ┃       ╔═════════════════════════════╗       ┃
                                  ┃       ║   Trusted Device Manager    ║       ┃
                                  ┃       ║                             ║       ┃
                                  ┃       ║   ┌─────────────────────┐   ║       ┃
                                  ┃       ║   │ Attestation Module  │   ║       ┃
                                  ┃       ║   └─────────────────────┘   ║       ┃
                                  ┃       ║                             ║       ┃
                                  ┃       ║                             ║       ┃
                                  ┃       ║╔═══════════╗     ╔════════╗ ║       ┃
                                  ┃       ╚╣   CoCo    ╠═════╣ Device ╠═╝       ┃
                                  ┃     ┌─▷║  Module   ║──┐  ║ Plugin ║         ┃
                                  ┃     │  ╚═══════════╝  │  ╚════════╝         ┃
                                  ┃     │                 │       △             ┃
                                  ┃Attestation       Attestation  │             ┃
                                  ┃  Request           Results    │             ┃
                                  ┃     │                 │       │             ┃
                                  ┃     └────┐       ┌────┘       │             ┃
                                  ┃          │       │            │             ┃
                                  ┃          │       │            ▽             ┃
                                  ┃        ┌─┴───────▽┐     ┌──────────┐        ┃
                                  ┃     ┌──┤ CoCo ABI ├─────┤Device ABI├──┐     ┃
                                  ┃     │  └──────────┘     └──────────┘  │     ┃
                                  ┃     │        Linux Guest Kernel       │     ┃
                                  ┃     └─────────────────────────────────┘     ┃
                                  ┗━━━━━━━━━━━━━━━━━━━━━━△━━━━━━━━━━━━━━━━━━━━━━┛
                                                         │
                                                         │
                                                   TEE Guest ABI
                                                         │
                                                         │
                                                         ▽
┏━━━━━━━━━━━━━━━━━━━━━━━┓                    ┏━━━━━━━━━━━━━━━━━━━━━━━┓
┃  Host VMM/Hypervisor  ┃                    ┃   Trusted Security    ┃
┃    (KVM+QEMU/CLH)     ┃◁────TEE Host ABI──▷┃        Manager        ┃
┃                       ┃                    ┃(TDX Module, ASP, etc) ┃
┗━━━━━━━━━━━━━━━━━━━━━━━┛                    ┗━━━━━━━━━━━━━━━━━━━━━━━┛
            △
            ┃
        PCIe Bus
            ┃
            ┃
            ▽
┏━━━━━━━━━━━━━━━━━━━━━━━┓
┃ TEE-IO Compliant PCIe ┃
┃        Device         ┃
┗━━━━━━━━━━━━━━━━━━━━━━━┛

</pre>

Essentially, the TDM is a userspace helper for the guest kernel to attest to
detected PCIe devices. It is part of a hybrid architecture where the guest
kernel and the TDM together verify that an assigned TEE-IO device is trustworthy
or not.

After scanning the host VMM emulated PCIe topology, the guest kernel detects
assigned TEE-IO devices. For each detected device, it must verify and challenge
its authenticity with the TSM support. The last step of the TDISP recommended
device verification flow is about attesting to the device trustworthiness. The
guest kernel relies on a registered TDM to run this attestation step. The TDM
eventually provides the guest kernel with an attestation result, and the guest
kernel can use this result to decide if it accepts or rejects the assigned
device repectively into or from its TCB.

In order for the TDM to achieve the above described goals, it must be able to:

As described above, an VMM-assigned PCIe device verification process is split
between the guest kernel and the TDM. They will go through the following steps:

1. The TDM registers itself against the guest kernel through the Linux kernel
   generic confidential computing (CoCo) userspace ABI. The TDM waits for the
   guest kernel notifications and requests.
2. The **guest kernel** detects VMM-assigned PCIe devices. Those devices are
   part of the guest PCIe topology, which is emulated by the host VMM. In other
   words, a confidential guest must not trust a device detected in this PCIe
   topology. Those devices must be verified before being probed and accepted
   into the guest's TCB.
4. The **guest kernel** verifies the detected device state, as tracked by the
   TSM. In particular, it must verify that the device's TDISP state, and its
   SPDM and TDISP configuration.
5. The **guest kernel** verifies the detected device authenticity. This relies
   on the TSM providing a certificate chain for the device through a
   vendor-specific ABI. The guest kernel verify the certificate chain validity
   and authenticates it against a provisioned trust anchor.
6. The **guest kernel** retrieves the detected device attestation evidence,
   typically from the device certificate chain or through another
   vendor-specific ABI for requesting the TSM to provide such evidence.
7. The **guest kernel** requests the previously registered TDM to attest the
   assigned device. The device attestation evidence is added to the attestation
   request message sent by the guest kernel to the TDM.
8. The **TDM** runs the assigned device attestation and provide attestation
   results back to the guest kernel.
9. The **guest kernel** parses the provided attestation results and decides to
   accept or reject the assigned device.
10. The **guest kernel** notifies the TSM about its decision. When the guest
    kernel accepts the device, the TSM will would enable all memory mapped and
    DMA IO between the TVM and the assigned device.
11. When accepting the assigned device, the **guest kernel** probes it and binds
    it to a kernel driver.

The TDM software architecture is composed of 2 modules:

1. The **TDI Management** module serves attestation requests coming in from the
   guest kernel. This module registers against the Linux kernel CoCo ABI and
   waits for attestation requests. Each such requests is responded to
   synchronously, i.e. the TDI Management module waits for the Device Attesation
   module to verify the provided attestation evidence before replying to the
   request. The attestation request reply contains the attestation results
   provided by the Device Attestation module.
2. The **Device Attestation** module is responsible for verifying a device
   attestation evidence, which can be achieved through local or remote
   attestation. It provides attestation results back to the TDI management
   module.

<pre>
                             ┌────────────────────────┐
                             │ Trusted Device Manager │
  ┌──────────────────────────┴────────────────────────┴───────────────────────────┐
  │                                      ┌ ─ ─ ─ ─ ─ ─ ─ ─ ┐                      │
  │                     ┌───────────┐      ┌─────────────┐       ┌───────────┐    │
  │                     │   Local   │    │ │  Attester   │ │     │Attestation│    │
  │                     │Attestation│─────▷│    Crate    │──────▷│  Service  │◁─┐ │
  │                     └───────────┘    │ └─────────────┘ │     │   Crate   │  │ │
  │ ┌────────────┐            △                                  └───────────┘  │ │
  │ │   Device   │            │          │                 │      ┌─────────┐   │ │
  │ │Attestation │◁──Attestation                                  │Policies │───┘ │
  │ │   Module   │      Token │          │                 │   ┌──┴─────────┴───┐ │
  │ └────────────┘            ▽                                │Reference Values│ │
  │        △            ┌───────────┐    │ ┌─────────────┐ │   └────────────────┘ │      ┌─────────────┐
  │        │            │  Remote   │      │ Attestation │                        │      │             │
  │        │            │Attestation│────┼▷│    Agent    ├─┼──────────────────────┼─────▷│Relying Party│
  │        │            └───────────┘      │    Crate    │                        │      │             │
  │        └──────────┐                  │ └─────────────┘ │                      │      └─────────────┘
  │                   │                                                           │
  │                   │                  │   Attestation   │                      │
  │                   │                         Agent                             │
  │                   │                  └ ─ ─ ─ ─ ─ ─ ─ ─ ┘                      │
  │                   ▽                                                           │
  │┌────────────────────────────────────┐                                         │
  ││       TDI Management Module        │                                         │
  │├───────────┬┬───────────────────────┤                                         │
  ││           ││ Device Vendor Plugins │                                         │
  ││   CoCo    ││┌──────┐ ┌──────┐ ┌───┐│                                         │
  ││  Module   │││NVIDIA│ │ BCOM │ │...││                                         │
  ││           ││└──────┘ └──────┘ └───┘│                                         │
  │└─▲───────┳─┘└───────────┳───────────┘                                         │
  └──╋───────╋──────────────╋─────────────────────────────────────────────────────┘
     ┃       ┃              ┃
Attestation  ┃              ┃
  Request    ┃          Device ABI
     ┃       ┃              ┃
     ┃  Attestation         ┃
     ┃    Results           ┃
     ┃       ┃              ┃
   ┌─┻───────▼──────────────▼────────────┐
   │         Linux Guest Kernel          │───────┐
   └─────┬─────────────────────────┬─────┘       │
         │                         │             │
   Accept/Reject             Authenticate        │
         │                         │             │
         └───────────┬─────────────┘             │
                     │                        Detects
                     │                          and
                     │                        Enables
                     ▽                           │
       ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┓             │        ┏━━━━━━━━━━━━━━━━━━━━━━━┓
       ┃ Trusted Security Manager  ┃             │        ┃TEE-IO Device Interface┃
       ┃  (TDX Module, ASP, etc)   ┃             └───────▶┃         (TDI)         ┃
       ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━┛                      ┗━━━━━━━━━━━━━━━━━━━━━━━┛
                     │                                                ▲
                                                                      │
                     └ ─ ─ ─ ─ ─ ─ ─ ─ ─Via VMM─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─

</pre>

### TDI Management

The TDI Management module is the interface between the TDM and the guest kernel,
and it's main responsibility is to serve incoming attestation requests with
attestation results.

This modules relies on the guest kernel to provide the following capabilities
through the Linux CoCo ABI:

- Accept TDM registration. The TDM must be able to register itself against the
  guest kernel as a device attestation service provider.
- Send device attestation requests to the registered TDM, when the kernel
  requires device to be attested before accepting it, i.e. before probing it.
- Receive device attestation results from the registered TDM in order to decide
  if a device can be accepted into the guest TCB or not.

#### Attestation Request

#### Attestation Results

TODO (sameo) Define attestation results payload content format: Use
[IETF EAT Attestation Results][EAR] (Serialized [AR4SI][AR4SI]).

#### Vendor Plugins

### Device Attestation

#### Local Attestation

#### Remote Attestation

## Theory of Operations

TODO (sameo): Elaborate

### TDI Detection

1. Guest kernel detects the TDI
2. Guest kernel verifies the TDI state
3. Guest kernel verifies the TDI authenticity
4. Guest kernel requests TDM to attest to the TDI

### TDI Attestation

1. TDM runs TDI attestation
2. TDM replies with TDI attestation results

### TDI Acceptance

1. Guest kernel parses the TDI attestation results.
2. Guest kernel notifies the TSM that it accepts the TDI
3. Guest kernel probes the TDI and binds it to a driver.

## Glossary

| Term | Acronym | Definition |
|:-----|:-------:|------------|
| Confidential Computing                 | CoCo   | The protection of data in use by performing computation in a Hardware-based TEE.
| Confidential VM                        | CVM    | A confidential computing virtual machine. Same as a TVM.
| Device Security Manager                | DSM    | A DSM is a logical entity on a TEE-IO device that enforces the TDISP security policies, attributes and states.
| Integrity and Data Encryption          | IDE    | Extended PCIe capability for integrity, confidentiality and replay protection of PCIe Transport Layer Packets (TLP).
| Security Protocol and Data Model       | SPDM   | A DMTF defined specification for exchanging messages between devices over a variety of transports and physical media. SPDM is used to exchange TDISP and IDE Key Management messages over PCIe DOE mailboxes.
| TEE Device Interface Security Protocol | TDISP  | An architecture for trusted I/O virtualization.
| TEE Input and Output                   | TEE-IO | A PCIe-defined conceptual framework for establishing and managing trust relationships between a PCIe device and a TEE.
| TEE I/O Device Interface               | TDI    | The unit of assignment for a trusted I/O capable device. For example, a TDI can be a Virtual Function (VF) or a Physical Function (PF).
| TEE VM                                 | TVM    | A VM instantiation of an confidential workload.
| Trusted Device Manager                 | TDM    | A confidential guest TEE-IO device manager, responsible for verifying, attesting and accepting CoVE-IO devices into a TVM TCB. This is a TVM guest software stack component.

[EAR]: https://datatracker.ietf.org/doc/html/draft-fv-rats-ear-02
[AR4SI]: https://datatracker.ietf.org/doc/html/draft-ietf-rats-ar4si-05
