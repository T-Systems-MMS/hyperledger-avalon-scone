<!--
Licensed under Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by/4.0/
-->

<img src="images/HL_Avalon_Logo_Color.png" width="318" height="87"
 alt="Hyperledger Avalon logo" />

# Hyperledger Avalon

Hyperledger Avalon (formerly Trusted Compute Framework)
enables privacy in blockchain transactions,
moving intensive processing from a main blockchain to improve scalability and
latency, and to support attested Oracles.

The Trusted Compute Specification was designed to help developers gain the
benefits of computational trust and to mitigate its drawbacks. In the case of
the Avalon, a blockchain is used to enforce execution
policies and ensure transaction auditability, while associated off-chain
trusted compute resources execute transactions. By using trusted off-chain
compute resources, a developer can accelerate throughput and improve data
privacy.

Preservation of the integrity of execution and the enforcement
of confidentiality guarantees come through the use of a Trusted Compute (TC)
option, e.g. ZKP (Zero Knowledge Proof), MPC (Multi Party Compute),
or a hardware-based TEE (Trusted Execution Environment).
While the approach will work with any TC option that guarantees integrity and
confidentiality for code and data, our initial implementation uses
Intel® Software Guard Extensions (SGX).

Hyperledger Avalon leverages the existence of a distributed ledger to
 * Maintain a registry of the trusted workers (including their attestation info)
 * Provide a mechanism for submitting work orders from a client(s) to a worker
 * Preserve a log of work order receipts and acknowledgments

Hyperledger Avalon uses the
[ _Off-Chain Trusted Compute Specification_](https://entethalliance.github.io/trusted-computing/spec.html)
defined by Enterprise Ethereum Alliance (EEA) Task Force as a starting point to
apply a consistent and compatible approach to all supported blockchains.

For more details on Hyperledger Avalon architecture, see
[_avalon-arch.pdf_](docs/avalon-arch.pdf).

# Hyperledger Avalon with SCONE

This particular fork of Hyperledger Avalon is made at its stable release v0.6
that supports blockchain integration and basic registry service for trusted compute workers. 
We provide SCONE based workers for Hyperledger Avalon that can be used to run legacy 
applications within the framework of Hyperledger Avalon. 

For whitepaper, see
[_Hyperledger-Avalon-Scone-Whitepaper.pdf_](docs/whitepaper_avalon_scone.pdf).

For demo of the applications running with SCONE workers, see
[_Hyperledger-Avalon-Scone-Demo.mp4_](https://drive.google.com/file/d/1cvAZFJGkGXEHFVFMG_QnTOEDjZFlpgbO/view?usp=sharing).
[![Hyperledger Avalon SCONE demo](../images/avalon-scone-screenshot.PNG](https://drive.google.com/file/d/1cvAZFJGkGXEHFVFMG_QnTOEDjZFlpgbO/view?usp=sharing)

## Building

To build Hyperledger Avalon, follow instructions in the
[build document](BUILD.md).

## Documentation

[Hyperledger Avalon Documentation](https://hyperledger.github.io/avalon/)

[Scone Documentation](https://scontain.com/index.html?lang=en)

## Contributing

See the [contributing document](CONTRIBUTING.md)
for information on how to contribute and the guidelines for contributions.

## Initial Committers
* Manjunath A C (manju956)
* Daniel Anderson (danintel)
* Thomas J Barnes (TomBarnes)
* Srinath Duraisamy (srinathduraisamy)
* Manoj Gopalakrishnan (manojgop)
* Karthika Murthy (Karthika)
* Ramakrishna Srinivasamurthy (ram-srini)
* Yevgeniy Y. Yarmosh (EugeneYYY)
* Mujtaba Idrees (mujtabaidrees94)

## Sponsor
* Mic Bowman (cmickeyb) - TSC member
* Technische Universität Dresden
* T-Systems MMS

## License
Hyperledger Avalon is released under the Apache License
Version 2.0 software license. See the [license file](LICENSE) for more details.

Hyperledger Avalon documentation is licensed under the
Creative Commons Attribution 4.0 International License. You may obtain a copy
of the license at: http://creativecommons.org/licenses/by/4.0/.

© Copyright 2019-2020, Intel Corporation.
