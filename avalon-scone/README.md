<!--
Licensed under Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by/4.0/
-->

# Hyperledger Avalon Python Worker for SCONE

## Introduction
* Avalon SCONE worker implementation is based on [EEA Trusted Compute Specification](https://entethalliance.github.io/trusted-computing/spec.html).
* [SCONE](https://sconedocs.github.io/) supports running unmodified legacy applications on Intel SGX.
* Avalon SCONE worker supports execution of python workloads inside a docker container in SCONE_MODE=SIM and also in SCONE_MODE=HW environment. It can also be extended to support other SCONE based enclaves.
* Avalon scone worker uses [pycryptodomex](https://pypi.org/project/pycryptodomex/) package for encryption and [ecdsa](https://pypi.org/project/ecdsa/) package for signing and verification.

## Design Assumptions

- Avalon SCONE worker can run as a standalone docker based application and is not dependent on core Avalon framework for building and running the application.
- Avalon SCONE python worker consists of generic classes for work order processing , worker encryption, signing and hash calculation. These classes support work order execution based on EEA Trusted Compute Specification v1.1. 
- Avalon SCONE worker and workloads can be run unmodified in Intel SGX using SCONE containers.
- Avalon SCONE worker can be easily extended to support additional python workloads.
- Avalon SCONE worker can also integrate with other SCONE curated apps running in their respective enclaves and it communicates with them via https connection (certs provisioned via CAS)
- Avalon Enclave Manager and SCONE worker communicates using JSON-RPC via TCP socket. This implementation uses ZMQ socket to send and receive JSON-RPC messages. (This communication is end to end encrypted via keys generated in key management enclave so this communication needs not to be over SSL).
- Avalon SCONE worker uses SCONE-CAS attestation and does not use traditional IAS attestation directly.
- Avalon SCONE worker relies upon SCONE-KME for generation of Signing and Encryption keys. Once KME is set up in trusted enclave, it creates these keys for each worker and securely transmits these keys to SCONE CAS for secret provisioning. 
- Avalon SCONE workers get their keys from CAS when they boot up in context of CAS session after their MR Enclave and filesystem state verification. 
- When they get the keys they register themselves at Avalon Enclave manager via ZMQ socket and wait for requests. 

## Avalon SCONE Examples

In this thesis we have made working examples of real world use cases of trusted compute framework. SCONE based trusted compute workers have following example applications:

### Complete python stack

Developers can add any python based workload that would execute in scone based trsuted workers. As example we have Hello-World, Fibonacci Calculations, Secure Discounted Transaction Demos.

- Hello-World: It is just an echo app. It just appends hello before any string submitted to it. For example if we send 'World' as input, the reponse would be 'Hello World'.

- Fibonacci: It calculates fibonacci of any number submitted to it. Since fibonacci of large numbers is considered a computationally hard problem it is used for benchmarking in this thesis. 

- Secure Discounted Transaction: It is a demo of real-world use case of coins transfer from one wallet to another wallet. Since the execution of smart contracts is not private and the code written in smart contract is also visible to everybody, it is not possible to provide variable discounts to different customers without the other customers knowing about it. But in trusted execution the discount can be provided with each transaction to each customer without anyone knowing about it, other than the two parties involved. This workload can be integrated with smart contracts using blockchain connectors to enable trusted private secure transactions. 

## Building and Running the workers for testing (1) without SCONE/Intel SGX (2) SCONE SIM Mode (3) Unsecure Hardware Mode 

### RUN without Intel SGX

- To run the code for testing without Intel SGX, get the latest code from 'no-cas-fs-unprotected' branch:

  ```bash
  git clone https://github.com/T-Systems-MMS/hyperledger-avalon-scone.git -b no-cas-fs-unprotected
  ```

- You can run docker-compose-scone.yaml from the project root directory:

  ```bash
  docker-compose -f docker-compose-scone.yaml up --build
  docker-compose -f docker-compose-scone.yaml down -v
  ```

### RUN in SCONE SIM Mode

- To run the in SCONE Simulation Mode, get the latest code from 'no-cas-fs-unprotected' branch:

  ```bash
  git clone https://github.com/T-Systems-MMS/hyperledger-avalon-scone.git -b no-cas-fs-unprotected
  ```

- To run the in Simulation Mode, you can run docker-compose-scone-sim.yaml from the project root directory:

  ```bash
  docker-compose -f docker-compose-scone-sim.yaml up --build
  docker-compose -f docker-compose-scone-sim.yaml down -v
  ```

### RUN in SCONE Hardware Mode with No Network and File System Shields (Unsecure)

- To run the in simplified SCONE Hardware Mode, get the latest code from 'no-cas-fs-unprotected' branch:

  ```bash
  git clone https://github.com/T-Systems-MMS/hyperledger-avalon-scone.git -b no-cas-fs-unprotected
  ```

- To run the in Unsecure Hardware Mode, you can run docker-compose-scone-hw.yaml from the project root directory:

  ```bash
  docker-compose -f docker-compose-scone-hw.yaml up --build
  docker-compose -f docker-compose-scone-hw.yaml down -v
  ```

  This will create 5 worker containers registered with Avalon Manager waiting for the requests.

### Test SCONE worker bootstrapped above using Avalon

- To send work orders to SCONE worker we can use [generic client](https://github.com/T-Systems-MMS/hyperledger-avalon-scone/blob/no-cas-fs-unprotected/examples/apps/generic_client/generic_client.py) application. Execute following commands:

  1. Get into Avalon Shell container : `sudo docker exec -it avalon-shell bash`

  2. `cd /project/avalon/examples/apps/generic_client/`

  3. Send work order request with *"python-hello"* workload id to SCONE worker *"scone-worker-1"*

     `./generic_client.py --uri "http://avalon-listener:1947" -w "scone-worker-1" --workload_id "python-hello" --in_data "Mujtaba" -o`

     If everything goes fine, then you should see following output in stdout:

     *Decryption result at client - Hello Mujtaba*

  4. Send work order request with *"python-fib"* workload id to SCONE worker *"scone-worker-1"* 

     `./generic_client.py --uri "http://avalon-listener:1947" -w "scone-worker-1" --workload_id "python-fib" --in_data "5" -o`

     If everything goes fine, then you should see the Fibonacci of 5.

  5. Send work order request with *"secure-transaction"* workload id to SCONE worker *"scone-worker-1"* 

     `./generic_client.py --uri "http://avalon-listener:1947" -w "scone-worker-1" --workload_id "secure-transaction" --in_data "100 100 50 50" -o`

     This input format is (sender_balance, receiver_balance, transfer_amount, discount) If everything goes fine, then you should see the updated balances of sender and receiver.

- Openvino and Hospital apps are only available in hardware mode as they need CAS interaction.

## Adding a new Python Workload

- Avalon Python worker supports two sample workloads: "python-hello" and "python-fib".

- List of sample workloads are listed in *workloads.json* file in [scone_worker](https://github.com/mujtabaidrees94/hyperledger-avalon-scone/blob/master/avalon-scone/scone_worker/workloads.json) directory.

  *{*
      *"python-hello": {*
          *"module": "avalon_worker.workload.hello",*
          *"class": "HelloWorkLoad"*
      *},*
      *"python-fib": {*
          *"module": "avalon_worker.workload.fibonacci",*
          *"class": "FibonacciWorkLoad"*
      *}*
  *}*

- Python workload code is kept in [workload](https://github.com/mujtabaidrees94/hyperledger-avalon-scone/tree/master/avalon-scone/scone_worker/avalon_worker/workload) directory.

- To add a new python workload, keep the python workload implementation class in workload directory and also edit the *workloads.json* file to add new workload. The format of workload in *workloads.json* file is as shown below :

  *"workload-id": {*
          *"module": "<workload python module>",*
          *"class": "<workload implementation class name>"*
      *}*

