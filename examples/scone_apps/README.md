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

### Openvino

Openvino is a machine learning based computer vision tool. Various models can be added in it, and based on these models it can detect certain things when fed with an image or video. Based on this detection various realworld applications can be made such as facebook uses facial recognition. 

As an example we have added vehicle detection model in SCONE curated openvino image. If snaps and videos of security camera are provided to the workload it can detect the vehicles and their licenses. It is interesting with the aspect that such complex application can not be programmed in blockchain based smart contract. Hence we use SCONE based trusted execution environment to serve as an attested oracle for blockchain.

### Hospital Patient Management System

This example demonstrates a hospital app running inside SCONE based trusted execution environment. The patient's data in a hospital is critical with respect to privacy. If this data is kept on public servers it can be subjected to root admin attack. Moreover if we need to use this data with a smart contract in blockchain it can not be done in privacy preserving way until we maintain it with Avalon. 

This app has a redis data store and python backend. We use SCONE curated redis and python containers and run both inside trusted enclaves and then integrate this app with our trusted workers so that it can be used with Avalon ecosystem and also with blockchains.

## Building and Running the worker without SCONE or SCONE SIM Mode

- For SIM Mode we need to install Intel SGX driver and SCONE. (Skip this step if you are running without Intel SGX)

  - To install Intel SGX driver please refer https://github.com/hyperledger/avalon/blob/master/PREREQUISITES.md#intel-sgx-in-hardware-mode
  - To install SCONE please refer https://sconedocs.github.io/installation/

- To build Avalon SCONE worker get the latest code from 'simulation' branch:
  
  ```bash
  git clone https://git.t-systems-mms.com/scm/confcom/secure-avalon.git -b simulation
  ```
- To run without Intel SGX hardware and SCONE, you can run docker-compose-scone.yaml from the project root directory:

  ```bash
  docker-compose -f docker-compose-scone.yaml up --build
  docker-compose -f docker-compose-scone.yaml down -v
  ```

- To run with SCONE SIM mode, you can run docker-compose-scone-sim.yaml from the project root directory:

  ```bash
  docker-compose -f docker-compose-scone-sim.yaml up --build
  docker-compose -f docker-compose-scone-sim.yaml down -v
  ```

  This will create 5 worker containers registered with Avalon Manager waiting for the requests.

### Test SCONE worker using Avalon

- To send work orders to SCONE worker we can use [generic client](https://git.t-systems-mms.com/projects/CONFCOM/repos/secure-avalon/browse/examples/apps/generic_client/generic_client.py?at=refs%2Fheads%2Fsimulation) application. Execute following commands:

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

## Building and Running the worker in SCONE Hardware Mode

- Before building and running application for SCONE HW Mode, we need to install Intel SGX driver and SCONE.

  - To install Intel SGX driver please refer https://github.com/hyperledger/avalon/blob/master/PREREQUISITES.md#intel-sgx-in-hardware-mode
  - To install SCONE please refer https://sconedocs.github.io/installation/

- To build Avalon SCONE worker get the latest code from master branch:

  ```bash
  git clone https://git.t-systems-mms.com/scm/confcom/secure-avalon.git
  ```

- To run the in Hardware Mode, you can run scone-demo.sh script from the project root directory:
  ```bash
  ./scone-demo.sh start
  ./scone-demo.sh stop
  ```
  This will create 5 worker containers registered with Avalon Manager waiting for the requests.

### Test SCONE worker using Avalon

- To send work orders to SCONE worker we can use [scone generic client](https://git.t-systems-mms.com/projects/CONFCOM/repos/secure-avalon/browse/examples/scone_apps/generic_client_scone.py) application. Execute following commands:

  1. Get into Avalon Shell container : `sudo docker exec -it avalon-shell bash`

  2. `cd /project/avalon/examples/scone_apps/`

  3. Send work order request with *"python-hello"* workload id to SCONE worker *"scone-worker-1"*

     `./generic_client_scone.py --uri "http://avalon-listener:1947" -w "scone-worker-1" --workload_id "python-hello" --in_data "Mujtaba" -o`

     If everything goes fine, then you should see following output in stdout:

     *Decryption result at client - Hello Mujtaba*

  4. Send work order request with *"python-fib"* workload id to SCONE worker *"scone-worker-1"* 

     `./generic_client_scone.py --uri "http://avalon-listener:1947" -w "scone-worker-1" --workload_id "python-fib" --in_data "5" -o`

     If everything goes fine, then you should see the Fibonacci of 5.

  5. Send work order request with *"secure-transaction"* workload id to SCONE worker *"scone-worker-1"* 

     `./generic_client_scone.py --uri "http://avalon-listener:1947" -w "scone-worker-1" --workload_id "secure-transaction" --in_data "100 100 50 50" -o`

     This input format is (sender_balance, receiver_balance, transfer_amount, discount) If everything goes fine, then you should see the updated balances of sender and receiver.

  6. Send work order request with *"scone-openvino"* workload id to SCONE worker *"scone-worker-1"* 

     `./generic_client_scone.py --uri "http://avalon-listener:1947" -w "scone-worker-1" --workload_id "scone-openvino" --in_data "car1.jpg" -o`

     This input 'car1.jpg' is name of one of the hardcoded input images provided in openvino container. If everything goes fine, then you should see the message asking you to check output in openvino application output folder. 

  7. Send work order request with *"scone-hospital-app"* workload id to SCONE worker *"scone-worker-1"* 

     `./generic_client_scone.py --uri "http://avalon-listener:1947" -w "scone-worker-1" --workload_id "scone-hospital-app" --in_data "method=add_patient&id=patient_1&fname=Jane&lname=Doe&address='123 Main Street'&city=Richmond&state=Washington&ssn=123-223-2345&email=nr@aaa.com&dob=01/01/2010&contactphone=123-234-3456&drugallergies='Sulpha, Penicillin, Tree Nut'&preexistingconditions='diabetes, hypertension, asthma'&dateadmitted=01/05/2010&insurancedetails='Primera Blue Cross'" -o`

     This input is patient object in query parameters format along with method name 'add_patient'. If everything goes fine, then you should see added patient data echoed back. 

     `./generic_client_scone.py --uri "http://avalon-listener:1947" -w "scone-worker-1" --workload_id "scone-hospital-app" --in_data "method=get_patient&id=patient_1" -o`

     This input is patient id along with method name 'get_patient'. If everything goes fine, then you should see added patient data echoed back. 

     `./generic_client_scone.py --uri "http://avalon-listener:1947" -w "scone-worker-1" --workload_id "scone-hospital-app" --in_data "method=get_patient_score&id=patient_1" -o`

     This input is patient id along with method name 'get_patient_score'. If everything goes fine, then you should see the patients health score as per hospital records. 


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

