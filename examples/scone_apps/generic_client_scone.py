#! /usr/bin/env python3

# Copyright 2019 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import sys
import json
import argparse
import logging
import secrets
import toml
import requests
import subprocess

import config.config as pconfig
import utility.logger as plogger
import utility.hex_utils as hex_utils
import avalon_crypto_utils.crypto_utility as crypto_utility
#import verify_report.verify_attestation_report as attestation_util
from avalon_sdk.worker.worker_details import WorkerType
import avalon_sdk.worker.worker_details as worker_details
from avalon_sdk.work_order.work_order_params import WorkOrderParams
from avalon_sdk.connector.blockchains.ethereum.ethereum_worker_registry_list \
    import EthereumWorkerRegistryListImpl
from avalon_sdk.connector.direct.jrpc.jrpc_worker_registry import \
    JRPCWorkerRegistryImpl
from avalon_sdk.connector.direct.jrpc.jrpc_work_order import \
    JRPCWorkOrderImpl
from avalon_sdk.connector.direct.jrpc.jrpc_work_order_receipt \
    import JRPCWorkOrderReceiptImpl
from error_code.error_status import WorkOrderStatus, ReceiptCreateStatus
import avalon_crypto_utils.signature as signature
from error_code.error_status import SignatureStatus
from avalon_sdk.work_order_receipt.work_order_receipt \
    import WorkOrderReceiptRequest

# Remove duplicate loggers
for handler in logging.root.handlers[:]:
    logging.root.removeHandler(handler)
logger = logging.getLogger(__name__)
TCFHOME = os.environ.get("TCF_HOME", "../../")


def _parse_command_line(args):

    parser = argparse.ArgumentParser()
    mutually_excl_group = parser.add_mutually_exclusive_group()
    parser.add_argument(
        "-c", "--config",
        help="The config file containing the Ethereum contract information",
        type=str)
    mutually_excl_group.add_argument(
        "-u", "--uri",
        help="Direct API listener endpoint, default is http://localhost:1947",
        default="http://localhost:1947",
        type=str)
    mutually_excl_group.add_argument(
        "-a", "--address",
        help="an address (hex string) of the smart contract " +
        "(e.g. Worker registry listing)",
        type=str)
    parser.add_argument(
        "-m", "--mode",
        help="should be one of listing or registry (default)",
        default="registry",
        choices={"registry", "listing"},
        type=str)
    mutually_excl_group_worker = parser.add_mutually_exclusive_group()
    mutually_excl_group_worker.add_argument(
        "-w", "--worker_id",
        help="worker id in plain text to use to submit a work order",
        type=str)
    mutually_excl_group_worker.add_argument(
        "-wx", "--worker_id_hex",
        help="worker id as hex string to use to submit a work order",
        type=str)
    parser.add_argument(
        "-l", "--workload_id",
        help='workload id for a given worker',
        type=str)
    parser.add_argument(
        "-i", "--in_data",
        help='Input data',
        nargs="+",
        type=str)
    parser.add_argument(
        "-p", "--in_data_plain",
        help="Send input data as unencrypted plain text",
        action='store_true')
    parser.add_argument(
        "-r", "--receipt",
        help="If present, retrieve and display work order receipt",
        action='store_true')
    parser.add_argument(
        "-o", "--decrypted_output",
        help="If present, display decrypted output as JSON",
        action='store_true')
    parser.add_argument(
        "-rs", "--requester_signature",
        help="Enable requester signature for work order requests",
        action="store_true")
    options = parser.parse_args(args)

    return options


def _parse_config_file(config_file):
    # Parse config file and return a config dictionary.
    if config_file:
        conf_files = [config_file]
    else:
        conf_files = [TCFHOME +
                      "/sdk/avalon_sdk/tcf_connector.toml"]
    confpaths = ["."]
    try:
        config = pconfig.parse_configuration_files(conf_files, confpaths)
        json.dumps(config)
    except pconfig.ConfigurationException as e:
        logger.error(str(e))
        config = None

    return config


def _retrieve_uri_from_registry_list(config):
    # Retrieve Http JSON RPC listener uri from registry
    logger.info("\n Retrieve Http JSON RPC listener uri from registry \n")
    # Get block chain type
    blockchain_type = config['blockchain']['type']
    if blockchain_type == "Ethereum":
        worker_registry_list = EthereumWorkerRegistryListImpl(
            config)
    else:
        worker_registry_list = None
        logger.error("\n Worker registry list is currently supported only for "
                     "ethereum block chain \n")
        return None

    # Lookup returns tuple, first element is number of registries and
    # second is element is lookup tag and
    # third is list of organization ids.
    registry_count, lookup_tag, registry_list = \
        worker_registry_list.registry_lookup()
    logger.info("\n Registry lookup response: registry count: {} "
                "lookup tag: {} registry list: {}\n".format(
                    registry_count, lookup_tag, registry_list))
    if (registry_count == 0):
        logger.error("No registries found")
        return None
    # Retrieve the fist registry details.
    registry_retrieve_result = worker_registry_list.registry_retrieve(
        registry_list[0])
    logger.info("\n Registry retrieve response: {}\n".format(
        registry_retrieve_result
    ))

    return registry_retrieve_result[0]


def _lookup_first_worker(worker_registry, jrpc_req_id):
    # Get first worker id from worker registry
    worker_id = None
    worker_lookup_result = worker_registry.worker_lookup(
        worker_type=WorkerType.TEE_SGX, id=jrpc_req_id
    )
    logger.info("\n Worker lookup response: {}\n".format(
        json.dumps(worker_lookup_result, indent=4)
    ))
    if "result" in worker_lookup_result and \
            "ids" in worker_lookup_result["result"].keys():
        if worker_lookup_result["result"]["totalCount"] != 0:
            worker_id = worker_lookup_result["result"]["ids"][0]
        else:
            logger.error("ERROR: No workers found")
            worker_id = None
    else:
        logger.error("ERROR: Failed to lookup worker")
        worker_id = None

    return worker_id

'''
def _do_worker_verification(worker_obj):
    # Do worker verfication on proof data if it exists
    # Proof data exists in SGX hardware mode.
    # TODO Need to do verify MRENCLAVE value
    # in the attestation report
    if not worker_obj.proof_data:
        logger.info("Proof data is empty. " +
                    "Skipping verification of attestation report")
    else:
        # Construct enclave signup info json
        enclave_info = {
            'verifying_key': worker_obj.verification_key,
            'encryption_key': worker_obj.encryption_key,
            'proof_data': worker_obj.proof_data,
            'enclave_persistent_id': ''
        }

        logger.info("Perform verification of attestation report")
        verify_report_status = attestation_util.verify_attestation_report(
            enclave_info)
        if verify_report_status is False:
            logger.error("Verification of enclave signup info failed")
            exit(1)
        else:
            logger.info("Verification of enclave signup info passed")

'''
def _do_worker_verification_cas(worker_data, worker_id_hex):
    # Do CAS attestation 
    # Do KME verification by getting its CAS generated certs from CAS
    # SCONE KME generates the secret keys and publishes them
    # in CAS sessions for workers to get them.
    # CAS attests MR Enclave of worker and then provisions the secret keys
    # to the workers.
    # Do worker verification by getting the public keys from CAS

    logger.info("Verification by SCONE CAS")

    try:
        # Reading config to get cas url, kme url & port info
        tcf_home = os.environ.get("TCF_HOME", "/project/avalon")
        config = toml.load(tcf_home + "/config/scone_config.toml")
        scone_cas_alias=config["CAS"]["scone_cas_alias"]
        scone_cas_port=config["CAS"]["scone_cas_port"]
        scone_cas_mr_enclave=config["CAS"]["scone_cas_mr_enclave"]
        scone_cas_url='https://'+scone_cas_alias+':'+scone_cas_port
        scone_kme_alias=config["EnclaveManager"]["scone_kme_alias"]
        scone_kme_port=config["EnclaveManager"]["scone_kme_port"]

        # SCONE CAS Attestation, this is how we ensure cas as root of trust
        result = subprocess.run(['scone', 'cas', 'attest', '--only_for_testing-debug', '--accept-group-out-of-date', scone_cas_alias+':'+scone_cas_port, '--only_for_testing-ignore-signer', scone_cas_mr_enclave], stdout=subprocess.PIPE)
        cas_attestation_res=result.stdout.decode('utf-8')
        cas_attestion_success_msg='CAS '+scone_cas_alias+':'+scone_cas_port+' at '+scone_cas_url+'/ is trustworthy\n'
        if cas_attestation_res != cas_attestion_success_msg:
            logger.error("CAS attestion failed")
            exit(1)

        # Get SCONE CAS CA Cert
        result = subprocess.run(['scone', 'cas', 'show-certificate'], stdout=subprocess.PIPE)
        ca_cert=result.stdout.decode('utf-8')
        f = open("ca_cert.pem", "w")
        f.write(ca_cert)
        f.close()

        # Getting CAS generated SSL certs for KME so we can establish tls connection with KME
        res=requests.get(scone_cas_url+'/v1/values/session='+scone_kme_alias, verify='ca_cert.pem')
        cert_json = json.loads(res.text)
        f = open("kme_cert.pem", "w")
        f.write(cert_json['values']['api_ca_cert']['value'])
        f.close()

        # Calling KME endpoint to get list of valid scone workers publihsed by this KME
        scone_kme_url='https://'+scone_kme_alias+':'+scone_kme_port+'/scone_workers'
        res=requests.get(scone_kme_url, verify='kme_cert.pem')
        logger.info("Valid workers : %s", res.text)
        valid_workers=json.loads(res.text)
        worker_match=False
        valid_matched_worker=""
        for valid_worker_id in valid_workers:
            valid_worker_id_hex=hex_utils.get_worker_id_from_name(valid_worker_id)
            if valid_worker_id_hex == worker_id_hex:
                logger.info("%s is found in KME valid workers list", valid_worker_id)
                valid_matched_worker=valid_worker_id
                worker_match=True
                break
        
        # If our worker is not on the KME's attested workers list then we can not trust this worker
        if worker_match is False:
            logger.error("Worker is not among KME's published list of valid workers")
            exit(1)

        # If worker is found on KME's attested workers list then we get its public keys from CAS
        # These keys were generated by KME and published on CAS by KME enclave
        # As we trust CAS we can establish this chain of trust to get workers public keys
        # If the worker has respective private keys then it means the workflow is end to end secure
        res=requests.get(scone_cas_url+'/v1/values/session='+valid_matched_worker, verify='ca_cert.pem')
        worker_public_keys = json.loads(res.text)
        worker_ver_pub_key=worker_public_keys['values']['signing_public_key']['value']
        worker_enc_pub_key=worker_public_keys['values']['encryption_public_key']['value']
        worker_enc_key_sig=worker_public_keys['values']['encryption_key_signature']['value']

        # Format Encryption Public Key
        worker_enc_pub_key=worker_enc_pub_key.replace("-----BEGIN PUBLIC KEY-----", "start_")
        worker_enc_pub_key=worker_enc_pub_key.replace("-----END PUBLIC KEY-----", "_end")
        worker_enc_pub_key=worker_enc_pub_key.replace(" ","\n")
        worker_enc_pub_key=worker_enc_pub_key.replace("start_", "-----BEGIN PUBLIC KEY-----")
        worker_enc_pub_key=worker_enc_pub_key.replace( "_end", "-----END PUBLIC KEY-----")
        
        # Format Verification Public Key
        worker_ver_pub_key=worker_ver_pub_key.replace("-----BEGIN PUBLIC KEY-----", "start_")
        worker_ver_pub_key=worker_ver_pub_key.replace("-----END PUBLIC KEY-----", "_end")
        worker_ver_pub_key=worker_ver_pub_key.replace(" ","\n")
        worker_ver_pub_key=worker_ver_pub_key.replace("start_", "-----BEGIN PUBLIC KEY-----")
        worker_ver_pub_key=worker_ver_pub_key.replace( "_end", "-----END PUBLIC KEY-----")

        # Updating the public keys fetched from CAS in worker object
        worker_data["workerTypeData"]["verificationKey"]=worker_ver_pub_key
        worker_data["workerTypeData"]["encryptionKey"]=worker_enc_pub_key
        worker_data["workerTypeData"]["encryptionKeySignature"]=worker_enc_key_sig
        
        logger.info("Verification of worker complete")

    except Exception as e:
        logger.error(str(e))
        sys.exit(-1)


def _create_work_order_params(worker_id, workload_id, in_data,
                              worker_encrypt_key, session_key, session_iv,
                              enc_data_enc_key):
    # Convert workloadId to hex
    workload_id = workload_id.encode("UTF-8").hex()
    work_order_id = secrets.token_hex(32)
    requester_id = secrets.token_hex(32)
    requester_nonce = secrets.token_hex(16)
    # Create work order params
    try:
        wo_params = WorkOrderParams(
            work_order_id, worker_id, workload_id, requester_id,
            session_key, session_iv, requester_nonce,
            result_uri=" ", notify_uri=" ",
            worker_encryption_key=worker_encrypt_key,
            data_encryption_algorithm="AES-GCM-256"
            )

    except Exception as err:
        return False, err

    # Add worker input data
    for value in in_data:
        wo_params.add_in_data(value,
                              encrypted_data_encryption_key=enc_data_enc_key)

    # Encrypt work order request hash
    code, out_json = wo_params.add_encrypted_request_hash()
    if not code:
        return code, out_json

    return True, wo_params


def _create_work_order_receipt(wo_receipt, wo_params,
                               client_private_key, jrpc_req_id):
    # Create a work order receipt object using WorkOrderReceiptRequest class.
    # This function will send a WorkOrderReceiptCreate JSON RPC request.
    wo_request = json.loads(wo_params.to_jrpc_string(jrpc_req_id))
    wo_receipt_request_obj = WorkOrderReceiptRequest()
    wo_create_receipt = wo_receipt_request_obj.create_receipt(
        wo_request,
        ReceiptCreateStatus.PENDING.value,
        client_private_key
    )
    logger.info("Work order create receipt request : {} \n \n ".format(
        json.dumps(wo_create_receipt, indent=4)
    ))
    # Submit work order create receipt jrpc request
    wo_receipt_resp = wo_receipt.work_order_receipt_create(
        wo_create_receipt["workOrderId"],
        wo_create_receipt["workerServiceId"],
        wo_create_receipt["workerId"],
        wo_create_receipt["requesterId"],
        wo_create_receipt["receiptCreateStatus"],
        wo_create_receipt["workOrderRequestHash"],
        wo_create_receipt["requesterGeneratedNonce"],
        wo_create_receipt["requesterSignature"],
        wo_create_receipt["signatureRules"],
        wo_create_receipt["receiptVerificationKey"],
        jrpc_req_id
    )
    logger.info("Work order create receipt response : {} \n \n ".format(
        wo_receipt_resp
    ))


def _retrieve_work_order_receipt(wo_receipt, wo_params, jrpc_req_id):
    # Retrieve work order receipt
    receipt_res = wo_receipt.work_order_receipt_retrieve(
        wo_params.get_work_order_id(),
        id=jrpc_req_id
    )
    logger.info("\n Retrieve receipt response:\n {}".format(
        json.dumps(receipt_res, indent=4)
    ))
    # Retrieve last update to receipt by passing 0xFFFFFFFF
    jrpc_req_id += 1
    receipt_update_retrieve = \
        wo_receipt.work_order_receipt_update_retrieve(
            wo_params.get_work_order_id(),
            None,
            1 << 32,
            id=jrpc_req_id)
    logger.info("\n Last update to receipt receipt is:\n {}".format(
        json.dumps(receipt_update_retrieve, indent=4)
    ))

    return receipt_update_retrieve


def _verify_receipt_signature(receipt_update_retrieve):
    # Verify receipt signature
    sig_obj = signature.ClientSignature()
    status = sig_obj.verify_update_receipt_signature(
        receipt_update_retrieve['result'])
    if status == SignatureStatus.PASSED:
        logger.info(
            "Work order receipt retrieve signature verification " +
            "successful")
    else:
        logger.error(
            "Work order receipt retrieve signature verification failed!!")
        return False

    return True


def _verify_wo_res_signature(work_order_res,
                             worker_verification_key,
                             requester_nonce):
    # Verify work order result signature
    sig_obj = signature.ClientSignature()
    status = sig_obj.verify_signature(work_order_res,
                                      worker_verification_key,
                                      requester_nonce)
    if status == SignatureStatus.PASSED:
        logger.info("Signature verification Successful")
    else:
        logger.error("Signature verification Failed")
        return False

    return True


def Main(args=None):
    options = _parse_command_line(args)

    config = _parse_config_file(options.config)
    if config is None:
        logger.error("\n Error in parsing config file: {}\n".format(
            options.config
        ))
        sys.exit(-1)

    # mode should be one of listing or registry (default)
    mode = options.mode

    # Http JSON RPC listener uri
    uri = options.uri
    if uri:
        config["tcf"]["json_rpc_uri"] = uri

    # Address of smart contract
    address = options.address
    if address:
        if mode == "listing":
            config["ethereum"]["direct_registry_contract_address"] = \
                address
        elif mode == "registry":
            logger.error(
                "\n Only Worker registry listing address is supported." +
                "Worker registry address is unsupported \n")
            sys.exit(-1)

    # worker id
    worker_id = options.worker_id
    worker_id_hex = options.worker_id_hex

    worker_id = worker_id_hex if not worker_id \
        else hex_utils.get_worker_id_from_name(worker_id)

    # work load id of worker
    workload_id = options.workload_id
    if not workload_id:
        logger.error("\nWorkload id is mandatory\n")
        sys.exit(-1)

    # work order input data
    in_data = options.in_data

    # Option to send input data in plain text
    in_data_plain_text = options.in_data_plain

    # show receipt in output
    show_receipt = options.receipt

    # show decrypted result in output
    show_decrypted_output = options.decrypted_output

    # requester signature for work order requests
    requester_signature = options.requester_signature

    # setup logging
    config["Logging"] = {
        "LogFile": "__screen__",
        "LogLevel": "INFO"
    }

    plogger.setup_loggers(config.get("Logging", {}))
    sys.stdout = plogger.stream_to_logger(
        logging.getLogger("STDOUT"), logging.DEBUG)
    sys.stderr = plogger.stream_to_logger(
        logging.getLogger("STDERR"), logging.WARN)

    logger.info("******* Hyperledger Avalon Generic client *******")

    if mode == "registry" and address:
        logger.error("\n Worker registry contract address is unsupported \n")
        sys.exit(-1)

    # Retrieve JSON RPC uri from registry list
    if not uri and mode == "listing":
        uri = _retrieve_uri_from_registry_list(config)
        if uri is None:
            logger.error("\n Unable to get http JSON RPC uri \n")
            sys.exit(-1)

    # Prepare worker
    # JRPC request id. Choose any integer value
    jrpc_req_id = 31
    worker_registry = JRPCWorkerRegistryImpl(config)
    if not worker_id:
        # Get first worker from worker registry
        worker_id = _lookup_first_worker(worker_registry, jrpc_req_id)
        if worker_id is None:
            logger.error("\n Unable to get worker \n")
            sys.exit(-1)
    # Retrieve worker details
    jrpc_req_id += 1
    worker_retrieve_result = worker_registry.worker_retrieve(
        worker_id, jrpc_req_id
    )
    logger.info("\n Worker retrieve response: {}\n".format(
        json.dumps(worker_retrieve_result, indent=4)
    ))

    if "error" in worker_retrieve_result:
        logger.error("Unable to retrieve worker details\n")
        sys.exit(1)

    # Create session key and iv to sign work order request
    session_key = crypto_utility.generate_key()
    session_iv = crypto_utility.generate_iv()

    _do_worker_verification_cas(worker_retrieve_result['result']['details'], worker_id)

    # Initializing Worker Object
    worker_obj = worker_details.SGXWorkerDetails()
    worker_obj.load_worker(worker_retrieve_result['result']['details'])

    # Do worker verification
    # _do_worker_verification(worker_obj)


    logger.info("**********Worker details Updated with Worker ID" +
                "*********\n%s\n", worker_id)

    # Create work order
    if in_data_plain_text:
        # As per TC spec, if encryptedDataEncryptionKey is "-" then
        # input data is not encrypted
        encrypted_data_encryption_key = "-"
    else:
        # As per TC spec, if encryptedDataEncryptionKey is not
        # provided then set it to None which means
        # use default session key to encrypt input data
        encrypted_data_encryption_key = None

    code, wo_params = _create_work_order_params(
                            worker_id, workload_id,
                            in_data, worker_obj.encryption_key,
                            session_key, session_iv,
                            encrypted_data_encryption_key)
    if not code:
        logger.error("Work order submission failed: {}\n".format(
            wo_params
        ))
        exit(1)

    client_private_key = crypto_utility.generate_signing_keys()
    if requester_signature:
        # Add requester signature and requester verifying_key
        if wo_params.add_requester_signature(client_private_key) is False:
            logger.info("Work order request signing failed")
            exit(1)

    # Submit work order
    logger.info("Work order submit request : %s, \n \n ",
                wo_params.to_jrpc_string(jrpc_req_id))
    work_order = JRPCWorkOrderImpl(config)
    jrpc_req_id += 1
    response = work_order.work_order_submit(
        wo_params.get_work_order_id(),
        wo_params.get_worker_id(),
        wo_params.get_requester_id(),
        wo_params.to_string(),
        id=jrpc_req_id
    )
    logger.info("Work order submit response : {}\n ".format(
        json.dumps(response, indent=4)
    ))

    if "error" in response and response["error"]["code"] != \
            WorkOrderStatus.PENDING:
        sys.exit(1)

    # Create receipt
    wo_receipt = JRPCWorkOrderReceiptImpl(config)
    if show_receipt:
        jrpc_req_id += 1
        _create_work_order_receipt(wo_receipt, wo_params,
                                   client_private_key, jrpc_req_id)

    # Retrieve work order result
    jrpc_req_id += 1
    res = work_order.work_order_get_result(
        wo_params.get_work_order_id(),
        jrpc_req_id
    )

    logger.info("Work order get result : {}\n ".format(
        json.dumps(res, indent=4)
    ))

    # Check if result field is present in work order response
    if "result" in res:
        # Verify work order response signature
        if _verify_wo_res_signature(res['result'],
                                    worker_obj.verification_key,
                                    wo_params.get_requester_nonce()) is False:
            logger.error("Work order response signature verification Failed")
            sys.exit(1)
        # Decrypt work order response
        if show_decrypted_output:
            decrypted_res = crypto_utility.decrypted_response(
                res['result'], session_key, session_iv)
            logger.info("\nDecrypted response:\n {}"
                        .format(decrypted_res))
    else:
        logger.error("\n Work order get result failed {}\n".format(
            res
        ))
        sys.exit(1)

    if show_receipt:
        # Retrieve receipt
        jrpc_req_id += 1
        retrieve_wo_receipt \
            = _retrieve_work_order_receipt(wo_receipt,
                                           wo_params, jrpc_req_id)
        # Verify receipt signature
        if "result" in retrieve_wo_receipt:
            if _verify_receipt_signature(
                    retrieve_wo_receipt) is False:
                logger.error("Receipt signature verification Failed")
                sys.exit(1)
        else:
            logger.info("Work Order receipt retrieve failed")
            sys.exit(1)


# -----------------------------------------------------------------------------
Main()
