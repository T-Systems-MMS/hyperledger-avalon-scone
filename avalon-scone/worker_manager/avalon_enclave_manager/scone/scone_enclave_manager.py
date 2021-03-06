#!/usr/bin/env python3

# Copyright 2020 Intel Corporation
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

import argparse
import json
import logging
import os
import sys
import random
import threading
import copy

from avalon_enclave_manager.base_enclave_manager import EnclaveManager
from avalon_enclave_manager.work_order_processor_manager \
    import WOProcessorManager
from avalon_enclave_manager.scone.scone_enclave_info \
    import SignupScone
from utility.zmq_comm import ZmqCommunication

logger = logging.getLogger(__name__)


# -------------------------------------------------------------------------


class SconeEnclaveManager(WOProcessorManager):
    """
    Manager class to handle Scone based work order processing
    """

    def __init__(self, config, zmq_socket):
        """
        Constructor for Scone Enclave Manager

        Parameters :
            config: Configuration for Scone Enclave Manager class
        """
        self.zmq_socket=zmq_socket
        super().__init__(config)
        self.proof_data_type = config.get("WorkerConfig")["ProofDataType"]
        self._identity = self._worker_id

# -------------------------------------------------------------------------

    def _manager_on_boot(self):
        """
        Executes Boot flow of enclave manager
        """
        logger.info("Executing boot time procedure")

        # Add a new worker
        worker_info = EnclaveManager.create_json_worker(self, self._config)
        # Hex string read from config which is 64 characters long
        worker_id = self._worker_id
        self._worker_kv_delegate.add_new_worker(worker_id, worker_info)
        # Update mapping of worker_id to workers in a pool
        self._worker_kv_delegate.update_worker_map(
            worker_id, self._identity)

        # Cleanup all stale work orders for this worker which
        # used old worker keys
        self._wo_kv_delegate.cleanup_work_orders()

# -------------------------------------------------------------------------

    def _create_signup_data(self):
        """
        Creates Scone worker signup data.

        Returns :
            signup_data: Signup data containining information of worker
                         like public encryption and verification key,
                         worker quote, mrencalve.
                         In case of error return None.
        """
        json_request = self._create_json_request("ProcessWorkerSignup", None)
        try:
            # Send signup request to Scone worker
            worker_signup = self.zmq_socket.send_request_zmq(
                                            json.dumps(json_request))
        except Exception as ex:
            logger.error("Exception while sending data over ZMQ:" + str(ex))
            return None

        if worker_signup is None:
            logger.error("Unable to get Scone worker signup data")
            return None
        logger.debug("Scone signup result {}".format(worker_signup))
        try:
            worker_signup_json = json.loads(worker_signup)
        except Exception as ex:
            logger.error("Exception during signup json creation:" + str(ex))
            return None
        # Create Signup Scone object
        signup_data = SignupScone(worker_signup_json)
        return signup_data

# -------------------------------------------------------------------------

    def _execute_wo_in_trusted_enclave(self, input_json_str):
        """
        Submits workorder request to Scone Worker and retrieves
        the response

        Parameters :
            input_json_str: JSON formatted str of the request to execute
        Returns :
            JSON response received from Scone worker.
        """
        json_request = self._create_json_request("ProcessWorkOrder",
                                                 input_json_str)
        result = self.zmq_socket.send_request_zmq(json.dumps(json_request))
        if result is None:
            logger.error("Scone work order execution error")
            return None
        try:
            json_response = json.loads(result)
        except Exception as ex:
            logger.error("Error loading json execution result: " + str(ex))
            return None
        return json_response

# -------------------------------------------------------------------------
    # TODO: Move this function to common/python/utiity/jrpc_utility.py
    def _create_json_request(self, method_name, params=None):
        """
        Creates JSON RPC request

        Parameters :
            method_name: JSON RPC method name
            params: JSON RPC params
        Returns :
            JSON RPC request.
        """
        json_request = {}
        json_request["jsonrpc"] = "2.0"
        json_request["id"] = random.randint(0, 100000)
        json_request["method"] = method_name
        json_request["params"] = params

        return json_request

# -----------------------------------------------------------------

# mutithreaded enclave manager
def manage_enclave_thread(config, scone_zmq_url):
    logger.info("worker connected : %s", config.get("WorkerConfig")["worker_id"])
    logger.info("scone_zmq_url connected : %s", scone_zmq_url)
    zmq_socket = ZmqCommunication(scone_zmq_url)
    zmq_socket.connect()
    enclave_manager = SconeEnclaveManager(config, zmq_socket)
    logger.info("About to start Scone Enclave manager")
    enclave_manager.start_enclave_manager()

# -----------------------------------------------------------------

def main(args=None):
    import config.config as pconfig
    import utility.logger as plogger

    # parse out the configuration file first
    tcf_home = os.environ.get("TCF_HOME", "../../../")

    conf_files = ["scone_config.toml"]
    conf_paths = [".", tcf_home + "/"+"config"]

    parser = argparse.ArgumentParser()
    parser.add_argument("--config", help="configuration file", nargs="+")
    parser.add_argument("--config-dir", help="configuration folder", nargs="+")
    parser.add_argument("--worker_id_template",
                        help="Id of worker in plain text", type=str)

    (options, remainder) = parser.parse_known_args(args)

    if options.config:
        conf_files = options.config

    if options.config_dir:
        conf_paths = options.config_dir

    try:
        config = pconfig.parse_configuration_files(conf_files, conf_paths)
        json.dumps(config, indent=4)
    except pconfig.ConfigurationException as e:
        logger.error(str(e))
        sys.exit(-1)

    if options.worker_id_template:
        config["WorkerConfig"]["worker_id_template"] = options.worker_id_template

    plogger.setup_loggers(config.get("Logging", {}))
    sys.stdout = plogger.stream_to_logger(
        logging.getLogger("STDOUT"), logging.DEBUG)
    sys.stderr = plogger.stream_to_logger(
        logging.getLogger("STDERR"), logging.WARN)

    EnclaveManager.parse_command_line(config, remainder)
    try:
        #logger.info("config : %s", config)

        # zmq socket has to be created before calling super class constructor
        # super class constructor calls _create_signup_data() which uses
        # socket for communicating with Scone worker.
        num_of_enclaves = int(config.get("EnclaveModule")["num_of_enclaves"])
        logger.info("num_of_enclaves %s", num_of_enclaves)
        count = 0
        thread_list = []
        while count < num_of_enclaves:
            count = count + 1
            scone_zmq_url_template = config.get("EnclaveManager")["scone_zmq_url_template"]
            scone_zmq_url=scone_zmq_url_template.replace("-n", "-"+str(count))
            logger.info("scone_zmq_url %s", scone_zmq_url)
            worker_id_template = config.get("WorkerConfig")["worker_id_template"]
            worker_id=worker_id_template.replace("-n", "-"+str(count))
            logger.info("worker_id %s", worker_id)
            config["WorkerConfig"]["worker_id"]=worker_id
            thread = threading.Thread(target=manage_enclave_thread, args=(copy.deepcopy(config), copy.deepcopy(scone_zmq_url)))
            thread_list.append(thread)

        for thread in thread_list:
            thread.start()

        for thread in thread_list:
            thread.join()

    except Exception as ex:
        logger.error("Error starting Scone Enclave Manager: " + str(ex))
    # Disconnect ZMQ socket.
    #if self.zmq_socket:
    #    self.zmq_socket.disconnect()


main()
