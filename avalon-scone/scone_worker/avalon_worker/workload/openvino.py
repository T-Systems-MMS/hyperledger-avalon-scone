#!/usr/bin/python3

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
import os
import random
import string
import toml
import requests
import sys
import logging
import json
from workload.workload import WorkLoad

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.StreamHandler(sys.stdout))

# -------------------------------------------------------------------------


class OpenvinoWorkLoad(WorkLoad):
    """
    Openvino workload class. This is an example workload.
    """

# -------------------------------------------------------------------------

    def execute(self, in_data_array):
        """
        Executes Openvino workload.
        Parameters :
            in_data_array: Input data array containing data in plain bytes
        Returns :
            status as boolean and output result in bytes.
        """
        logger.info("Execute Openvino workload")
        data_plain_bytes = in_data_array[0]["data"]

        try:
            tcf_home = os.environ.get("TCF_HOME", "/project/avalon")
            config = toml.load(tcf_home + "/config/scone_config.toml")

            data_str = data_plain_bytes.decode("UTF-8")
            openvino_template=config["WorkloadExecution"]["openvino_template"]
            openvino_template_arr=openvino_template.split('-')
            session_name = openvino_template_arr[0]+'-'+os.environ["SELF_IDENTITY"]
            rand_str=''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(20))
            PATH = 'session_log.txt'
            opv_session_file=''
            # if session file already exists, it means we have to update the session
            if os.path.isfile(PATH) and os.access(PATH, os.R_OK):
                f = open("session_log.txt", "r")
                prev_session_hash=f.read()
                f.close()
                f = open(tcf_home + "/config/openvino_session_template.yml", "r")
                opv_session_file=f.read()
                f.close()
                opv_session_file=opv_session_file+'\npredecessor: '+prev_session_hash
            
            # else we must create the session
            else:
                f = open(tcf_home + "/config/openvino_session_template.yml", "r")
                opv_session_file=f.read()
                f.close()

            # Adding actual values to session template
            opv_session_file=opv_session_file.replace("SESSION_NAME",session_name)
            opv_session_file=opv_session_file.replace("IMAGE_NAME",data_str)
            opv_session_file=opv_session_file.replace("RANDOM_STRING",rand_str)
        

            scone_cas_alias=config["CAS"]["scone_cas_alias"]
            scone_cas_port=config["CAS"]["scone_cas_port"]
            scone_cas_url='https://'+scone_cas_alias+':'+scone_cas_port

            # Post session add/update request to CAS
            # certs used in this req are the ones which are generated at worker boot up
            res = requests.post(scone_cas_url+'/session', opv_session_file.encode(), verify=tcf_home+'/cas-ca.pem', cert=(tcf_home+'/client.crt', tcf_home+'/client-key.key'))
            session_upload_response=json.loads(res.text)

            # writes the session hash to file so it could be used to update session for next req
            f = open("session_log.txt", "wt")
            f.write(session_upload_response['hash'])
            f.close()

            out_msg = "Workload submitted to openvino enclave see output folder"
            out_msg_bytes = out_msg.encode("utf-8")
            result = True

        except Exception as e:
            out_msg = "Error processing ovenvino workload: " + str(e)
            out_msg_bytes = out_msg.encode("utf-8")
            logger.error(out_msg)
            result = False
        return result, out_msg_bytes

# -------------------------------------------------------------------------


