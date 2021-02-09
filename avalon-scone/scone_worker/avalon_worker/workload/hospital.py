#!/usr/bin/python3

# Copyright 2020 Mujtaba Idrees
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
import string
import toml
import requests
import sys
import logging
import json
import os
from workload.workload import WorkLoad

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.StreamHandler(sys.stdout))

# -------------------------------------------------------------------------


class HospitalWorkLoad(WorkLoad):
    """
    Hospital workload class. This is an example workload.
    """

# -------------------------------------------------------------------------

    def execute(self, in_data_array):
        """
        Executes Hospital workload.
        Parameters :
            in_data_array: Input data array containing data in plain bytes
        Returns :
            status as boolean and output result in bytes.
        """
        logger.info("Execute Hospital API workload")
        data_plain_bytes = in_data_array[0]["data"]

        try:
            tcf_home = os.environ.get("TCF_HOME", "/project/avalon")
            config = toml.load(tcf_home + "/config/scone_config.toml")

            scone_cas_alias=config["CAS"]["scone_cas_alias"]
            scone_cas_port=config["CAS"]["scone_cas_port"]
            scone_cas_url='https://'+scone_cas_alias+':'+scone_cas_port
            hospital_app_url=config["WorkloadExecution"]["hospital_app_url"]
            hospital_app_session=config["WorkloadExecution"]["hospital_app_session"]

            # Getting SSL certs from CAS for Hospital App so we can establish tls connection
            res=requests.get(scone_cas_url+'/v1/values/session='+hospital_app_session, verify=tcf_home+'/cas-ca.pem')
            cert_json = json.loads(res.text)
            f = open("hospital_cert.pem", "w")
            f.write(cert_json['values']['api_ca_cert']['value'])
            f.close()

            data_str = data_plain_bytes.decode("UTF-8")
            data_arr=data_str.split('&')
            data_str_api= data_str.replace(data_arr[0]+'&'+data_arr[1]+'&', '')

            method_arr=data_arr[0].split('=')
            id_arr=data_arr[1].split('=')

            if method_arr[1] == "add_patient":
                params=dict((itm.split('=')[0],itm.split('=')[1]) for itm in data_str_api.split('&'))
                # Calling Hospital App endpoint 
                res=requests.post(hospital_app_url+'/patient/'+id_arr[1], data=params, verify='hospital_cert.pem')
                out_msg=res.text

            elif method_arr[1] == "get_patient":
                res=requests.get(hospital_app_url+'/patient/'+id_arr[1], verify='hospital_cert.pem')
                out_msg=res.text

            elif method_arr[1] == "get_patient_score":
                res=requests.get(hospital_app_url+'/score/'+id_arr[1], verify='hospital_cert.pem')
                out_msg=res.text

            else: 
                out_msg = "Illegal Method Submitted"

            out_msg_bytes = out_msg.encode("utf-8")
            result = True

        except Exception as e:
            out_msg = "Error processing hospital workload: " + str(e)
            out_msg_bytes = out_msg.encode("utf-8")
            logger.error(out_msg)
            result = False
        return result, out_msg_bytes

# -------------------------------------------------------------------------


