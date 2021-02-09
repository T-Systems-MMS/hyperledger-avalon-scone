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

import worker_signing
import worker_encryption
import worker_hash
import requests
import os
import sys
import toml
import json
import random
import string
from flask import Flask
from OpenSSL import crypto, SSL
 

app = Flask(__name__)

tcf_home = os.environ.get("TCF_HOME", "/project/avalon")
scone_workers_list=[]


def generate_self_signed_certs(
    commonName="www.scontain.com",
    countryName="US",
    localityName="Saxony",
    stateOrProvinceName="Dresden",
    organizationName="Scontain",
    organizationUnitName="Org",
    validityStartInSeconds=0,
    validityEndInSeconds=31*24*60*60,
    KEY_FILE = tcf_home + "/client-key.key",
    CERT_FILE = tcf_home + "/client.crt"):
    #can look at generated file using openssl:
    #openssl x509 -inform pem -in selfsigned.crt -noout -text
    # create a key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 4096)
    # create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = countryName
    cert.get_subject().ST = stateOrProvinceName
    cert.get_subject().L = localityName
    cert.get_subject().O = organizationName
    cert.get_subject().OU = organizationUnitName
    cert.get_subject().CN = commonName
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(validityEndInSeconds)
    cert.set_serial_number(random.randrange(100000))
    cert.set_version(2)
    cert.add_extensions([
        crypto.X509Extension(b'subjectAltName', False,
            ','.join([
                'DNS:www.scontain.com']).encode()),
        crypto.X509Extension(b"basicConstraints", True, b"CA:false")])
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha256')
    f = open(CERT_FILE, "wt")
    f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
    f.close()
    f = open(KEY_FILE, "wt")
    f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))
    f.close()

def main(args=None):
    # Generate self signed worker certs which can be used with various cas workflows
    generate_self_signed_certs()
    km = KeyManager()
    app.run(host='0.0.0.0', port=5000, ssl_context=(tcf_home+'/cert.pem', tcf_home+'/key.pem'))

    
@app.route('/scone_workers')
def get_workers():
    workers_json = json.dumps([ob.__dict__ for ob in scone_workers_list])
    return workers_json

@app.route('/scone_worker_session/<worker_id>')
def get_worker_session(worker_id):
    worker_session_id='invalid'
    for valid_worker in scone_workers_list:
        if valid_worker.worker_id==worker_id:
            worker_session_id=valid_worker.worker_session_id   
    return worker_session_id

class Avalon_Scone_Workers:  
    def __init__(self, worker_id, worker_session_id):  
        self.worker_id = worker_id  
        self.worker_session_id = worker_session_id

class KeyManager():

    def __init__(self):
        """
        Constructor to generate worker signing and encryption keys.
        """
        self._upload_worker_sessions()

    def _upload_worker_sessions(self):
        """
        Generates worker signing and encryption keys.
        """
        try:
            config = toml.load(tcf_home + "/config/scone_config.toml")
        
            # Get worker encryption tags
            fspf_key=os.environ["WORKER_FS_KEY"]
            fspf_tag=os.environ["WORKER_FS_TAG"]
            Worker_MREnclave=os.environ["WORKER_MRENCLAVE"]
            # Generate worker signing key
            print("Generate worker signing and encryption keys")
            num_of_enclaves = int(config["EnclaveModule"]["num_of_enclaves"])
            print("num_of_enclaves ", num_of_enclaves)
            count = 0
            while count < num_of_enclaves:
                count = count + 1
                worker_id_template = config["WorkerConfig"]["worker_id_template"]
                worker_id = worker_id_template.replace("-n", "-" + str(count))
                letters_and_digits = string.ascii_letters + string.digits
                #worker_session_id=worker_id
                worker_session_id=''.join((random.choice(letters_and_digits) for i in range(10)))
                print("worker_id ", worker_id)
                sign = worker_signing.WorkerSign()
                sign.generate_signing_key()
                worker_public_sign_key = sign.get_public_sign_key()
                worker_private_sign_key = sign.get_private_sign_key()
                # Generate worker encryption key
                encrypt = worker_encryption.WorkerEncrypt()
                encrypt.generate_rsa_key()
                worker_public_enc_key = encrypt.get_rsa_public_key()
                worker_private_enc_key = encrypt.get_rsa_private_key()
                # Sign worker encryption key hash
                hash_obj = worker_hash.WorkerHash()
                hash_val = hash_obj.compute_message_hash(worker_public_enc_key)
                worker_public_enc_key_sign = sign.sign_message(hash_val)
                # create session
                f = open(tcf_home+"/config/session_template.yml", "r")
                session_file=f.read()
                f.close()
                session_file=session_file.replace("encryption_private_key_value","\""+worker_private_enc_key.decode("utf-8")+"\"")
                session_file=session_file.replace("encryption_public_key_value","\""+worker_public_enc_key.decode("utf-8")+"\"")
                session_file=session_file.replace("signing_private_key_value","\""+worker_private_sign_key.decode("utf-8")+"\"")
                session_file=session_file.replace("signing_public_key_value","\""+worker_public_sign_key.decode("utf-8")+"\"")
                session_file=session_file.replace("encryption_key_signature_value","\""+worker_public_enc_key_sign.hex()+"\"")
                # Uploading expected MREnclave of worker in KME session
                session_file=session_file.replace("MR_ENCLAVE", Worker_MREnclave)
                session_file=session_file.replace("WORKER_ID", worker_session_id)
                session_file=session_file.replace("WORKER_FSPF_TAG", fspf_tag)
                session_file=session_file.replace("WORKER_FSPF_KEY", fspf_key)

                scone_cas_alias=config["CAS"]["scone_cas_alias"]
                scone_cas_port=config["CAS"]["scone_cas_port"]
                scone_cas_url='https://'+scone_cas_alias+':'+scone_cas_port

                p = requests.post(scone_cas_url+'/session', session_file.encode(), verify=tcf_home+'/cas-ca.pem', cert=(tcf_home+'/client.crt', tcf_home+'/client-key.key'))
                
                if p.text.find("\"hash\":")>=0:
                    print ('Session uploaded for : ', worker_id)
                    scone_workers_list.append( Avalon_Scone_Workers(worker_id, worker_session_id) )
                else:
                    print("Error in session uploading")
                    print(p.text)

        except Exception as e:
            print(str(e))
            sys.exit(-1)


main()
