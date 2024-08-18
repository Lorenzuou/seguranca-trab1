# Copyright 2022 Cartesi Pte. Ltd.
#
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use
# this file except in compliance with the License. You may obtain a copy of the
# License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.

from os import environ
import traceback
import logging
import requests
import json
import os 
import json
import traceback
import requests

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

logging.basicConfig(level="INFO")
logger = logging.getLogger(__name__)

rollup_server = environ["ROLLUP_HTTP_SERVER_URL"]
logger.info(f"HTTP rollup_server url is {rollup_server}")



import json
import traceback
import requests


def hex2str(hex):
    """
    Decodes a hex string into a regular string
    """
    return bytes.fromhex(hex[2:]).decode("utf-8")

def str2hex(str):
    """
    Encodes a string as a hex string
    """
    return "0x" + str.encode("utf-8").hex()


def handle_advance(data):
    logger.info(f"Received advance request data {data}")

    status = "accept"
    try:

        input = hex2str(data["payload"])
        data = json.loads(input)
        # query the public key to check if it is already in the data.json file and its status is "valid"
        with open('data.json', 'r') as file:
            json_array = json.load(file)
            logger.info(f"json_array: {json_array}")

        for i in range(len(json_array)):
            logger.info(f"public_key: {json_array[i]['public_key']}, data_public_key: {data['public_key']}")
            logger.info(json_array[i]["public_key"] == data["public_key"])
            if json_array[i]["public_key"] == data["public_key"]:
                if json_array[i]["status"] == "reject":
                    return "reject"
        # Extract and decode the public key, message, and signature
        public_key_pem = data["public_key"].encode('utf-8')
        message = data["message"].encode('utf-8')
        status_message = data["status"]
        signature = bytes.fromhex(data['signature'])

        # if status is "reject", query the data.json based on the "public_Key" file and set its status to "reject"
        if status_message == "reject":
            with open('data.json', 'r') as file:
                json_array = json.load(file)
            for i in range(len(json_array)):
                logger.info(json_array[i]["public_key"] == data["public_key"])
                if json_array[i]["public_key"] == data["public_key"]:
                    json_array[i]["status"] = "reject"
            with open('data.json', 'w') as file:
                json.dump(json_array, file, indent=4)

            output = json.dumps(data)
            response = requests.post(rollup_server + "/notice", json={"payload": str2hex(str(output))})
            return "accept"
        
       
        # Deserialize the public key
        public_key = RSA.import_key(public_key_pem)

        # Verify the signature
        try:
            h = SHA256.new(message)
            try: 
                pkcs1_15.new(public_key).verify(h, signature)
            except ValueError:
                logger.error("Signature verification failed.")
                raise
            logger.info("Signature is valid.")
        except (ValueError, TypeError) as e:
            logger.error(f"Signature verification failed: {e}")
            return "reject"
        # Turn into JSON
        output = json.dumps(data)
        # Emits notice with result of calculation
        logger.info(f"Adding notice with payload: '{output}'")
        response = requests.post(rollup_server + "/notice", json={"payload": str2hex(str(output))})
        logger.info(f"Received notice status {response.status_code} body {response.content}")

        try:
            with open('data.json', 'r') as file:
                json_array = json.load(file)
        except FileNotFoundError:
            json_array = []
    
        json_array.append(data)

        with open('data.json', 'w') as file:
            json.dump(json_array, file, indent=4)
    except Exception as e:
        status = "reject"
        msg = f"Error processing data {data}\n{traceback.format_exc()}"
        logger.error(msg)
        response = requests.post(rollup_server + "/report", json={"payload": str2hex(msg)})
        logger.info(f"Received report status {response.status_code} body {response.content}")

    return status
def handle_inspect(data):
    logger.info(f"Received inspect request data {data}")
    logger.info("Adding report")

    with open('data.json', 'r') as file:
        json_array = json.load(file)

    output = json.dumps(json_array)
    response = requests.post(rollup_server + "/report",
                             json={"payload": str2hex(str(output))})

    logger.info(f"Received report status {response.status_code}")
    return "accept"

handlers = {
    "advance_state": handle_advance,
    "inspect_state": handle_inspect,
}

finish = {"status": "accept"}

while True:
    logger.info("Sending finish")
    response = requests.post(rollup_server + "/finish", json=finish)
    logger.info(f"Received finish status {response.status_code}")
    if response.status_code == 202:
        logger.info("No pending rollup request, trying again")
    else:
        rollup_request = response.json()
        data = rollup_request["data"]
        
        handler = handlers[rollup_request["request_type"]]
        finish["status"] = handler(rollup_request["data"])
