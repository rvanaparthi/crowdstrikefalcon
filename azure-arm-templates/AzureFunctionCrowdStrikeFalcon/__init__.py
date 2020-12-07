'''
    TITLE:          Crowdstrike Falcon Data Connector
    LANGUAGE:       python 3.8
    VERSION:        1.0
    AUTHOR(S):      Microsoft
    LAST UPDATED:   11/29/2020
    COMMENTS:       Initial Release

    .DESCRIPTION
    This Function App calls the Qualys Vulnerability Management (VM) - KnowledgeBase (KB) API (https://www.qualys.com/docs/qualys-api-vmpc-user-guide.pdf) to pull vulnerability data from the Qualys KB. 
    The response from the Qualys API is recieved in XML format. This function will build the signature and authorization header 
    needed to post the data to the Log Analytics workspace via the HTTP Data Connector API. This Function App will the vulnerability records to the QualysKB_CL table in Azure Sentinel/Log Analytics

    .DISCLAIMER
    Copyright CrowdStrike 2020

    By accessing or using this script, sample code, application programming interface, tools, and/or associated documentation (if any) (collectively, “Tools”), You (i) represent and warrant that You are entering into this Agreement on behalf of a company, organization or another legal entity (“Entity”) that is currently a customer or partner of CrowdStrike, Inc. (“CrowdStrike”), and (ii) have the authority to bind such Entity and such Entity agrees to be bound by this Agreement.

    CrowdStrike grants Entity a non-exclusive, non-transferable, non-sublicensable, royalty free and limited license to access and use the Tools solely for Entity’s internal business purposes and in accordance with its obligations under any agreement(s) it may have with CrowdStrike. Entity acknowledges and agrees that CrowdStrike and its licensors retain all right, title and interest in and to the Tools, and all intellectual property rights embodied therein, and that Entity has no right, title or interest therein except for the express licenses granted hereunder and that Entity will treat such Tools as CrowdStrike’s confidential information.

    THE TOOLS ARE PROVIDED “AS-IS” WITHOUT WARRANTY OF ANY KIND, WHETHER EXPRESS, IMPLIED OR STATUTORY OR OTHERWISE. CROWDSTRIKE SPECIFICALLY DISCLAIMS ALL SUPPORT OBLIGATIONS AND ALL WARRANTIES, INCLUDING WITHOUT LIMITATION, ALL IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR PARTICULAR PURPOSE, TITLE, AND NON-INFRINGEMENT. IN NO EVENT SHALL CROWDSTRIKE BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THE TOOLS, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

'''
import hashlib
import os
import base64
import time
import datetime
import requests
import json
import threading
import traceback

from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential

azureCredential = DefaultAzureCredential()
keyVaultClient = SecretClient(vault_url=keyVaultUri, credential=azureCredential)

#clientId = os.environ["clientId"]
#clientSecret = os.environ["clientSecret"]
clientId = "9c45a593267e486886d785a51f23456d"
clientSecret = "R82lL0zJWIviKnHYDNgEkZxa31O9h45c7MGVCms6"

lines = []

class Token():
    def __init__(self):
        self.payload = 'client_id='+clientId+'&client_secret='+CLIENT_SECRET
        self.url = 'https://api.crowdstrike.com/oauth2/token'
        self.headers = {'content-type': 'application/x-www-form-urlencoded'}
    
    def get(self):
        response = requests.request("POST", self.url, data=self.payload, headers=self.headers)
        r = response.json()
        token = r['access_token']
        return token

class Stream():
    def __init__(self):
        self.app_id = "sampleappid"
        self.discoverURL = "https://api.crowdstrike.com:443/sensors/entities/datafeed/v2?appId=" + self.app_id
        self.token = ""
        self.token_period_start = 0

    def refreshToken(self):
        tokenFetcher = Token()
        self.token = tokenFetcher.get()
        self.token_period_start = time.time()

    def main(self):

        # see if we have a saved offset to resume at, else set it high and get the next event
        try:
            with open("offset", 'r') as f:
                offset = f.readline()
        except :
            offset = 99999999

        # get token
        self.refreshToken()

        # get streams
        response = self.get_streams(self.token)

        # start thread for each stream in environment
        threads = []
        i = 0
        for stream in response['resources']:
            i = i + 1
            data_url = stream['dataFeedURL']
            refreshURL = stream['refreshActiveSessionURL']
            token = stream['sessionToken']['token']
            threads.append(threading.Thread(target=self.stream, args=(data_url, token, offset, refreshURL)))
            threads[-1].start()
            time.sleep(5)
        for t in threads:
            t.join()
            print("Event Occurance Completed")

    # obtains active streams in environment
    def get_streams(self, token):
        headers = {'Authorization': 'bearer ' + token, 'Accept': 'application/json'}
        r = requests.get(self.discoverURL, headers=headers)
        response = r.json()
        return response

    # thread function for streams
    def stream(self, url, token, offset, refreshURL):
        stream_period_start = time.time()
        url += "&offset=%s" %offset
        headers={'Authorization': 'Token %s' % token, 'Connection': 'Keep-Alive'}
        r = requests.get(url, headers=headers, stream=True)
        print("Streaming API Connection established")
        for line in r.iter_lines():
            # print any new streams
            if line:
                decoded_line = line.decode('utf-8')
                decoded_line = json.loads(decoded_line)
                offset = decoded_line.metadata.offset
                lines.append(decoded_line)
            # refresh stream after 25 minutes
            if (time.time() - stream_period_start >= 1500):
                headers = { 'Authorization': 'bearer %s' % self.token, 'Accept': 'application/json', 'Content-Type': 'application/json' }
                payload = { 'action_name': 'refresh_active_stream_session', 'appId': 'my_app_id' }
                response = requests.request("POST", refreshURL, data = payload, headers=headers)
                print("stream refresh code: %s" %(response.status_code))
                stream_period_start = time.time()
            # refresh token after 25 minutes
            if (time.time() - self.token_period_start >= 1500):
                self.refreshToken()
        # Remove file to prevent appending.
        os.remove("offset")
        with open("offset", 'w') as f:
            # Save offset for reuse later.
            f.write(offset)
class AzureSentinel():

    # Build the API signature
    def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
        x_headers = 'x-ms-date:' + date
        string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
        bytes_to_hash = bytes(string_to_hash, encoding="utf-8")  
        decoded_key = base64.b64decode(shared_key)
        encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
        authorization = "SharedKey {}:{}".format(customer_id,encoded_hash)
        return authorization

    # Build and send a request to the POST API
    def post_data(customer_id, shared_key, body, log_type):
        method = 'POST'
        content_type = 'application/json'
        resource = '/api/logs'
        rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
        content_length = len(body)
        signature = build_signature(customer_id, shared_key, rfc1123date, content_length, method, content_type, resource)
        uri = 'https://' + customer_id + '.ods.opinsights.azure.com' + resource + '?api-version=2016-04-01'

        headers = {
            'content-type': content_type,
            'Authorization': signature,
            'Log-Type': log_type,
            'x-ms-date': rfc1123date
        }

        response = requests.post(uri,data=body, headers=headers)
        if (response.status_code >= 200 and response.status_code <= 299):
            print('Accepted')
        else:
            print("Response code: {}".format(response.status_code))

    def main():
        # Should be no overhead, if nothing to process.
        if lines.size:
            #workspaceId = os.environ["workspaceId"]
            #sharedKey = os.environ["workspaceKey"]
            workspaceId = "0bf74ebf-ee26-4537-8e15-d0c67a30b4d8"
            sharedKey = os.environ["workspaceKey"]
            logName = 'CrowdstrikeFalcon'
            body = json.dumps(lines)
            post_data(customerId, sharedKey, body, logName)
    
# start stream class
_stream = Stream()
_stream.main()
AzureSentinel.main()