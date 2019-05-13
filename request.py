import json
import requests
import datetime
import hashlib
import hmac
import base64
import sys

# Update the customer ID to your Log Analytics workspace ID
customer_id = 'af7ddb70-d3e7-41cd-a182-1aac535ed246'

# For the shared key, use either the primary or the secondary Connected Sources$
shared_key = "o1HZ+hFFkC3A435GvW6cMjOaVBh3pRnvKYwjNwYQxUjCZ1iQAVGe3s3OoD0tqaw1IeEz7KAMTshANkthntzRCg=="

# The log type is the name of the event that is being submitted
log_type = 'WebMonitorTest_CL'

# An example JSON web monitor object
json_data = [{
"service": sys.argv[1]
    }]
body = json.dumps(json_data)

#####################
######Functions######  
#####################

# Build the API signature
def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    x_headers = 'x-ms-date:' + date
    string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
    bytes_to_hash = bytes(string_to_hash).encode('utf-8')  
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest())
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
        print ("Accepted")

post_data(customer_id, shared_key, body, log_type)
