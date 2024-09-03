#!/bin/python
import hmac
from Crypto.Hash import SHA256
import datetime
from aiortc.rtcconfiguration import RTCConfiguration
from aiortc.rtcicetransport import RTCIceCandidate
from aiortc.rtcpeerconnection import RTCSessionDescription
import requests
from furl import furl
import aiortc
from urllib3 import request
import websockets.asyncio.client as ws
import json
import os
import boto3
from aiortc.mediastreams import asyncio
from websockets.exceptions import InvalidStatus
import hashlib
import base64
import sys

# from aiortc import rtcpeerconnection

aws_access_key_id = os.getenv("AWS_ACCESS_KEY_ID")
aws_secret_access_key = os.getenv("AWS_SECRET_ACCESS_KEY")
channel = "test"
region_name = os.getenv("AWS_DEFAULT_REGION")

if aws_access_key_id == None:
    print("aws acess key not set!")
    exit(0)
if aws_secret_access_key == None:
    print("aws secret access key not set!")
    exit(0)

if region_name == None:
    print("region name not set!")
    exit(0)


def add_query_string_to_url(endpoint, query_params):
    return furl(endpoint).add(query_params)


def sign(msg):
    hash = SHA256.new()
    hash.update(msg.encode("utf-8"))
    return hash.digest()


def hmac_sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def getSignatureKey(key, date_stamp, regionName, serviceName):
    kDate = hmac_sign(("AWS4" + key).encode("utf-8"), date_stamp)
    kRegion = hmac_sign(kDate, regionName)
    kService = hmac_sign(kRegion, serviceName)
    kSigning = hmac_sign(kService, "aws4_request")
    return kSigning


def sort_dict(dict):
    myKeys = list(dict.keys())
    myKeys.sort()
    sorted_dict = {i: dict[i] for i in myKeys}
    return sorted_dict


def create_signed_url(endpoint, query_string_params):
    t = datetime.datetime.now(datetime.timezone.utc)
    DEFAULT_ALGORITHM = "AWS4-HMAC-SHA256"
    DEFAULT_SERVICE = "kinesisvideo"
    amz_date = t.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = t.strftime("%Y%m%d")
    f_url = furl(endpoint)
    path = f_url.path
    hosts = f_url.host
    assert region_name is not None
    original_credentials = (
        date_stamp + "/" + region_name + "/" + DEFAULT_SERVICE + "/aws4_request"
    )
    assert aws_access_key_id is not None
    credentials = (
        aws_access_key_id
        + "/"
        + date_stamp
        + "/"
        + region_name
        + "/"
        + DEFAULT_SERVICE
        + "/aws4_request"
    )
    query_string_params = query_string_params | {
        "X-Amz-Algorithm": DEFAULT_ALGORITHM,
        "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
        "X-Amz-Credential": credentials,
        "X-Amz-Date": amz_date,
        "X-Amz-Expires": 299,
    }

    query_string_params = sort_dict(query_string_params)
    signed_host = ";".join(["host"])
    query_string = furl("").add(
        query_params=query_string_params | {"X-Amz-SignedHeaders": "host"}
    )
    canonicalRequest = [
        "GET",
        str(path),
        str(query_string)[1::],
        f"host:{str( hosts )}\n",
        signed_host,
        (sign("").hex()),
    ]
    canonicalRequest = "\n".join(canonicalRequest)

    canonicalRequestHash = sign(canonicalRequest).hex()

    stringToSign = [
        DEFAULT_ALGORITHM,
        amz_date,
        original_credentials,
        (str(canonicalRequestHash)),
    ]
    stringToSign = "\n".join(stringToSign)
    signingKey = getSignatureKey(
        aws_secret_access_key, date_stamp, region_name, DEFAULT_SERVICE
    )
    # (signature) = hmac_sign(signingKey, stringToSign)
    (signature) = hmac_sign(
        signingKey,
        stringToSign,
    )

    query_string_params = query_string_params | {
        "X-Amz-Signature": signature.hex(),
        "X-Amz-SignedHeaders": "host",
    }
    query_string_params = sort_dict(query_string_params)
    endpoint = add_query_string_to_url(endpoint, query_string_params)
    return endpoint


assert len(sys.argv) > 1
role = sys.argv[1]
CLIENT_ID = "PYTHON_CLIENT"

client = boto3.client(
    "kinesisvideo",
    aws_access_key_id=os.getenv("aws_access_key_id"),
    aws_secret_access_key=os.getenv("aws_secret_access_key"),
    region_name=os.getenv("aws_default_region"),
)

try:
    channel_description = client.describe_signaling_channel(ChannelName=channel)
except:
    channel_description = client.create_signaling_channel(
        ChannelName=channel,
        ChannelType="SINGLE_MASTER",
        SingleMasterConfiguration={"MessageTtlSeconds": 90},
    )

CHANNEL_ARN = channel_description["ChannelInfo"]["ChannelARN"]
signal_endpoints = client.get_signaling_channel_endpoint(
    ChannelARN=CHANNEL_ARN,
    SingleMasterChannelEndpointConfiguration={
        "Protocols": ["WSS", "HTTPS"],
        "Role": role.upper(),
    },
)

signal_endpoint = None
ice_endpoint = None
for i in signal_endpoints["ResourceEndpointList"]:
    if i["Protocol"] == "WSS":
        signal_endpoint = i["ResourceEndpoint"]
    if i["Protocol"] == "HTTPS":
        ice_endpoint = i["ResourceEndpoint"]

assert signal_endpoint is not None
assert signal_endpoint is not None


client = boto3.client(
    "kinesis-video-signaling",
    endpoint_url=ice_endpoint,
    aws_access_key_id=os.getenv("aws_access_key_id"),
    aws_secret_access_key=os.getenv("aws_secret_access_key"),
    region_name=os.getenv("aws_default_region"),
)
ice_config = client.get_ice_server_config(ChannelARN=CHANNEL_ARN)
ice_server_list = ice_config["IceServerList"]
ice_servers = []
for i in ice_server_list:
    ice_servers.append(aiortc.RTCIceServer(i["Uris"], i["Username"], i["Password"]))
config = RTCConfiguration(ice_servers)
rtcpeer = aiortc.RTCPeerConnection(config)


conn_header = {"X-Amz-ChannelARN": CHANNEL_ARN, "X-Amz-ClientId": CLIENT_ID}
url = create_signed_url(signal_endpoint + "/", conn_header)

print(url)


def parse_ice_candidate(candidate):
    ip = candidate["candidate"].split(" ")[4]
    port = candidate["candidate"].split(" ")[5]
    protocol = candidate["candidate"].split(" ")[7]
    priority = candidate["candidate"].split(" ")[3]
    foundation = candidate["candidate"].split(" ")[0]
    component = candidate["candidate"].split(" ")[1]
    candidate_type = candidate["candidate"].split(" ")[7]
    rtc_candidate = RTCIceCandidate(
        ip=ip,
        port=port,
        protocol=protocol,
        priority=priority,
        foundation=foundation,
        component=component,
        type=candidate_type,
        sdpMid=candidate["sdpMid"],
        sdpMLineIndex=candidate["sdpMLineIndex"],
    )
    return rtc_candidate


async def generate_answer_payload(answer):
    global signal_endpoint
    sdp = json.dumps({"type": "answer", "sdp": answer}).encode()
    req = {
        "action": "SDP_ANSWER",
        "messagePayload": base64.b64encode(sdp).decode("utf-8"),
        "recipientClientId": CLIENT_ID,
        # "CorrelationId": "17252873849432440_0",
    }

    return json.dumps(req)


async def process_message(connection, msg):
    try:
        parsed_msg = json.loads(msg)
        payload = parsed_msg["messagePayload"]
        decoded_payload = base64.b64decode(payload)
        decoded_payload = decoded_payload.decode("utf-8")
        msg_type = parsed_msg["messageType"]
        if msg_type == "SDP_OFFER":
            json_payload = json.loads(decoded_payload)
            session_desc = RTCSessionDescription(json_payload["sdp"], "offer")
            await rtcpeer.setRemoteDescription(session_desc)
            answer = await rtcpeer.createAnswer()
            assert answer is not None
            await rtcpeer.setLocalDescription(answer)
            payload = await generate_answer_payload(rtcpeer.localDescription.sdp)
            await connection.send(payload)
        elif msg_type == "ICE_CANDIDATE":
            candidate = parse_ice_candidate(json.loads(decoded_payload))
            await rtcpeer.addIceCandidate(candidate)
        else:
            print(msg)
    except Exception as e:
        print(e)
        print("failed to parse message ", msg)


@rtcpeer.on("datachannel")
def on_datachannel(channel):
    print(channel, "-", "created by remote party")

    @channel.on("message")
    def on_message(message):
        print("recieved message from datachannel", message)


async def main():
    try:
        connection = await ws.connect(url.url)
    except InvalidStatus as e:
        print(e.response)
        exit()

    if len(sys.argv) == 3:
        if sys.argv[2].lower() == "test":
            await connection.send(
                '{"action":"SDP_OFFER","messagePayload":"eyJzZHAiOiJvZmZlcj0gdHJ1ZVxudmlkZW89IHRydWUiLCJ0eXBlIjoib2ZmZXIifQ=="}'
            )

    while True:
        try:
            ret = await asyncio.wait_for(connection.recv(), 1)
            asyncio.create_task(process_message(connection, ret))
            continue
        except:
            pass


asyncio.run(main())
