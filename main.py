#!/bin/python
import hmac
import datetime
import json
import os
import sys
import hashlib
import base64
import asyncio
import boto3

from Crypto.Hash import SHA256
from furl import furl
from aiortc.rtcconfiguration import RTCConfiguration, RTCIceServer
from aiortc.rtcicetransport import RTCIceCandidate
from aiortc.rtcpeerconnection import RTCSessionDescription, RTCPeerConnection
from websockets.exceptions import InvalidStatus
import websockets.asyncio.client as ws


# AWS Credentials and Configuration
aws_access_key_id = os.getenv("AWS_ACCESS_KEY_ID")
aws_secret_access_key = os.getenv("AWS_SECRET_ACCESS_KEY")
region_name = os.getenv("AWS_DEFAULT_REGION")

# Channel Configuration
channel = "test"
CLIENT_ID = "PYTHON_CLIENT"


# Validate environment variables
def validate_env_variables():
    if not aws_access_key_id:
        print("AWS access key not set!")
        exit(1)
    if not aws_secret_access_key:
        print("AWS secret access key not set!")
        exit(1)
    if not region_name:
        print("Region name not set!")
        exit(1)


def sign(msg):
    hash = SHA256.new()
    hash.update(msg.encode("utf-8"))
    return hash.digest()


def hmac_sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def get_signature_key(key, date_stamp, region_name, service_name):
    k_date = hmac_sign(("AWS4" + key).encode("utf-8"), date_stamp)
    k_region = hmac_sign(k_date, region_name)
    k_service = hmac_sign(k_region, service_name)
    k_signing = hmac_sign(k_service, "aws4_request")
    return k_signing


def sort_dict(d):
    return dict(sorted(d.items()))


def create_signed_url(endpoint, query_string_params):
    t = datetime.datetime.now(datetime.timezone.utc)
    amz_date = t.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = t.strftime("%Y%m%d")
    DEFAULT_ALGORITHM = "AWS4-HMAC-SHA256"
    DEFAULT_SERVICE = "kinesisvideo"

    credentials = (
        f"{aws_access_key_id}/{date_stamp}/{region_name}/{DEFAULT_SERVICE}/aws4_request"
    )
    query_string_params.update(
        {
            "X-Amz-Algorithm": DEFAULT_ALGORITHM,
            "X-Amz-Credential": credentials,
            "X-Amz-Date": amz_date,
            "X-Amz-Expires": 299,
            "X-Amz-SignedHeaders": "host",
        }
    )

    query_string_params = sort_dict(query_string_params)
    canonical_request = "\n".join(
        [
            "GET",
            str(furl(endpoint).path),
            str(
                furl("").add(
                    query_params=query_string_params | {"X-Amz-SignedHeaders": "host"}
                )
            )[1::],
            f"host:{furl(endpoint).host}\n",
            "host",
            sign("").hex(),
        ]
    )

    string_to_sign = "\n".join(
        [
            DEFAULT_ALGORITHM,
            amz_date,
            f"{date_stamp}/{region_name}/{DEFAULT_SERVICE}/aws4_request",
            sign(canonical_request).hex(),
        ]
    )

    signing_key = get_signature_key(
        aws_secret_access_key, date_stamp, region_name, DEFAULT_SERVICE
    )
    signature = hmac_sign(signing_key, string_to_sign).hex()

    query_string_params["X-Amz-Signature"] = signature
    return furl(endpoint).add(query_string_params).url


def parse_ice_candidate(candidate):
    fields = candidate["candidate"].split(" ")
    return RTCIceCandidate(
        ip=fields[4],
        port=fields[5],
        protocol=fields[7],
        priority=fields[3],
        foundation=fields[0],
        component=fields[1],
        type=fields[7],
        sdpMid=candidate["sdpMid"],
        sdpMLineIndex=candidate["sdpMLineIndex"],
    )


async def create_answer_payload(answer):
    sdp = json.dumps({"type": "answer", "sdp": answer}).encode()
    return await create_websocket_message(
        action="SDP_ANSWER",
        payload=sdp,
    )


async def create_offer_payload(offer):
    sdp = json.dumps({"type": "offer", "sdp": offer}).encode()
    return await create_websocket_message(
        action="SDP_OFFER",
        payload=sdp,
    )


async def create_websocket_message(
    action: str, payload: bytes, client_id: str | None = None
):
    client_id = CLIENT_ID
    return json.dumps(
        {
            "action": action,
            "messagePayload": base64.b64encode(payload).decode("utf-8"),
            "recipientClientId": client_id,
        }
    )


async def process_message(connection, msg, rtcpeer):
    try:

        parsed_msg = json.loads(msg)
        payload = base64.b64decode(parsed_msg["messagePayload"]).decode("utf-8")
        msg_type = parsed_msg["messageType"]

        if msg_type == "SDP_OFFER":
            session_desc = RTCSessionDescription(json.loads(payload)["sdp"], "offer")
            await rtcpeer.setRemoteDescription(session_desc)
            answer = await rtcpeer.createAnswer()
            await rtcpeer.setLocalDescription(answer)
            payload = await create_answer_payload(rtcpeer.localDescription.sdp)
            await connection.send(payload)
        elif msg_type == "ICE_CANDIDATE":
            candidate = parse_ice_candidate(json.loads(payload))
            await rtcpeer.addIceCandidate(candidate)
        elif msg_type == "SDP_ANSWER":
            session_desc = RTCSessionDescription(json.loads(payload)["sdp"], "answer")
            print("answer:", session_desc.sdp)
            await rtcpeer.setRemoteDescription(session_desc)
        else:
            print(f"Unexpected message type: {msg_type}")

    except Exception as e:
        print(f"Failed to process message: {msg}, error: {e}")


async def main():
    role = sys.argv[1].upper()
    validate_env_variables()

    client = boto3.client(
        "kinesisvideo",
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        region_name=region_name,
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
    endpoints = client.get_signaling_channel_endpoint(
        ChannelARN=CHANNEL_ARN,
        SingleMasterChannelEndpointConfiguration={
            "Protocols": ["WSS", "HTTPS"],
            "Role": role,
        },
    )

    signal_endpoint, ice_endpoint = None, None
    for endpoint in endpoints["ResourceEndpointList"]:
        if endpoint["Protocol"] == "WSS":
            signal_endpoint = endpoint["ResourceEndpoint"]
        elif endpoint["Protocol"] == "HTTPS":
            ice_endpoint = endpoint["ResourceEndpoint"]

    assert signal_endpoint is not None
    assert ice_endpoint is not None

    client = boto3.client(
        "kinesis-video-signaling",
        endpoint_url=ice_endpoint,
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        region_name=region_name,
    )

    ice_config = client.get_ice_server_config(ChannelARN=CHANNEL_ARN)
    ice_servers = [
        RTCIceServer(i["Uris"], i["Username"], i["Password"])
        for i in ice_config["IceServerList"]
    ]
    pc = RTCPeerConnection(RTCConfiguration(iceServers=ice_servers))

    @pc.on("signalingstatechange")
    async def on_signalingstatechange():
        print("Signaling state change:", pc.signalingState)
        if pc.signalingState == "stable":
            print("ICE gathering complete")

    @pc.on("iceconnectionstatechange")
    async def on_iceconnectionstatechange():
        print("ICE connection state is", pc.iceConnectionState)
        if pc.iceConnectionState == "failed":
            print("ICE Connection has failed, attempting to restart ICE")

    @pc.on("connectionstatechange")
    async def on_connectionstatechange():
        print("Connection state change:", pc.connectionState)
        if pc.connectionState == "connected":
            print("Peers successfully connected")

    @pc.on("icegatheringstatechange")
    async def on_icegatheringstatechange():
        print("ICE gathering state changed to", pc.iceGatheringState)
        if pc.iceGatheringState == "complete":
            print("All ICE candidates have been gathered.")

    @pc.on("datachannel")
    def on_datachannel(dc):
        @dc.on("message")
        def on_message(message):
            print("Received message from datachannel:", message)

    conn_header = {"X-Amz-ChannelARN": CHANNEL_ARN, "X-Amz-ClientId": CLIENT_ID}
    url = create_signed_url(signal_endpoint + "/", conn_header)

    try:
        connection = await ws.connect(url)
    except InvalidStatus as e:
        print(f"Connection failed with status: {e.response}")
        exit(1)

    if sys.argv[1] == "VIEWER":
        dc = pc.createDataChannel("dc1")

        @dc.on("message")
        def on_message(message):
            print("Received message from datachannel:", message)
            dc.send("sending echo message")

        @dc.on("open")
        def on_open():
            print("datachannel opened")
            dc.send("sent message from viewer ig idk tho")

        offer = await pc.createOffer()
        await pc.setLocalDescription(offer)
        ws_message = await create_offer_payload(pc.localDescription.sdp)
        print(pc.localDescription.sdp)
        await connection.send(ws_message)

    while True:
        try:
            ret = await asyncio.wait_for(connection.recv(), 1)
            asyncio.create_task(process_message(connection, ret, pc))
        except asyncio.TimeoutError:
            continue


if __name__ == "__main__":
    asyncio.run(main())
