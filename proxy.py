from fastapi import FastAPI, Request
from pydantic import BaseModel
import logging
import aiohttp
import asyncio
from cryptography.hazmat.primitives.asymmetric import ed25519

import yaml
import traceback

from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

config = yaml.safe_load(Path("config.yml").read_text())
config_version = config["version"]
settings = config["settings"]

CRT = settings["crt"]
KEY = settings["key"]

HOST = settings["host"]
PORT = settings["port"]

TIMEOUT = settings["timeout"]

app = FastAPI()

class Payload(BaseModel):
    d: dict 
    op: int = 0
    s: int = 0
    t: str = ""
    id: str = ""

def GenerateSignature(secret: str, event_ts: str, plain_token: str):

    while len(secret) < 32:
        secret = (secret + secret)[:32]

    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(secret.encode())
    message = f"{event_ts}{plain_token}".encode()
    signature = private_key.sign(message).hex()

    return {
        "plain_token": plain_token,
        "signature": signature
    }

async def Call(target: str, headers: dict, data: dict):
    timeout = aiohttp.ClientTimeout(total=TIMEOUT)
    session = aiohttp.ClientSession(timeout=timeout)

    await session.post(
        target,
        headers = headers,
        json = data,
    )

    await session.close()

def Repost(target: str, headers: dict, data: dict):
    loop = asyncio.get_running_loop()
    loop.call_later(
        0,
        lambda: asyncio.create_task(
            Call(target, headers, data)
        )
    )

class Group:
    def __init__(
        self,
        target: str,
        path: str,
        secret: str
    ) -> None:
        self.target = target
        """目标地址"""

        self.path = path
        """代理路径"""

        self.secret = secret
        """密钥"""
    
    def __call__(
        self, 
        request: Request,
        payload: Payload
    ):
        if "event_ts" in payload.d and "plain_token" in payload.d:
            eventTs = payload.d["event_ts"]
            plainToken = payload.d["plain_token"]
            return GenerateSignature(self.secret, eventTs, plainToken)
    
        headers = {}
        for key in [
            "X-Signature-Ed25519",
            "X-Signature-Method",
            "X-Signature-Timestamp",
            "X-Bot-Appid",
            "User_Agent"
        ]:
            if obj := request.headers.get(key):
                headers[key] = obj

        Repost(self.target, headers, payload.dict())

        return {"status": "ok"}

for group in settings["groups"]:
    try:
        app.post(
            group["path"],
        )(
            Group(
                group["target_address"],
                group["path"],
                group["secret"]
            )
        )
        logger.info(f"Group {group['path']} has been created, target: {group['target_address']}")
    except:
        logger.error(f"Group {group['path']} has been created failed")
        logger.error(traceback.format_exc())

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app, host = HOST, port = PORT,
        ssl_keyfile = KEY,
        ssl_certfile = CRT
    )