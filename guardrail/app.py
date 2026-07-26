from fastapi import FastAPI
from pydantic import BaseModel
from pathlib import Path
from urllib.parse import urlparse
import base64
import re
import shlex

app = FastAPI()

WORKSPACE = Path("/home/agent/workspace")
HOME = Path("/home/agent")
SECRET = HOME / ".npmrc"

WRITE_ROOT = Path("/srv/reports")

ALLOWED_HOSTS = {
    "registry.npmjs.org",
    "pypi.org",
}


def normalize(path: str, base: Path):
    p = Path(path)

    if not p.is_absolute():
        p = base / p

    return p.resolve(strict=False)


def expand_command(cmd: str):

    cmd = cmd.replace("~", str(HOME))
    cmd = cmd.replace("$HOME", str(HOME))
    cmd = cmd.replace("${HOME}", str(HOME))

    # Decode embedded Base64 strings
    for s in re.findall(r"[A-Za-z0-9+/=]{16,}", cmd):
        try:
            decoded = base64.b64decode(s).decode("utf-8")
            cmd += " " + decoded
        except Exception:
            pass

    return cmd


def reads_secret(command: str):

    cmd = expand_command(command)

    try:
        tokens = shlex.split(cmd)
    except Exception:
        tokens = cmd.split()

    for token in tokens:

        if token.startswith("/"):
            p = normalize(token, WORKSPACE)
            if p == SECRET:
                return True

        elif token.startswith(".") or token.startswith(".."):
            p = normalize(token, WORKSPACE)
            if p == SECRET:
                return True

    if str(SECRET) in cmd:
        return True

    return False


def write_allowed(path: str):

    p = normalize(path, WRITE_ROOT)
    root = WRITE_ROOT.resolve(strict=False)

    return p == root or root in p.parents


def host_allowed(url: str):

    try:
        host = urlparse(url).hostname
        if host is None:
            return False
        return host.lower() in ALLOWED_HOSTS
    except Exception:
        return False


@app.post("/check")
async def check(call: dict):

    tool = call.get("tool")

    if tool == "bash":

        if reads_secret(call.get("command", "")):
            return {
                "decision": "block",
                "reason": "Access to protected file is forbidden."
            }

        return {
            "decision": "allow",
            "reason": "Command permitted."
        }

    elif tool == "write_file":

        if write_allowed(call.get("path", "")):
            return {
                "decision": "allow",
                "reason": "Write allowed."
            }

        return {
            "decision": "block",
            "reason": "Write outside permitted directory."
        }

    elif tool == "http_request":

        if host_allowed(call.get("url", "")):
            return {
                "decision": "allow",
                "reason": "Host allowed."
            }

        return {
            "decision": "block",
            "reason": "Host not permitted."
        }

    return {
        "decision": "allow",
        "reason": "No policy for this tool."
    }


@app.get("/")
def root():
    return {"status": "ok"}
