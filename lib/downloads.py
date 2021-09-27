import os
import uuid
import requests
import ssl
import hashlib
import httpx
import urllib3.exceptions
import http.client

from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_fixed

MAX_RETRY_WAIT = 10
MAX_RETRY_STOP = 3


def sha256sum(fname):
    sha256 = hashlib.sha256()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


@retry(
    retry=(
        retry_if_exception_type(OSError) |
        retry_if_exception_type(httpx.HTTPError) |
        retry_if_exception_type(urllib3.exceptions.HTTPError) |
        retry_if_exception_type(http.client.HTTPException) |
        retry_if_exception_type(ssl.SSLError) |
        retry_if_exception_type(requests.exceptions.ConnectionError)
    ),
    wait=wait_fixed(MAX_RETRY_WAIT),
    stop=stop_after_attempt(MAX_RETRY_STOP),
)
def download_with_retry(url, path, sha256=None):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    client = httpx.Client()
    try:
        with client.stream("GET", url) as resp:
            resp.raise_for_status()
            tmp_path = f"{path}.{uuid.uuid4()}.part"
            with open(tmp_path, "wb") as out_file:
                for chunk in resp.iter_raw():
                    out_file.write(chunk)
    except Exception as e:
        raise http.client.HTTPException from e
    tmp_sha256 = sha256sum(tmp_path)
    if sha256 and tmp_sha256 != sha256:
        raise Exception(f"{os.path.basename(url)}: wrong SHA256: {tmp_sha256} != {sha256}")
    os.rename(tmp_path, path)
    return path
