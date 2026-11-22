import base64
import collections
import collections.abc
import datetime
import gzip
import io
import json
import logging
import os
import re
import shutil
import socketserver
import subprocess
import time
import urllib.parse
import uuid
import zlib

collections.Callable = collections.abc.Callable

import brotli
import PyPDF2
import yara
from pyicap import BaseICAPRequestHandler, ICAPServer

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")

YARA_RULE_PATH = os.getenv(
    "NETWORK_YARA_RULE_PATH",
    os.path.join(os.path.dirname(__file__), "sensitive.yar"),
)
LOG_FILE = os.getenv("NETWORK_DLP_LOG", "/var/log/network_dlp.log")
MAX_PAYLOAD_SIZE = 15 * 1024 * 1024

compiled_rules = yara.compile(filepath=YARA_RULE_PATH)
log_cache = {}


def check_is_spam(client_ip, url, action, file_name, rule_matched=""):
    now = time.time()

    try:
        domain = urllib.parse.urlparse(url).netloc if url.startswith("http") else url[:50]
    except Exception:
        domain = url[:50]

    signature = f"{client_ip}_{domain}_{action}_{file_name}_{rule_matched}"

    if signature in log_cache and now - log_cache[signature] < 10:
        return True

    log_cache[signature] = now

    if len(log_cache) > 500:
        expired_keys = [key for key, value in log_cache.items() if now - value > 10]
        for key in expired_keys:
            del log_cache[key]

    return False


def write_log(client_ip, url, action, rule_matched="", size=0, file_name="Unknown_File"):
    record = {
        "timestamp": datetime.datetime.now().isoformat(),
        "module": "network_dlp",
        "dlp_action": action,
        "srcip": client_ip,
        "src_ip": client_ip,
        "destination_url": url,
        "url": url,
        "payload_size": size,
        "file_path": file_name,
        "targetFilename": file_name,
        "path": file_name,
        "target": file_name,
        "file": file_name,
        "rule_matched": rule_matched,
    }

    try:
        with open(LOG_FILE, "a", encoding="utf-8") as stream:
            stream.write(json.dumps(record) + "\n")
    except OSError:
        logging.error("Cannot write network DLP log; inspect file permissions")


def get_filename(headers, payload, req_url, host):
    candidates = []

    try:
        decoded = urllib.parse.unquote(req_url)
        for name in ("name=", "filename=", "title=", "file=", "path="):
            if name in decoded:
                candidates.append(
                    decoded.split(name, 1)[1].split("&", 1)[0].split("/")[-1]
                )
    except Exception:
        pass

    for match in re.finditer(b'(?:filename|name)="([^"]+)"', payload[:16384]):
        candidate = match.group(1).decode("utf-8", "ignore")
        candidates.append(candidate.split("\\")[-1].split("/")[-1])

    ignored_names = (
        "blob",
        "unknown_file",
        "null",
        "undefined",
        "document",
        "file",
        "form-data",
        "chunk",
    )

    for name in candidates:
        name = name.strip()
        if name.lower() not in ignored_names and 0 < len(name) < 150:
            return name

    return "Unknown_File"


def decode_advanced_encodings(payload):
    decoded = b""
    target = payload[:1048576]
    pattern = re.compile(b"[A-Za-z0-9+/_-]{20,}={0,2}")

    for match in pattern.finditer(target):
        try:
            value = match.group(0)
            value += b"=" * ((4 - len(value) % 4) % 4)
            result = base64.urlsafe_b64decode(value)
            if len(result) > 5:
                decoded += result + b"\n"
        except Exception:
            pass

    if b"\\u" in target:
        try:
            decoded += target.decode("unicode_escape").encode("utf-8")
        except Exception:
            pass

    return decoded


def extract_deep_content(payload):
    extracted = b""
    start = payload.find(b"%PDF-")

    if start != -1:
        try:
            end = payload.rfind(b"%%EOF")
            pdf = payload[start : end + 5] if end != -1 else payload[start:]
            reader = PyPDF2.PdfReader(io.BytesIO(pdf))
            for page in reader.pages:
                text = (page.extract_text() or "") + "\n"
                extracted += text.encode("utf-8", "ignore")
        except Exception:
            pass

    sandbox = f"/tmp/dlp_sandbox_{uuid.uuid4().hex}"
    os.makedirs(sandbox, exist_ok=True)

    try:
        signatures = (
            (b"PK\x03\x04", ".zip"),
            (b"7z\xBC\xAF\x27\x1C", ".7z"),
            (b"Rar!\x1A\x07", ".rar"),
        )

        for magic, extension in signatures:
            index = payload.find(magic)
            if index == -1:
                continue

            archive = os.path.join(sandbox, "temp_archive" + extension)
            with open(archive, "wb") as stream:
                stream.write(payload[index:].split(b"\r\n--", 1)[0])

            subprocess.run(
                ["7z", "x", "-y", f"-o{sandbox}", archive],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=15,
            )

            for root, _, files in os.walk(sandbox):
                for name in files:
                    if name.startswith("temp_archive"):
                        continue
                    try:
                        with open(os.path.join(root, name), "rb") as stream:
                            extracted += stream.read() + b"\n"
                    except Exception:
                        pass

            break
    finally:
        shutil.rmtree(sandbox, ignore_errors=True)

    return extracted


class Handler(BaseICAPRequestHandler):
    def log_request(self, code="-", size="-"):
        pass

    def log_message(self, fmt, *args):
        pass

    def reqmod_OPTIONS(self):
        self.set_icap_response(200)
        self.set_icap_header(b"Methods", b"REQMOD")
        self.set_icap_header(b"Service", b"Wazuh ICAP Server")
        self.set_icap_header(b"Options-TTL", b"3600")
        self.set_icap_header(b"Preview", b"0")
        self.set_icap_header(b"Connection", b"close")
        self.send_headers(False)

    def reqmod_REQMOD(self):
        try:
            if not getattr(self, "enc_req", None):
                return self.no_adaptation_required()

            method = self.enc_req[0].decode("utf-8", "ignore")
            request_url = self.enc_req[1].decode("utf-8", "ignore")

            headers = (
                self.enc_req_headers
                if isinstance(getattr(self, "enc_req_headers", None), dict)
                else {}
            )
            host = headers.get(b"host", [b""])[0].decode("utf-8", "ignore")
            final_url = (
                request_url
                if request_url.startswith("http")
                else f"https://{host}{request_url}"
            )

            if method not in ("POST", "PUT", "PATCH"):
                if b"204" in self.allow:
                    return self.no_adaptation_required()
                return self.pass_request()

            payload = b""
            too_large = False

            if getattr(self, "has_body", False):
                while True:
                    chunk = self.read_chunk()
                    if chunk == b"":
                        break
                    if len(payload) + len(chunk) > MAX_PAYLOAD_SIZE:
                        too_large = True
                    elif not too_large:
                        payload += chunk

                if too_large:
                    write_log(
                        self.client_address[0],
                        final_url,
                        "ScanError",
                        "PayloadLimit",
                        len(payload),
                    )
                    return self.reject_request(
                        b"HTTP/1.1 413 Payload Too Large",
                        b"Upload exceeds the lab scan limit",
                    )

            scan = payload
            filename = get_filename(headers, scan, final_url, host)

            try:
                if payload.startswith(b"\x1f\x8b"):
                    scan = gzip.decompress(payload)
                elif payload.startswith((b"\x78\x9c", b"\x78\xda")):
                    scan = zlib.decompress(payload)
                else:
                    scan = brotli.decompress(payload)
            except Exception:
                pass

            scan += extract_deep_content(scan)
            scan += decode_advanced_encodings(scan)

            matches = compiled_rules.match(data=scan) if scan else []

            client_ip = self.headers.get(
                b"x-client-ip", [self.client_address[0].encode()]
            )[0].decode("utf-8", "replace")

            if matches:
                matched_rule = matches[0].rule

                if not check_is_spam(
                    client_ip, final_url, "Blocked", filename, matched_rule
                ):
                    write_log(
                        client_ip,
                        final_url,
                        "Blocked",
                        matched_rule,
                        len(payload),
                        filename,
                    )

                body = b'{"error":{"code":403,"message":"WAZUH DLP ALERT: Upload Blocked due to sensitive data policy."}}'

                self.set_icap_response(200)
                self.set_enc_status(b"HTTP/1.1 403 Forbidden")
                self.set_enc_header(b"Content-Type", b"application/json")
                self.set_enc_header(b"Content-Length", str(len(body)).encode())
                self.set_icap_header(b"Connection", b"close")
                self.send_headers(True)
                self.send_chunk(body)
                self.send_chunk(b"")
                return

            if not check_is_spam(client_ip, final_url, "Allowed", filename):
                write_log(
                    client_ip,
                    final_url,
                    "Allowed",
                    "None",
                    len(payload),
                    filename,
                )

            if b"204" in self.allow:
                self.no_adaptation_required()
            else:
                self.pass_request(payload)

        except Exception:
            logging.error("ICAP scan failed; request was not classified as clean")
            try:
                write_log(
                    self.client_address[0],
                    locals().get("final_url", "Unknown"),
                    "ScanError",
                    "ProcessingError",
                )
                self.reject_request(
                    b"HTTP/1.1 503 Service Unavailable",
                    b"DLP scan failed",
                )
            except Exception:
                pass

    def pass_request(self, payload=None):
        self.set_icap_response(200)
        self.set_enc_request(b" ".join(self.enc_req))

        for key, values in self.enc_req_headers.items():
            for value in values:
                self.set_enc_header(key, value)

        self.send_headers(self.has_body)

        if not self.has_body:
            return

        if payload is not None:
            if payload:
                self.send_chunk(payload)
            self.send_chunk(b"")
            return

        while True:
            chunk = self.read_chunk()
            self.send_chunk(chunk)
            if not chunk:
                break

    def reject_request(self, status, body):
        self.set_icap_response(200)
        self.set_enc_status(status)
        self.set_enc_header(b"Content-Type", b"text/plain")
        self.set_enc_header(b"Content-Length", str(len(body)).encode())
        self.set_icap_header(b"Connection", b"close")
        self.send_headers(True)
        self.send_chunk(body)
        self.send_chunk(b"")


class Server(socketserver.ThreadingMixIn, ICAPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass


if __name__ == "__main__":
    Server.allow_reuse_address = True
    logging.info("Network DLP ICAP Server is running on port 1344")
    Server(("127.0.0.1", 1344), Handler).serve_forever()
