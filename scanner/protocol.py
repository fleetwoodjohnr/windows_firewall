"""Bounded, versioned scan-only IPC; authorization is enforced by the service."""
import json
import ntpath
import uuid
import re

VERSION = 1
SERVICE_NAME = "WinHardenScanner"
PIPE_NAME = r"\\.\pipe\WinHardenScanner-v1"
MAX_FRAME = 256 * 1024
OPERATIONS = {"health": (), "history": (), "submit": ("kind", "request_id"),
              "job": ("job_id",), "cancel": ("job_id",)}
KINDS = ("quick", "full", "custom", "update", "remediate", "protect")


def local_path(value):
    if not isinstance(value, str) or not value or len(value) > 240:
        raise ValueError("Choose a local file or folder with a path of at most 240 characters.")
    drive, tail = ntpath.splitdrive(value)
    if (len(drive) != 2 or drive[1] != ":" or not drive[0].isascii()
            or not drive[0].isalpha() or not tail.startswith(("\\", "/"))
            or any(ord(c) < 32 for c in value) or any(c in value for c in '*?"|<>')
            or ":" in tail):
        raise ValueError("Only absolute local paths are supported; device, network and stream paths are refused.")
    parts = tail.replace("/", "\\").split("\\")
    if any(p in (".", "..") or (p and p.rstrip(" .") != p) for p in parts):
        raise ValueError("Ambiguous path components are not supported.")
    reserved = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(10)),
                *(f"LPT{i}" for i in range(10))}
    if any(p.split(".")[0].upper() in reserved for p in parts):
        raise ValueError("Device names cannot be scanned.")
    return ntpath.normpath(value)


def validate(request):
    if not isinstance(request, dict) or request.get("version") != VERSION:
        raise ValueError("Scan service version mismatch. Repair the installation.")
    op = request.get("op")
    if op not in OPERATIONS:
        raise ValueError("Unknown scan operation.")
    required = {"version", "op", *OPERATIONS[op]}
    optional = {"path", "owner_sid"} if op == "submit" else set()
    if not required <= request.keys() or request.keys() - required - optional:
        raise ValueError("Invalid scan request fields.")
    clean = dict(request)
    if 'owner_sid' in clean and (not isinstance(clean['owner_sid'], str) or not re.fullmatch(r'S-1-\d+(?:-\d+){1,15}', clean['owner_sid'])):
        raise ValueError('Invalid scan owner SID')
    for key in ("job_id", "request_id"):
        if key in clean:
            clean[key] = str(uuid.UUID(clean[key]))
    if op == "submit":
        if clean["kind"] not in KINDS:
            raise ValueError("Unknown scan type.")
        if clean["kind"] == "custom":
            clean["path"] = local_path(clean.get("path"))
        elif "path" in clean:
            raise ValueError("Only custom scans accept a path.")
    return clean


def encode(value):
    frame = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode() + b"\n"
    if len(frame) > MAX_FRAME:
        raise ValueError("Scan response exceeds its size limit.")
    return frame


def decode(frame):
    if len(frame) > MAX_FRAME:
        raise ValueError("Scan request exceeds its size limit.")
    return json.loads(frame.decode("utf-8"))
