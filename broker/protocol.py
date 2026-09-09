"""The GUI <-> broker wire protocol, and the trust boundary it enforces.

Shared by both sides: `broker/broker.py` imports it as the authority on what a
request may contain, and `win_harden/backend/broker_client.py` imports the same
module to build one. There is deliberately no second copy -- a validator the
caller and callee disagree about is worse than no validator.

This module imports nothing but the standard library, and nothing Windows-only,
so the entire trust boundary is unit-testable on any platform.

The rule, carried over from the Fedora app's privileged helper:

    The ONLY thing the privileged side accepts from its caller is a verb and,
    for verbs that need one, a value matched against a fixed list of literals.
    It never takes a path, an address, a directive, or any other free text.

`VERB_FIELDS` and `FIELD_VALUES` below are that rule expressed as data, so
`validate_request` can be exhaustive by construction rather than by a reviewer
remembering to check a new field. Adding a verb means adding a row to
`VERB_FIELDS`; a field whose name is not in `FIELD_VALUES` is rejected outright,
so a new field cannot be introduced without also declaring its permitted values.

`interface` is the single exception and is commented where it is defined.
"""

import json

# Bumped whenever the request/response shape or the verb set changes. The GUI
# ships inside the same installer as the broker, but a half-finished upgrade or
# a stale broker still running from a previous session will drift -- and
# misreading a status payload is a far worse outcome than refusing to talk.
PROTOCOL_VERSION = 1

# -- the fixed vocabularies ---------------------------------------------------

LEVELS = ("off", "basic", "balanced", "strict")

# One per level-selector on the Protection and Hardening pages. Each maps to an
# action module under broker/actions/ that holds the authoritative definition of
# what its levels mean.
FAMILIES = ("defender", "exploit", "exposure", "credential", "dns", "tls")

# Resolver identities, not addresses. The GUI never sends an IP or a DoH
# template: the broker holds that table itself, so a compromised GUI process
# cannot point the system's DNS at a server of its choosing.
PROVIDERS = ("automatic", "quad9", "cloudflare", "mullvad", "adguard")

ASR_ACTIONS = ("off", "audit", "warn", "block")

# Individually switchable system components. Fixed keys, never a service name or
# a capability string from the caller -- the broker maps each key to the actual
# service/feature itself.
TOGGLES = (
    "openssh-server",
    "smb1",
    "rdp",
    "winrm",
    "remote-registry",
    "firewall-domain",
    "firewall-private",
    "firewall-public",
    "panic-mode",
)

VERBS = (
    "ping",
    "status",
    "apply",
    "revert",
    "set-asr",
    "set-toggle",
    "set-dns-provider",
    "shutdown",
)

# -- what each verb may carry -------------------------------------------------

# field name -> the complete set of values it may take. A field absent from this
# mapping cannot appear in any verb's field list (enforced by _check_tables at
# import, so the mistake is impossible to ship rather than merely unlikely).
FIELD_VALUES = {
    "family": FAMILIES,
    "level": LEVELS,
    "provider": PROVIDERS,
    "asr_action": ASR_ACTIONS,
    "toggle": TOGGLES,
    "enabled": (True, False),
}

# The one field that is not drawn from a fixed list, because it cannot be: a
# network interface index is assigned by Windows at runtime. It is constrained
# to a non-negative int here, and -- this is the part that matters -- the broker
# re-enumerates the machine's real interfaces and rejects an index that is not
# among them, so the validated range is the set of interfaces that actually
# exist rather than every integer.
INT_FIELDS = ("interface",)

# ASR rules are identified by GUID, which is data the GUI reads out of the
# broker's own status payload and hands back. It is checked for GUID shape here
# and against the authoritative rule table in the broker, for the same reason as
# `interface`: the permitted set is discovered at runtime, not fixed at build.
GUID_FIELDS = ("asr_rule",)

VERB_FIELDS = {
    "ping": (),
    "status": (),
    "apply": ("family", "level"),
    "revert": ("family",),
    "set-asr": ("asr_rule", "asr_action"),
    "set-toggle": ("toggle", "enabled"),
    "set-dns-provider": ("provider", "interface"),
    "shutdown": (),
}

# Verbs that change the system. Everything else is a read and runs unprivileged
# in the GUI process, so opening a page never triggers a UAC prompt.
PRIVILEGED_VERBS = ("apply", "revert", "set-asr", "set-toggle", "set-dns-provider")

# -- error kinds --------------------------------------------------------------
#
# Carried in the response so the GUI can react differently without parsing
# prose: a guard refusal is not a failure and must not be presented as one.

ERR_PROTOCOL = "protocol"      # version mismatch or malformed frame
ERR_VALIDATION = "validation"  # a field the trust boundary rejected
ERR_GUARD = "guard"            # a guard rail refused: doing this could lock you out
ERR_BLOCKED = "blocked"        # the OS refused (Tamper Protection, policy, licence)
ERR_FAILED = "failed"          # the change was attempted and did not work
ERR_TIMEOUT = "timeout"

ERROR_KINDS = (ERR_PROTOCOL, ERR_VALIDATION, ERR_GUARD, ERR_BLOCKED, ERR_FAILED, ERR_TIMEOUT)


class ProtocolError(Exception):
    """A frame that failed validation. Carries the kind so the responder can
    label it without re-deriving why it was rejected."""

    def __init__(self, message, kind=ERR_VALIDATION):
        super().__init__(message)
        self.kind = kind


def _check_tables():
    """Fail at import if the tables above contradict each other.

    Cheap, and it turns the class of mistake that would silently widen the trust
    boundary -- a verb listing a field nobody constrained -- into something that
    cannot start.
    """
    known = set(FIELD_VALUES) | set(INT_FIELDS) | set(GUID_FIELDS)
    for verb, fields in VERB_FIELDS.items():
        if verb not in VERBS:
            raise AssertionError(f"VERB_FIELDS has {verb!r}, which is not in VERBS")
        for field in fields:
            if field not in known:
                raise AssertionError(
                    f"verb {verb!r} declares field {field!r} with no permitted-value entry"
                )
    for verb in VERBS:
        if verb not in VERB_FIELDS:
            raise AssertionError(f"verb {verb!r} has no VERB_FIELDS entry")
    for verb in PRIVILEGED_VERBS:
        if verb not in VERBS:
            raise AssertionError(f"PRIVILEGED_VERBS has {verb!r}, which is not in VERBS")


_check_tables()


# -- GUID shape ---------------------------------------------------------------

def is_guid(value):
    """8-4-4-4-12 hex, with or without braces. Shape only -- the broker still
    checks the value against its own rule table before acting on it."""
    if not isinstance(value, str):
        return False
    text = value.strip()
    if text.startswith("{") and text.endswith("}"):
        text = text[1:-1]
    parts = text.split("-")
    if len(parts) != 5 or [len(p) for p in parts] != [8, 4, 4, 4, 12]:
        return False
    return all(c in "0123456789abcdefABCDEF" for p in parts for c in p)


# -- validation ---------------------------------------------------------------

def validate_request(payload):
    """Check one decoded request against the tables above.

    Returns a NEW dict containing only the fields the verb declares -- never the
    caller's dict. An unexpected key is dropped rather than carried along, so a
    field nothing validated can't reach an action module by riding on a request
    that was otherwise fine.

    Raises ProtocolError.
    """
    if not isinstance(payload, dict):
        raise ProtocolError("request must be a JSON object", ERR_PROTOCOL)

    version = payload.get("protocol")
    if version != PROTOCOL_VERSION:
        raise ProtocolError(
            f"this broker speaks protocol {PROTOCOL_VERSION}, but the request declared "
            f"{version!r}. The app and the broker are different versions -- reinstall, "
            f"or sign out and back in to restart the broker.",
            ERR_PROTOCOL,
        )

    verb = payload.get("verb")
    if verb not in VERBS:
        raise ProtocolError(f"unknown verb {verb!r}")

    request_id = payload.get("id")
    if not isinstance(request_id, str) or not request_id:
        raise ProtocolError("request id must be a non-empty string", ERR_PROTOCOL)

    clean = {"protocol": PROTOCOL_VERSION, "id": request_id, "verb": verb}

    for field in VERB_FIELDS[verb]:
        if field not in payload:
            raise ProtocolError(f"verb {verb!r} requires field {field!r}")
        value = payload[field]

        if field in FIELD_VALUES:
            # The whole trust boundary in one comparison: the caller picks from a
            # fixed tuple of literals and nothing else reaches an action module.
            permitted = FIELD_VALUES[field]
            # `True == 1` in Python, so an int would sail through a naive `in`
            # check against a bool field. Compare types as well as values.
            if not any(value == p and type(value) is type(p) for p in permitted):
                raise ProtocolError(f"{field}={value!r} is not one of {permitted!r}")
        elif field in INT_FIELDS:
            if type(value) is not int or value < 0:
                raise ProtocolError(f"{field} must be a non-negative integer, got {value!r}")
        elif field in GUID_FIELDS:
            if not is_guid(value):
                raise ProtocolError(f"{field} must be a GUID, got {value!r}")
        else:  # pragma: no cover - _check_tables makes this unreachable
            raise ProtocolError(f"field {field!r} has no validation rule")

        clean[field] = value

    return clean


def is_privileged(verb):
    return verb in PRIVILEGED_VERBS


# -- framing ------------------------------------------------------------------
#
# Newline-delimited JSON. A frame is one line, so a partial read is detectable
# and a malformed frame can't consume the next one.

MAX_FRAME_BYTES = 1 << 20  # a request or response larger than this is a bug or an attack


def encode_request(request_id, verb, **fields):
    payload = {"protocol": PROTOCOL_VERSION, "id": request_id, "verb": verb}
    payload.update(fields)
    # Validate on the way out as well as on the way in. The GUI finding its own
    # bug is much easier to diagnose than the broker rejecting a frame later.
    validate_request(payload)
    return (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")


def encode_response(request_id, ok, result=None, error_kind=None, error_message=None):
    payload = {"protocol": PROTOCOL_VERSION, "id": request_id, "ok": bool(ok)}
    if ok:
        payload["result"] = result if result is not None else {}
    else:
        if error_kind not in ERROR_KINDS:
            error_kind = ERR_FAILED
        payload["error"] = {"kind": error_kind, "message": error_message or "the change failed"}
    return (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")


def decode_frame(line):
    """Decode one newline-delimited frame. Raises ProtocolError."""
    if isinstance(line, (bytes, bytearray)):
        if len(line) > MAX_FRAME_BYTES:
            raise ProtocolError("frame too large", ERR_PROTOCOL)
        try:
            line = line.decode("utf-8")
        except UnicodeDecodeError as e:
            raise ProtocolError(f"frame is not valid UTF-8: {e}", ERR_PROTOCOL) from e
    try:
        return json.loads(line)
    except ValueError as e:
        raise ProtocolError(f"frame is not valid JSON: {e}", ERR_PROTOCOL) from e


def decode_response(line):
    """Decode a response frame into (ok, result, error_kind, error_message)."""
    payload = decode_frame(line)
    if not isinstance(payload, dict):
        raise ProtocolError("response must be a JSON object", ERR_PROTOCOL)
    if payload.get("protocol") != PROTOCOL_VERSION:
        raise ProtocolError(
            f"the broker replied with protocol {payload.get('protocol')!r}, but this app "
            f"speaks {PROTOCOL_VERSION}",
            ERR_PROTOCOL,
        )
    request_id = payload.get("id")
    if not isinstance(request_id, str) or not request_id:
        raise ProtocolError("response is missing its request id", ERR_PROTOCOL)
    if payload.get("ok"):
        result = payload.get("result")
        return request_id, True, (result if isinstance(result, dict) else {}), None, None
    error = payload.get("error")
    if not isinstance(error, dict):
        error = {}
    kind = error.get("kind")
    if kind not in ERROR_KINDS:
        kind = ERR_FAILED
    return request_id, False, None, kind, str(error.get("message") or "the change failed")
