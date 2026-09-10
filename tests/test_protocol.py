"""The trust boundary. If these tests pass, the privileged side cannot be handed
anything but a verb and values from fixed lists."""

import pytest

from broker import protocol as p


def req(**kw):
    return {"protocol": p.PROTOCOL_VERSION, "id": "r1", **kw}


class TestTables:
    def test_every_verb_declares_its_fields(self):
        assert set(p.VERB_FIELDS) == set(p.VERBS)

    def test_every_declared_field_has_permitted_values(self):
        known = (set(p.FIELD_VALUES) | set(p.INT_FIELDS) | set(p.GUID_FIELDS)
                 | set(p.TEXT_FIELDS))
        for verb, fields in p.VERB_FIELDS.items():
            for field in fields:
                assert field in known, f"{verb}.{field} is unconstrained"

    def test_free_text_fields_are_the_exception_and_stay_small(self):
        """Every free-text field widens the trust boundary, so the set is kept
        deliberately tiny and each one has to justify itself in a comment."""
        assert set(p.TEXT_FIELDS) == {"group"}, (
            "a new free-text field was added to the privileged protocol")

    def test_privileged_verbs_are_real_verbs(self):
        assert set(p.PRIVILEGED_VERBS) <= set(p.VERBS)

    def test_reads_are_not_privileged(self):
        # status and ping must stay unprivileged: opening a page must never
        # trigger a UAC prompt.
        assert not p.is_privileged("status")
        assert not p.is_privileged("ping")


class TestValidation:
    def test_accepts_a_well_formed_request(self):
        out = p.validate_request(req(verb="apply", family="dns", level="strict"))
        assert out == {"protocol": 2, "id": "r1", "verb": "apply", "family": "dns", "level": "strict"}

    @pytest.mark.parametrize("level", ["", "STRICT", "strict ", "off; shutdown", "../off", None, 1])
    def test_rejects_a_level_outside_the_fixed_list(self, level):
        with pytest.raises(p.ProtocolError):
            p.validate_request(req(verb="apply", family="dns", level=level))

    @pytest.mark.parametrize("family", ["", "dns2", "../dns", "DNS", None])
    def test_rejects_a_family_outside_the_fixed_list(self, family):
        with pytest.raises(p.ProtocolError):
            p.validate_request(req(verb="apply", family=family, level="off"))

    def test_rejects_an_unknown_verb(self):
        with pytest.raises(p.ProtocolError, match="unknown verb"):
            p.validate_request(req(verb="rm-rf"))

    def test_rejects_a_version_mismatch(self):
        with pytest.raises(p.ProtocolError) as e:
            p.validate_request({"protocol": 99, "id": "r1", "verb": "ping"})
        assert e.value.kind == p.ERR_PROTOCOL

    def test_rejects_a_missing_required_field(self):
        with pytest.raises(p.ProtocolError, match="requires field"):
            p.validate_request(req(verb="apply", family="dns"))

    def test_drops_fields_the_verb_did_not_declare(self):
        # An unexpected key must not ride along into an action module.
        out = p.validate_request(req(verb="revert", family="dns", path="C:\\Windows", level="strict"))
        assert out == {"protocol": 2, "id": "r1", "verb": "revert", "family": "dns"}
        assert "path" not in out and "level" not in out

    def test_bool_field_rejects_an_int(self):
        # True == 1 in Python, so a naive `in` check would let an int through.
        with pytest.raises(p.ProtocolError):
            p.validate_request(req(verb="set-toggle", toggle="rdp", enabled=1))
        assert p.validate_request(req(verb="set-toggle", toggle="rdp", enabled=False))["enabled"] is False

    def test_interface_must_be_a_non_negative_int(self):
        assert p.validate_request(
            req(verb="set-dns-provider", provider="quad9", interface=7))["interface"] == 7
        for bad in [-1, "7", 1.5, True, None]:
            with pytest.raises(p.ProtocolError):
                p.validate_request(req(verb="set-dns-provider", provider="quad9", interface=bad))

    def test_requires_a_usable_request_id(self):
        for bad in ["", None, 5]:
            with pytest.raises(p.ProtocolError):
                p.validate_request({"protocol": 2, "id": bad, "verb": "ping"})

    def test_rejects_a_non_object(self):
        for bad in [[], "ping", None, 5]:
            with pytest.raises(p.ProtocolError):
                p.validate_request(bad)


class TestRuleGroupNames:
    """The one field carrying text this app did not author."""

    @pytest.mark.parametrize("group", [
        "File and Printer Sharing", "Remote Desktop", "Network Discovery (NB-Name-In)",
        "Cast to Device functionality", "mDNS", "Delivery Optimization",
    ])
    def test_accepts_real_windows_group_names(self, group):
        out = p.validate_request(req(verb="set-rule-group", profile="Public",
                                     group=group, enabled=False))
        assert out["group"] == group

    @pytest.mark.parametrize("group", [
        "x`; Stop-Computer", "$(Invoke-Expression 'bad')", 'x" ; y', "a|b", "a;b",
        "a" * 129, "", None, 5, "x\ny",
    ])
    def test_rejects_anything_shaped_like_powershell(self, group):
        with pytest.raises(p.ProtocolError):
            p.validate_request(req(verb="set-rule-group", profile="Public",
                                   group=group, enabled=False))


class TestGuid:
    @pytest.mark.parametrize("value", [
        "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550",
        "{be9ba2d9-53ea-4cdc-84e5-9b1eeee46550}",
    ])
    def test_accepts_a_guid(self, value):
        assert p.is_guid(value)

    @pytest.mark.parametrize("value", [
        "", "not-a-guid", "BE9BA2D9-53EA-4CDC-84E5", None, 5,
        "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE4655G",   # non-hex
        "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550; rm",
    ])
    def test_rejects_a_non_guid(self, value):
        assert not p.is_guid(value)


class TestFraming:
    def test_request_round_trip(self):
        frame = p.encode_request("abc", "apply", family="tls", level="balanced")
        assert frame.endswith(b"\n")
        assert p.validate_request(p.decode_frame(frame.strip()))["level"] == "balanced"

    def test_encode_request_validates_on_the_way_out(self):
        with pytest.raises(p.ProtocolError):
            p.encode_request("abc", "apply", family="tls", level="nope")

    def test_success_response_round_trip(self):
        rid, ok, result, kind, message = p.decode_response(
            p.encode_response("abc", True, result={"level": "strict"}))
        assert (rid, ok, result, kind, message) == ("abc", True, {"level": "strict"}, None, None)

    def test_error_response_round_trip(self):
        rid, ok, result, kind, message = p.decode_response(
            p.encode_response("abc", False, error_kind=p.ERR_GUARD, error_message="no"))
        assert (rid, ok, result, kind) == ("abc", False, None, p.ERR_GUARD)
        assert message == "no"

    def test_unknown_error_kind_falls_back_to_failed(self):
        _rid, _ok, _res, kind, _msg = p.decode_response(
            p.encode_response("abc", False, error_kind="invented", error_message="x"))
        assert kind == p.ERR_FAILED

    def test_rejects_a_response_from_another_protocol(self):
        with pytest.raises(p.ProtocolError):
            p.decode_response(b'{"protocol":99,"id":"a","ok":true,"result":{}}')

    def test_rejects_malformed_json(self):
        with pytest.raises(p.ProtocolError):
            p.decode_frame(b"{not json")

    def test_rejects_an_oversized_frame(self):
        with pytest.raises(p.ProtocolError):
            p.decode_frame(b"x" * (p.MAX_FRAME_BYTES + 1))


@pytest.mark.parametrize('name', ['Partage de fichiers et imprimantes', 'Datei- und Druckerfreigabe', '文件和打印机共享'])
def test_localized_rule_groups_are_valid(name):
    out = p.validate_request(req(verb='set-rule-group', profile='Public', group=name, enabled=False))
    assert out['group'] == name
