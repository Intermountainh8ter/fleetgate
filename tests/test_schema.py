import pytest

from fleetgate.schema import SchemaError, check, validate


def test_types_and_bool_is_not_a_number():
    assert validate(1, {"type": "integer"}) == []
    assert validate(True, {"type": "integer"})
    assert validate(True, {"type": "number"})
    assert validate(1.5, {"type": "integer"})
    assert validate("a", {"type": ["string", "null"]}) == [] and validate(None, {"type": ["string", "null"]}) == []
    assert validate({}, {"type": "array"})


def test_enum_const_bounds_and_strings():
    assert validate("x", {"enum": ["a", "b"]})
    assert validate(2, {"const": 3})
    assert validate(5, {"minimum": 6}) and validate(5, {"maximum": 4}) and validate(5, {"exclusiveMinimum": 5})
    assert validate("ab", {"minLength": 3}) and validate("abcd", {"maxLength": 3})


def test_array_rules():
    s = {"type": "array", "minItems": 2, "maxItems": 3, "uniqueItems": True, "items": {"type": "integer"}}
    assert validate([1, 2], s) == []
    assert validate([1], s) and validate([1, 2, 3, 4], s) and validate([1, 1], s) and validate([1, "x"], s)


def test_object_rules_and_additional_properties():
    s = {"type": "object", "required": ["a"], "properties": {"a": {"type": "integer"}},
         "additionalProperties": False, "minProperties": 1, "maxProperties": 2}
    assert validate({"a": 1}, s) == []
    assert any("missing required" in e for e in validate({}, s))
    assert any("unexpected" in e for e in validate({"a": 1, "b": 2}, s))
    assert validate({"a": 1, "b": 2, "c": 3}, s)
    typed = {"type": "object", "additionalProperties": {"type": "integer"}}
    assert validate({"x": 1}, typed) == [] and validate({"x": "no"}, typed)
    assert validate({"bad key": 1}, {"type": "object", "propertyNames": {"pattern": "^[a-z]+$"}})


def test_pattern_dollar_does_not_match_before_trailing_newline():
    s = {"type": "string", "pattern": r"^[a-z_]+$"}
    assert validate("drain_host", s) == []
    for bad in ["drain_host\n", "drain_host ", " drain_host", "drain-host", "drаin_host"]:  # last: Cyrillic a
        assert validate(bad, s), repr(bad)
    # an escaped dollar stays a literal dollar
    assert validate("a$", {"pattern": r"a\$"}) == []


def test_error_paths_are_reported():
    errs = validate({"a": [{"b": "x"}]}, {"properties": {"a": {"items": {"properties": {"b": {"type": "integer"}}}}}})
    assert errs == ["$.a[0].b: expected integer, got str"]


def test_check_raises_with_first_ten_problems():
    with pytest.raises(SchemaError) as ei:
        check(list(range(30)), {"type": "array", "items": {"type": "string"}}, "numbers")
    msg = str(ei.value)
    assert msg.startswith("numbers: ") and "(+20 more)" in msg
    check("fine", {"type": "string"})
