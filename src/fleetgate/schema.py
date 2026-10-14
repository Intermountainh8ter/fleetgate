"""Tiny JSON-schema-subset validator.

fleetgate deliberately has no runtime dependencies, so instead of pulling in `jsonschema` this module
implements the subset we need to validate runbook specs, policy files, scenario files and LLM plan
output: type, enum, const, required, properties, additionalProperties, items, min/max for numbers,
strings and arrays, pattern and uniqueItems. Errors are returned as a list of "path: message"
strings so callers can report every problem at once.
"""
from __future__ import annotations

import re
from typing import Any

_SIMPLE = {"object": dict, "array": list, "string": str, "boolean": bool, "null": type(None)}


class SchemaError(ValueError):
    """Raised by `check()` when an instance does not match its schema."""


def _type_ok(value: Any, t: str) -> bool:
    if t == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if t == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    cls = _SIMPLE.get(t)
    return cls is not None and isinstance(value, cls)


def validate(instance: Any, schema: dict[str, Any], path: str = "$") -> list[str]:
    """Return a list of validation errors (empty when the instance is valid)."""
    errors: list[str] = []
    t = schema.get("type")
    if t is not None:
        types = t if isinstance(t, list) else [t]
        if not any(_type_ok(instance, x) for x in types):
            return [f"{path}: expected {'/'.join(types)}, got {type(instance).__name__}"]
    if "const" in schema and instance != schema["const"]:
        errors.append(f"{path}: expected constant {schema['const']!r}")
    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: {instance!r} not one of {schema['enum']!r}")

    if isinstance(instance, str):
        if "minLength" in schema and len(instance) < schema["minLength"]:
            errors.append(f"{path}: shorter than {schema['minLength']} chars")
        if "maxLength" in schema and len(instance) > schema["maxLength"]:
            errors.append(f"{path}: longer than {schema['maxLength']} chars")
        if "pattern" in schema and not re.search(schema["pattern"], instance):
            errors.append(f"{path}: {instance!r} does not match {schema['pattern']!r}")

    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            errors.append(f"{path}: {instance} < minimum {schema['minimum']}")
        if "maximum" in schema and instance > schema["maximum"]:
            errors.append(f"{path}: {instance} > maximum {schema['maximum']}")
        if "exclusiveMinimum" in schema and instance <= schema["exclusiveMinimum"]:
            errors.append(f"{path}: {instance} <= exclusive minimum {schema['exclusiveMinimum']}")

    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < schema["minItems"]:
            errors.append(f"{path}: fewer than {schema['minItems']} items")
        if "maxItems" in schema and len(instance) > schema["maxItems"]:
            errors.append(f"{path}: more than {schema['maxItems']} items")
        if schema.get("uniqueItems"):
            seen: list[Any] = []
            for i, item in enumerate(instance):
                if item in seen:
                    errors.append(f"{path}[{i}]: duplicate item {item!r}")
                seen.append(item)
        if "items" in schema:
            for i, item in enumerate(instance):
                errors.extend(validate(item, schema["items"], f"{path}[{i}]"))

    if isinstance(instance, dict):
        props = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in instance:
                errors.append(f"{path}: missing required property {key!r}")
        if "minProperties" in schema and len(instance) < schema["minProperties"]:
            errors.append(f"{path}: fewer than {schema['minProperties']} properties")
        if "maxProperties" in schema and len(instance) > schema["maxProperties"]:
            errors.append(f"{path}: more than {schema['maxProperties']} properties")
        for key, value in instance.items():
            if key in props:
                errors.extend(validate(value, props[key], f"{path}.{key}"))
            else:
                extra = schema.get("additionalProperties", True)
                if extra is False:
                    errors.append(f"{path}: unexpected property {key!r}")
                elif isinstance(extra, dict):
                    errors.extend(validate(value, extra, f"{path}.{key}"))
        if "propertyNames" in schema:
            for key in instance:
                errors.extend(validate(key, schema["propertyNames"], f"{path}.<{key}>"))
    return errors


def check(instance: Any, schema: dict[str, Any], what: str = "document") -> None:
    """Validate and raise `SchemaError` with the first ten problems."""
    errors = validate(instance, schema)
    if errors:
        more = f" (+{len(errors) - 10} more)" if len(errors) > 10 else ""
        raise SchemaError(f"{what}: " + "; ".join(errors[:10]) + more)
