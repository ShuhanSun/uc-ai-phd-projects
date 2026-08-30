"""Strict validation at the model-to-tool trust boundary."""

from typing import Any

from .policy import ToolSchema


def validate_arguments(arguments: Any, schema: ToolSchema) -> tuple[str, ...]:
    """Return stable validation errors without coercing model-generated values."""

    if not isinstance(arguments, dict):
        return ("arguments must be an object",)

    errors: list[str] = []
    keys = set(arguments)
    for name in sorted(schema.required - keys):
        errors.append(f"missing required argument: {name}")
    if not schema.allow_extra:
        for name in sorted(keys - schema.properties.keys()):
            errors.append(f"unexpected argument: {name}")
    for name in sorted(keys & schema.properties.keys()):
        expected = schema.properties[name]
        value = arguments[name]
        # bool is a subclass of int, but accepting it as a number is almost
        # always surprising at a security boundary.
        if not isinstance(value, expected) or (expected is int and isinstance(value, bool)):
            errors.append(f"argument {name} must be {expected.__name__}")
    return tuple(errors)
