#!/usr/bin/env python3
"""Render manifests from canonical module directories supplied by common.sh."""

from __future__ import annotations

import json
import shutil
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Backend:
    name: str
    major: int
    required: bool


@dataclass
class Module:
    directory: str
    name: str
    version: str
    major: int
    description: str
    author: str
    backends: list[Backend]
    required_count: int
    optional_count: int


def field(data, name, alias=None, default=None):
    if alias is not None and name in data and alias in data:
        raise ValueError(f"duplicate aliases for {name}: {name} and {alias}")
    value = data.get(name, data.get(alias, default) if alias else default)
    return default if value is None else value


def string(data, name, required=False):
    value = field(data, name, default="")
    if not isinstance(value, str) or (required and not value.strip()):
        raise ValueError(f"{name} must be a {'nonempty ' if required else ''}string")
    return value


def protocol_major(data):
    value = field(data, "protocolMajor", "protocol_major")
    # Protobuf JSON permits uint32 values as either numbers or decimal strings.
    if isinstance(value, str) and value.isascii() and value.isdecimal():
        value = int(value)
    if type(value) is not int or not 1 <= value <= 4294967295:
        raise ValueError("protocolMajor must be a positive uint32")
    return value


def array(data, name, alias):
    value = field(data, name, alias, [])
    if not isinstance(value, list):
        raise ValueError(f"{name} must be an array")
    return value


def capability_count(data, name, alias):
    requests = array(data, name, alias)
    for index, request in enumerate(requests):
        if not isinstance(request, dict):
            raise ValueError(f"{name}[{index}] must be a capability request object")
        try:
            string(request, "name", required=True)
        except ValueError as error:
            raise ValueError(f"{name}[{index}]: {error}") from error
    return len(requests)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError(f"invalid JSON constant: {value}")


def load_module(directory):
    manifest = json.loads(
        (Path(directory) / "manifest.json").read_text(encoding="utf-8"),
        object_pairs_hook=unique_object,
        parse_constant=reject_constant,
    )
    if not isinstance(manifest, dict):
        raise ValueError("manifest must be an object")
    name = string(manifest, "name")
    version = string(manifest, "version")
    major = protocol_major(manifest)
    description = string(manifest, "description")
    author = string(manifest, "author")
    required_count = capability_count(manifest, "requiredCapabilities", "required_capabilities")
    optional_count = capability_count(manifest, "optionalCapabilities", "optional_capabilities")
    backends = []
    for index, backend in enumerate(array(manifest, "backendRequirements", "backend_requirements")):
        try:
            if not isinstance(backend, dict):
                raise ValueError("must be a backend requirement object")
            backend_id = field(backend, "backendId", "backend_id")
            if not isinstance(backend_id, str) or not backend_id.strip():
                raise ValueError("backendId must be a nonempty string")
            backend_major = protocol_major(backend)
            required = field(backend, "required", default=False)
            if type(required) is not bool:
                raise ValueError("required must be a boolean")
            required_count += capability_count(backend, "requiredCapabilities", "required_capabilities")
            optional_count += capability_count(backend, "optionalCapabilities", "optional_capabilities")
            backends.append(Backend(backend_id, backend_major, required))
        except ValueError as error:
            raise ValueError(f"backendRequirements[{index}]: {error}") from error
    return Module(directory, name, version, major, description, author, backends,
                  required_count, optional_count)


def safe_text(value):
    """Keep metadata on one line and expose controls instead of executing them."""
    characters = []
    for character in value:
        category = unicodedata.category(character)
        if character.isspace():
            characters.append(" ")
        elif category.startswith("C"):
            codepoint = ord(character)
            characters.append(f"\\u{codepoint:04x}" if codepoint <= 0xffff else f"\\U{codepoint:08x}")
        else:
            characters.append(character)
    return " ".join("".join(characters).split())


def character_width(character):
    if unicodedata.combining(character) or unicodedata.category(character) in ("Mn", "Me"):
        return 0
    return 2 if unicodedata.east_asian_width(character) in ("W", "F") else 1


def display_width(text):
    return sum(character_width(character) for character in text)


def wrapped(text, width, indent=0):
    """Wrap words and long Korean/unspaced text by terminal display columns."""
    prefix = " " * min(indent, max(0, width - 2))
    available = width - len(prefix)
    lines = []
    line = ""
    used = 0
    for word in safe_text(text).split():
        word_width = display_width(word)
        if line and used + 1 + word_width <= available:
            line += " " + word
            used += 1 + word_width
            continue
        if line:
            lines.append(prefix + line)
            line, used = "", 0
        for character in word:
            columns = character_width(character)
            if line and used + columns > available:
                lines.append(prefix + line)
                line, used = "", 0
            line += character
            used += columns
    if line:
        lines.append(prefix + line)
    return lines or [prefix]


def render_modules(modules, width):
    if not modules:
        return "\n".join(wrapped("No modules found (direct modules/* directories with manifest.json).", width)) + "\n"
    lines = wrapped(f"Modules: {len(modules)}", width)
    lines += wrapped("Manifest metadata; capability requests are not permission grants.", width)
    for module in modules:
        lines.append("")
        name = module.name.strip() or "(unnamed)"
        version = module.version.strip() or "(not provided)"
        lines += wrapped(f"{name} | {version} | core protocol {module.major}", width)
        lines += wrapped(f"Folder: {module.directory}", width, indent=2)
        lines += wrapped(f"Purpose: {module.description.strip() or '(no description provided)'}", width, indent=2)
        lines += wrapped(f"Author: {module.author.strip() or '(not provided)'}", width, indent=2)
        backends = "; ".join(
            f"{backend.name} protocol {backend.major} ({'required' if backend.required else 'optional'})"
            for backend in module.backends
        )
        lines += wrapped(f"Backends: {backends or '(none declared)'}", width, indent=2)
        lines += wrapped(
            f"Requested capabilities (core + backends): {module.required_count} required, "
            f"{module.optional_count} optional", width, indent=2,
        )
    return "\n".join(lines) + "\n"


def main():
    modules = []
    # Load every manifest before emitting anything: an error must not look like a
    # successful, truncated inventory.
    for directory in sys.argv[1:]:
        try:
            modules.append(load_module(directory))
        except (OSError, UnicodeError, ValueError, RecursionError) as error:
            path = safe_text(str(Path(directory) / "manifest.json"))
            print(f"{path}: {safe_text(str(error))}", file=sys.stderr)
            return 1
    width = max(1, shutil.get_terminal_size(fallback=(80, 24)).columns)
    sys.stdout.write(render_modules(modules, width))
    return 0


if __name__ == "__main__":
    sys.exit(main())
