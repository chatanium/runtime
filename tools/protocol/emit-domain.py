#!/usr/bin/env python3
"""Emit P1 typed Discord domain contracts and P2 field mappings from frozen audits.

Run from the repository root: python3 tools/protocol/emit-domain.py
No compiler, network, runtime reflection, or JSON conversion is involved. The JSON
input is a SOURCE inventory; domain-mapping.json is the explicit converter plan.
"""
import argparse
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INVENTORY = ROOT / "tools/protocol/inventory"
CORE = "flexmodule.core.v2."


def load(name):
    return json.loads((INVENTORY / name).read_text())


def identifier(value, context):
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value):
        raise ValueError(f"Invalid protobuf identifier {value!r} for {context}; correct the source inventory, do not sanitize malformed source names.")
    return value


def snake(name):
    name = re.sub(r"IDs$", "Ids", name)
    name = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
    return identifier(re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name).lower(), "source field " + name)


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--mapping-only", action="store_true", help="Refresh source mapping JSON without emitting shared protobuf contracts")
args = parser.parse_args()

ast = load("source-ast.json")
closure = load("source-type-closure.json")
legacy = load("legacy-conversion-coverage.json")
events = load("source-events.json")
TYPES = {t["Name"]: t for t in ast["Types"] if t["File"].startswith("discordgo/") and t.get("Scope", "package") == "package"}
SOURCE_RENAMES = {"MessageComponentInteractionDataResolved": "ComponentInteractionDataResolved"}
RUNTIME = {"Session", "State", "Identify"}
MASKS = {"Intent", "SystemChannelFlag"} | {n for n in TYPES if n.endswith("Flags")}
PERMISSIONS = {"Permissions", "AppPermissions", "DefaultMemberPermissions", "Allow", "Deny"}
COMPONENTS = ["ActionsRow", "Button", "SelectMenu", "TextInput", "Section", "TextDisplay", "Thumbnail", "MediaGallery", "FileComponent", "Separator", "Container", "Label", "FileUpload"]
DATA = ["ApplicationCommandInteractionData", "MessageComponentInteractionData", "ModalSubmitInteractionData"]
if set(COMPONENTS) != set(closure["polymorphicExpansion"]["MessageComponent"]) or set(DATA) != set(closure["polymorphicExpansion"]["InteractionData"]):
    raise ValueError("Unclassified source polymorphic variant; review explicit oneof tags before emission.")
SPECIAL = {
    ("User", "Token"): (None, "runtime-only", "Bot/user credential is forbidden; trusted projection sanitizes; pure converter rejects raw token."),
    ("VoiceState", "SessionID"): (None, "runtime-only", "Private gateway connection/session state; no module replacement."),
    ("Ready", "SessionID"): (None, "runtime-only", "Private gateway session/resume state; no module replacement."),
    ("Ready", "ResumeGatewayURL"): (None, "runtime-only", "Private gateway connection/resume address; no module replacement."),
    ("Ready", "Shard"): (None, "runtime-only", "Host-owned gateway sharding/execution configuration; not module domain state."),
    ("Interaction", "Token"): (CORE + "CredentialRef", "safe-wrapper", "credential_ref: interaction-purpose scoped runtime reference; SDK Token remains empty."),
    ("Webhook", "Token"): (CORE + "CredentialRef", "safe-wrapper", "credential_ref: webhook-purpose scoped runtime reference; SDK Token remains empty."),
    ("GuildMemberAddParams", "AccessToken"): (CORE + "CredentialRef", "safe-wrapper", "credential_ref: operator-provisioned user credential reference, never raw OAuth token."),
    ("ApplicationCommandOptionChoice", "Value"): ("ApplicationCommandChoiceValue", "safe-wrapper", "String/integer/number only; parent option discriminator must agree."),
    ("ApplicationCommandInteractionDataOption", "Value"): ("ApplicationCommandOptionValue", "safe-wrapper", "Nine typed scalar variants; subcommand/group omit scalar and retain nested options."),
    ("MessageSend", "File"): (None, "inline", "Canonicalize into files; conflicting singular/plural values are errors."),
    ("MessageSend", "Embed"): (None, "inline", "Canonicalize into embeds; conflicting singular/plural values are errors."),
    ("MessageEdit", "Embed"): (None, "inline", "Canonicalize into embeds; preserve present empty; conflicts are errors."),
    ("MessageEdit", "Content"): (CORE + "NullableString", "safe-wrapper", "Absent/value/null; endpoint rejects unsupported null; empty string clears."),
    ("WebhookEdit", "Content"): (CORE + "NullableString", "safe-wrapper", "Absent/value/null; endpoint validates null support."),
    ("InteractionResponseData", "Content"): (CORE + "NullableString", "safe-wrapper", "Authoritative presence-aware view for message-update responses."),
}
# Reviewed outbound value-string families. Derive omissions from their SDK JSON
# tags, not individual demo fields. Snapshot and patch/nullable types stay out.
SOURCE_JSON_OMIT_EMPTY_TYPES = {"MessageSend", "WebhookParams", "ComponentEmoji", "SelectMenuOption"} | set(COMPONENTS)
# Only these audited value numerics use zero as SDK JSON omission for provider
# defaults. Do not infer that policy for snapshots, pointers or other numerics.
SOURCE_JSON_OMIT_ZERO = {
    ("Poll", "Duration"), ("Poll", "LayoutType"),
    ("SelectMenu", "MaxValues"), ("FileUpload", "MaxValues"),
    ("TextInput", "MaxLength"),
}
for owner in ["MessageEdit", "WebhookEdit", "InteractionResponseData"]:
    SPECIAL[owner, "Attachments"] = ("AttachmentEditList", "safe-wrapper", "Complete post-edit set; existing ID or zero-based new-file index; each new file exactly once; no hidden fetch/append.")
for field in ["OldValue", "NewValue"]:
    SPECIAL["AuditLogChange", field] = (CORE + "JSONValue", "safe-wrapper", "Exact single UTF-8 JSON value; absent differs from explicit JSON null; preserve numeric tokens and reject credential-bearing values.")
NULLABLE = {
    ("GuildMemberParams", "ChannelID"), ("GuildMemberParams", "CommunicationDisabledUntil"),
    ("ApplicationCommand", "DefaultMemberPermissions"),
    ("ChannelEdit", "Topic"), ("ChannelEdit", "ParentID"),
    ("ChannelEdit", "DefaultReactionEmoji"), ("ChannelEdit", "DefaultSortOrder"),
    ("RoleParams", "Icon"), ("RoleParams", "UnicodeEmoji"),
    ("GuildScheduledEventParams", "ChannelID"), ("GuildScheduledEventParams", "ScheduledEndTime"),
    ("GuildScheduledEventParams", "EntityMetadata"),
    ("GuildParams", "AfkChannelID"), ("GuildParams", "Icon"), ("GuildParams", "Splash"),
    ("GuildParams", "DiscoverySplash"), ("GuildParams", "Banner"),
    ("GuildParams", "SystemChannelID"), ("GuildParams", "RulesChannelID"),
    ("GuildParams", "PublicUpdatesChannelID"), ("GuildParams", "Description"),
}
LEGACY_FIELD_RENAMES = {
    ("Application", "PrivacyPolicyUrl"): "PrivacyProxyURL",
    ("User", "PublicFlagsValue"): "PublicFlags",
    ("Team", "OwnerUserId"): "OwnerID",
    ("SelectMenuOption", "IsDefault"): "Default",
}
BASIC = {"string": "string", "bool": "bool", "int": "sint64", "int32": "sint32", "int64": "sint64", "uint": "uint64", "uint8": "uint32", "uint16": "uint32", "uint32": "uint32", "uint64": "uint64", "float64": "double", "time.Duration": "sint64", "time.Time": "google.protobuf.Timestamp", "[]byte": "bytes"}
SCALARS = {"string", "bool", "sint32", "sint64", "uint32", "uint64", "double", "bytes"}
WRAPPERS = {}
MAPPED = {}
SELECTED = set()


def key(wire):
    return "".join(p[:1].upper() + p[1:] for p in re.split(r"[^A-Za-z0-9]+", wire) if p)


def nullable(wire):
    # Core definitions are normative, not duplicate Discord aliases.
    if wire == "string":
        return CORE + "NullableString"
    if wire == "google.protobuf.Timestamp":
        return CORE + "NullableTimestamp"
    name = "DomainNullable" + key(wire.removeprefix(CORE))
    WRAPPERS.setdefault(name, ("nullable", wire))
    return name


def sequence(wire):
    name = {"MessageEmbed": "EmbedList", "MessageComponent": "ComponentList", "FileAttachment": "FileAttachmentList", "AttachmentEditEntry": "AttachmentEditList"}.get(wire, "Domain" + key(wire) + "List")
    WRAPPERS.setdefault(name, ("list", wire))
    return name


def scalar_kind(name):
    if name in BASIC:
        return BASIC[name]
    if name not in TYPES:
        raise ValueError("Unknown source type: " + name)
    if name in MASKS:
        return "uint64"
    kind = TYPES[name]["Kind"]
    if kind in BASIC:
        return BASIC[kind]
    if kind in TYPES and kind != name:
        return scalar_kind(kind)
    return None


def resolve(source, partial=False):
    source = source.lstrip("*")
    if source == "[]byte":
        return "bytes"
    if source.startswith("[]"):
        element = resolve(source[2:], partial)
        return sequence(nullable(element) if partial else element)
    if source.startswith("map["):
        match = re.fullmatch(r"map\[([^]]+)\](.+)", source)
        if not match:
            raise ValueError("Unsupported map " + source)
        k, v = match.groups()
        kwire = resolve(k)
        if kwire not in {"string", "bool", "sint64", "sint32", "uint32", "uint64"}:
            raise ValueError("Unsupported map key " + k)
        vwire = resolve(v, partial)
        if partial:
            vwire = nullable(vwire)
        name = "Domain" + key(kwire) + "To" + key(vwire) + "Map"
        WRAPPERS.setdefault(name, ("map", kwire, vwire))
        return name
    scalar = scalar_kind(source)
    if scalar:
        SELECTED.add(source) if source in TYPES else None
        return scalar
    if source in RUNTIME:
        raise ValueError("Runtime object reached a domain field: " + source)
    if source == "File":
        SELECTED.add(source)
        return "FileAttachment"
    if source in {"MessageComponent", "InteractionData"}:
        SELECTED.add(source)
        return ("Partial" if partial else "") + source
    if source not in TYPES or TYPES[source]["Kind"] != "struct":
        raise ValueError("Unclassified non-domain type: " + source)
    SELECTED.add(source)
    return ("Partial" if partial else "") + source


def numeric_contract(source, owner, field):
    bare = source.lstrip("*")
    if field in PERMISSIONS and bare in {"int64", "int", "string"}:
        return "Nonnegative decimal permission bitmask; SDK int64 range 0..9223372036854775807; preserve absent/null/zero."
    if bare in MASKS or field.endswith("Flags") or field == "Flags":
        return "Unsigned 64-bit bitmask, not ordinal; source signed int adapter accepts 0..9223372036854775807; reject narrowing overflow."
    if bare == "time.Duration":
        return "Signed 64-bit nanoseconds (Go time.Duration); endpoint validates nonnegative durations."
    if bare == "time.Time":
        return "UTC protobuf Timestamp, validate seconds/nanos; zero time never replaced with now."
    if owner == "TimeStamps":
        return "Signed 64-bit Unix milliseconds, retain source unit."
    if owner == "SessionInformation" and field == "ResetAfter":
        return "Signed 64-bit milliseconds until reset, not nanoseconds."
    if bare in TYPES and scalar_kind(bare):
        if scalar_kind(bare) == "string":
            return "Source string alias " + bare + "; retain original string (including valid empty/default); never cast a numeric ordinal to a rune."
        backing = TYPES[bare]["Kind"]
        return "Source " + bare + " underlying " + backing + "; preserve actual values and unknown representable numeric values with no ordinal offset; " + numeric_contract(backing, owner, field)
    bounds = {
        "int": "-9223372036854775808..9223372036854775807 (pinned Linux amd64)",
        "int64": "-9223372036854775808..9223372036854775807",
        "int32": "-2147483648..2147483647",
        "uint": "0..18446744073709551615 (pinned Linux amd64)",
        "uint64": "0..18446744073709551615",
        "uint32": "0..4294967295", "uint16": "0..65535", "uint8": "0..255",
        "float64": "finite IEEE-754 binary64; NaN/infinity rejected",
    }
    if bare in bounds:
        return "Source range " + bounds[bare] + "; checked conversion, no truncation/wrap; negative lengths/counts rejected."
    return None


def field_mapping(owner, field, index):
    source = field["Type"]
    fname = field["Name"]
    wire_name = snake(fname)
    if owner == "MessageEdit" and fname == "Channel":
        wire_name = "channel_id"
    special = SPECIAL.get((owner, fname))
    classification = "direct"
    reason = "Field-by-field conversion; source value is not mutated."
    if owner in RUNTIME:
        wire, classification, reason = None, "runtime-only", "Live runtime object; use authorized API results and typed events, not cache/session reconstruction."
    elif special:
        wire, classification, reason = special
        if fname in {"Token", "AccessToken"} and wire:
            wire_name = "credential_ref"
    elif fname in PERMISSIONS and source.lstrip("*") in {"int64", "int", "string"}:
        wire, classification = "string", "safe-wrapper"
        reason = "Decimal permission bitmask; no floating-point or enum conversion."
    elif fname == "Flags" or fname.endswith("Flags"):
        wire, classification = "uint64", "inline"
        reason = "Numeric mask, preserve every representable bit; range check before SDK conversion."
    else:
        wire = resolve(source)
        if source.lstrip("*").startswith(("[]", "map[")):
            classification = "safe-wrapper"
            reason = "Concrete collection wrapper preserves absent versus present empty; retain order/map keys; reject nil elements, never skip."
        elif source.lstrip("*") in TYPES and TYPES[source.lstrip("*")]["Kind"] != "struct":
            classification = "inline" if wire in SCALARS else "safe-wrapper"
    if wire and (owner, fname) in NULLABLE:
        wire = nullable(wire)
        classification = "safe-wrapper"
        reason += " Nullable patch field: absent/value/null retained; endpoint rejects unsupported null."
    if wire and source.lstrip("*") in {"MessageComponent", "InteractionData"}:
        classification = "safe-wrapper"
        reason = "Exhaustive typed polymorphic oneof; unknown/empty/typed-nil variant is an error, no JSON fallback."
    presence = "not transported" if not wire else "absent/value/null" if wire.startswith((CORE + "Nullable", "DomainNullable")) else "absent/value"
    record = {"source_field": fname, "source_type": source, "source_location": f"{TYPES[owner]['File']}:{field['Line']}", "source_json_tag": field.get("Tag", ""), "classification": classification, "wire_field": wire_name if wire else None, "wire_type": wire, "field_number": index if wire else None, "presence": presence, "decision": reason}
    if owner in SOURCE_JSON_OMIT_EMPTY_TYPES and source == "string" and wire == "string" and ",omitempty" in field.get("Tag", ""):
        record["source_json_omit_empty"] = True
        record["decision"] += " Outbound SDK JSON omits an empty value-only string; nonempty source values and direct wire presence stay authoritative."
    if (owner, fname) in SOURCE_JSON_OMIT_ZERO:
        if source not in {"int", "PollLayoutType"} or wire != "sint64" or ",omitempty" not in field.get("Tag", ""):
            raise ValueError("Reviewed numeric source omission contract changed: " + owner + "." + fname)
        record["source_json_omit_zero"] = True
        record["decision"] += " SDK JSON omits source zero for the optional provider-default field; nonzero source values and direct wire presence stay authoritative."
    numeric = numeric_contract(source, owner, fname)
    if numeric:
        record["numeric_contract"] = numeric
    return record


def partial_wire(record):
    wire = record["wire_type"]
    source = record["source_type"].lstrip("*")
    if wire.startswith(CORE + "Nullable"):
        return wire
    if wire.startswith("DomainNullable"):
        return nullable_partial_existing(wire)
    if record["classification"] == "safe-wrapper" and (wire.endswith("CredentialRef") or wire.endswith("JSONValue") or wire in {"ApplicationCommandChoiceValue", "ApplicationCommandOptionValue", "AttachmentEditList"}):
        return nullable(wire)
    if source not in {"interface{}", "io.Reader"} and not SPECIAL.get((record["owner"], record["source_field"])):
        scalar_permission = record["source_field"] in PERMISSIONS and source in {"int64", "int", "string"}
        if not scalar_permission and record["source_field"] != "Flags" and not record["source_field"].endswith("Flags"):
            wire = resolve(source, True)
    return nullable(wire)


def nullable_partial_existing(wire):
    value = WRAPPERS[wire][1]
    if value in SELECTED and TYPES.get(value, {}).get("Kind") == "struct":
        value = "Partial" + value
    return nullable(value)


# The union includes every legacy declaration, every API reachable type, and all
# shared nested DTOs reachable from all module projections. Event wrappers remain
# owned by events.proto and are explicitly classified in the mapping artifact.
roots = {SOURCE_RENAMES.get(n, n) for n in ast["SchemaMessages"] + ast["SchemaEnums"]} | {t["Name"] for t in closure["namedTypes"]}
roots |= set(COMPONENTS + DATA)
event_sources = {e["sourceType"] for e in events["events"]}
for event in events["events"]:
    if not event["moduleFacing"]:
        continue
    for f in TYPES[event["sourceType"]].get("Fields") or []:
        if (event["sourceType"], f["Name"]) not in SPECIAL:
            resolve(f["Type"])
for name in sorted(roots):
    if name in RUNTIME:
        SELECTED.add(name)
    else:
        resolve(name)

# Expand until every explicit source field has a mapping. No unresolved type,
# interface, runtime object, or dynamic payload can silently become raw JSON.
while True:
    pending = sorted(SELECTED - MAPPED.keys())
    if not pending:
        break
    for name in pending:
        t = TYPES[name]
        fields = [] if name == "File" else [field_mapping(name, f, i) for i, f in enumerate(t.get("Fields") or [], 1)]
        for f in fields:
            f["owner"] = name
        MAPPED[name] = {"source_type": name, "source_kind": t["Kind"], "source_location": f"{t['File']}:{t['Line']}", "classification": "runtime-only" if name in RUNTIME else "safe-wrapper" if name in {"File", "MessageComponent", "InteractionData"} else "direct" if t["Kind"] == "struct" else "inline", "wire_type": None if name in RUNTIME else "FileAttachment" if name == "File" else scalar_kind(name) or name, "fields": fields}

# File is an intentional boundary replacement; no io.Reader ever enters resolve.
MAPPED["File"]["fields"] = [
    {"source_field": "Name", "source_type": "string", "classification": "safe-wrapper", "wire_field": "filename", "wire_type": "string", "decision": "Explicit FileAttachment filename; not a host path."},
    {"source_field": "ContentType", "source_type": "string", "classification": "safe-wrapper", "wire_field": "uploaded_file_ref.content_type", "wire_type": "string", "decision": "Owned upload metadata is authoritative; verify copied content type."},
    {"source_field": "Reader", "source_type": "io.Reader", "classification": "safe-wrapper", "wire_field": "uploaded_file_ref", "wire_type": CORE + "UploadedFileRef", "decision": "Explicit pre-upload and host read lease; never reconstruct a nil Reader as success."},
]

lines = [
    '// Code generated by tools/protocol/emit-domain.py; DO NOT EDIT.',
    'syntax = "proto3";', '',
    'package flexmodule.discord.v2;',
    'option go_package = "github.com/thirdscam/chatanium/proto/discord-v2;discordv2";', '',
    'import "core-v2/core.proto";',
    'import "google/protobuf/timestamp.proto";',
    'import "google/protobuf/struct.proto";', '',
    '// Snapshot scalar fields use optional presence; absent collections are distinct from present empty.',
    '// Partial<Type> recursively preserves ingress absent/value/null for EVERY safe source field.',
    '// A present nullable wrapper must select value or null_value; an empty oneof is invalid.',
    '// Partial DTOs are built at trusted JSON ingress, never inferred from SDK zero-filled snapshots.',
    '// Domain conversion is explicit and fails on unknown polymorphic variants; no raw JSON fallback.',
    '// Permissions are nonnegative decimal strings; masks are uint64, never ordinal enums.',
    '// Numeric source aliases retain their actual values and unknown representable values, with no offset.',
    '// Integer narrowing, timestamps, non-finite doubles, nil collection elements and cycles are errors.',
    '// Numeric source int is signed 64-bit on the pinned Linux amd64 adapter.',
    '// Null in partial ingress means actual JSON null; request endpoint validation remains mandatory.', '',
]


def message(name, body, comment=None):
    identifier(name, "message name")
    for row in body:
        if "=" in row and not row.lstrip().startswith("//"):
            identifier(row.split("=", 1)[0].split()[-1], "field in " + name)
    if comment:
        lines.append("// " + comment)
    lines.append("message " + name + " {")
    lines.extend("  " + row for row in body)
    lines.extend(["}", ""])


message("FileAttachment", [CORE + "UploadedFileRef uploaded_file_ref = 1;", "string filename = 2;", "optional string description = 3;"], "Explicit uploaded-file boundary; no io.Reader, bytes body, or host path.")
message("AttachmentEditEntry", ["oneof source {", "  string existing_attachment_id = 1;", "  uint32 new_file_index = 2;", "}", "optional string filename = 3;", "optional string description = 4;"], "Complete retained/new attachment set; selected new_file_index=0 is valid, not absent.")
for item in ["FileAttachment", "MessageEmbed", "MessageComponent", "AttachmentEditEntry"]:
    sequence(item)
message("ApplicationCommandOptionValue", ["oneof value {", "  string string_value = 1;", "  sint64 integer_value = 2;", "  bool boolean_value = 3;", "  string user_id = 4;", "  string channel_id = 5;", "  string role_id = 6;", "  string mentionable_id = 7;", "  double number_value = 8;", "  string attachment_id = 9;", "}"], "INTEGER [-2^53+1,2^53-1], NUMBER [-2^53,2^53]; finite values only; SDK INTEGER uses float64.")
message("ApplicationCommandChoiceValue", ["oneof value {", "  string string_value = 1;", "  sint64 integer_value = 2;", "  double number_value = 3;", "}"], "Choice variant and range must agree with parent option type.")
for name, variants, field_names in [
    ("MessageComponent", COMPONENTS, ["actions_row", "button", "select_menu", "text_input", "section", "text_display", "thumbnail", "media_gallery", "file", "separator", "container", "label", "file_upload"]),
    ("InteractionData", DATA, ["application_command", "message_component", "modal_submit"]),
]:
    for partial in [False, True]:
        prefix = "Partial" if partial else ""
        body = ["oneof " + ("component" if name == "MessageComponent" else "data") + " {"]
        body += [f"  {prefix}{v} {f} = {i};" for i, (v, f) in enumerate(zip(variants, field_names), 1)]
        body.append("}")
        message(prefix + name, body, "Exhaustive concrete variants; discriminator/payload agreement required.")

for name in sorted(MAPPED):
    entry = MAPPED[name]
    if name in RUNTIME or name == "File" or entry["source_kind"] != "struct":
        continue
    fields = [f for f in entry["fields"] if f["wire_type"]]
    if name == "MessageEdit":
        order = ["ID", "Channel", "Content", "Components", "Embeds", "AllowedMentions", "Flags", "Files", "Attachments"]
        fields.sort(key=lambda f: order.index(f["source_field"]))
        for i, f in enumerate(fields, 1):
            f["field_number"] = i
    if name == "AuditLogChange":
        order = ["Key", "OldValue", "NewValue"]
        fields.sort(key=lambda f: order.index(f["source_field"]))
        for i, f in enumerate(fields, 1):
            f["field_number"] = i
    for partial in [False, True]:
        body = []
        for f in fields:
            wire = partial_wire(f) if partial else f["wire_type"]
            f["partial_wire_type"] = partial_wire(f)
            f["partial_presence"] = "absent wrapper / selected typed value (including empty) / explicit null"
            if f.get("numeric_contract"):
                body.append("// " + f["numeric_contract"])
            optional = "optional " if not partial and wire in SCALARS else ""
            # Normative required identity scalar spellings are intentionally plain.
            if not partial and name == "MessageEdit" and f["source_field"] in {"ID", "Channel"}:
                optional = ""
            body.append(f"{optional}{wire} {f['wire_field']} = {f['field_number']};")
        message(("Partial" if partial else "") + name, body, entry["source_location"] + ("; recursive ingress presence view." if partial else "; safe domain snapshot/request."))

for name, shape in sorted(WRAPPERS.items()):
    if shape[0] == "nullable":
        message(name, ["oneof kind {", f"  {shape[1]} value = 1;", "  google.protobuf.NullValue null_value = 2;", "}"])
    elif shape[0] == "list":
        message(name, [f"repeated {shape[1]} values = 1;"])
    elif shape[0] == "map":
        message(name, [f"map<{shape[1]}, {shape[2]}> values = 1;"])
    else:
        raise ValueError("Unknown wrapper shape " + repr(shape))

# Each legacy field is explicitly mapped, including wrong v1 source names.
legacy_mapping = []
normalize = lambda s: re.sub("[^a-z0-9]", "", s.lower())
for item in legacy["messages"]:
    name = item["type"]
    current_name = SOURCE_RENAMES.get(name, name)
    target = MAPPED[current_name]
    fields = []
    for old in item.get("protoFields", []):
        retired = ast["RetiredTypeFields"].get(current_name, {})
        retired_names = [field for field in retired if normalize(field) == normalize(old)]
        if retired_names:
            if len(retired_names) != 1:
                raise ValueError(f"Ambiguous retired legacy field {name}.{old}")
            source_name = retired_names[0]
            decision = retired[source_name]
            fields.append({"legacy_field": old, "source_field": source_name, "classification": decision["classification"], "wire_field": None, "wire_type": None, "decision": decision["decision"]})
            continue
        if TYPES[current_name]["Kind"] != "struct":
            fields.append({"legacy_field": old, "classification": "safe-wrapper" if name == "MessageComponent" else "inline", "wire_type": target["wire_type"], "decision": "Exhaustive component oneof replaces v1 payload." if name == "MessageComponent" else "Inline underlying value, preserving numeric/string/mask meaning; no unnecessary scalar message."})
            continue
        source_name = LEGACY_FIELD_RENAMES.get((name, old))
        if not source_name:
            matches = [f["source_field"] for f in target["fields"] if normalize(f["source_field"]) == normalize(old)]
            if len(matches) != 1:
                raise ValueError(f"Unclassified legacy field {name}.{old}")
            source_name = matches[0]
        match = next(f for f in target["fields"] if f["source_field"] == source_name)
        fields.append({"legacy_field": old, "source_field": source_name, "classification": match["classification"], "wire_field": match.get("wire_field"), "wire_type": match.get("wire_type"), "decision": match["decision"]})
    legacy_mapping.append({"legacy_type": name, "source_type": SOURCE_RENAMES.get(name, name), "classification": target["classification"], "wire_type": target["wire_type"], "fields": fields, "migration": "Clean source rename; historical name is not emitted or re-exported." if name in SOURCE_RENAMES else "Current source declaration retained or explicitly classified."})

event_mapping = []
for event in events["events"]:
    owner = event["sourceType"]
    ef = []
    for f in TYPES[owner].get("Fields") or []:
        excluded = not event["moduleFacing"] or (owner, f["Name"]) in SPECIAL and SPECIAL[owner, f["Name"]][0] is None
        ef.append({"source_field": f["Name"], "source_type": f["Type"], "classification": "runtime-only" if excluded else "inline", "owner": "events.proto", "decision": "Host-only event/connection secret is not module-visible." if excluded else "Event-owner typed wrapper, recursive Partial<Type> for ingress and Type for real before snapshots; wrapper absent/value/null retained."})
    event_mapping.append({"source_type": owner, "projection": event["projection"], "module_facing": event["moduleFacing"], "classification": "inline" if event["moduleFacing"] else "runtime-only", "fields": ef})

event_by_source = {entry["source_type"]: entry for entry in event_mapping}
combined_mapping = []
for source in closure["combinedReachableNamedTypes"]:
    name = source["Name"]
    if name in MAPPED:
        entry = MAPPED[name]
        owner, wire_type = "domain.proto", entry["wire_type"]
    elif name in event_by_source:
        entry = event_by_source[name]
        owner, wire_type = "events.proto", entry["projection"]
    else:
        raise ValueError("Unclassified combined API/event closure type: " + name)
    combined_mapping.append({"source_type": name, "owner": owner, "classification": entry["classification"], "wire_type": wire_type})

artifact = {
    "contract": "P1/P2 explicit field-level source-to-wire mapping; SOURCE audit, not claimed converter implementation or executed validation",
    "generation_command": "python3 tools/protocol/emit-domain.py",
    "source_provenance": ast.get("sourceProvenance"),
    "historical_baseline": {"legacy_messages": len(ast["SchemaMessages"]), "legacy_enums": len(ast["SchemaEnums"]), "acceptance_limit": False},
    "source_renames": SOURCE_RENAMES,
    "component_discriminators": closure["componentDiscriminators"],
    "source_type_counts": {"api_reachable": closure["reachableNamedTypeCount"], "event_reachable": closure["eventReachableNamedTypeCount"], "combined_reachable": closure["combinedReachableNamedTypeCount"], "event_rows": events["sourceCount"], "module_projections": events["moduleFacingCount"]},
    "source_inventory_filter": "source-ast.Types entries whose File starts with discordgo/ only",
    "numeric_policy": {"int": "sint64 (Linux amd64 signed 64-bit)", "uint": "uint64", "uint8": "uint32; source range 0..255", "uint16": "uint32; source range 0..65535", "int32": "sint32", "int64": "sint64", "masks": "uint64; source range checked", "permissions": "nonnegative decimal string; source SDK int64 0..9223372036854775807", "numeric_enums": "inline actual source numeric value, no ordinal renumbering; unknown representable values retained where permitted", "string_enums": "inline original string; no rune casts", "interaction_integer": "sint64 [-9007199254740991,9007199254740991], reconstructed SDK float64", "interaction_number": "finite double [-9007199254740992,9007199254740992]"},
    "presence_policy": {"snapshot": "optional scalar; message/collection wrapper presence retained", "partial": "Partial<Type> for every safe source struct, recursively wrapped fields; absent wrapper=absent; oneof.value=present including zero/false/empty; oneof.null_value=actual explicit null; empty oneof invalid", "authority": "trusted ingress captures presence before SDK unmarshal; no reconstruction from scalar zero values; before snapshots only if actually cached", "collections": "snapshot nil/empty may normalize only when semantics equivalent; patch/event wrapper distinction remains authoritative; preserve map keys/order; nil elements rejected", "request_null": "only endpoint-approved null accepted, regardless of wrapper expressiveness"},
    "legacy_messages": legacy_mapping,
    "legacy_enums": [{"legacy_type": n, "classification": "inline", "source_backing": TYPES[n]["Kind"], "wire_type": scalar_kind(n), "meaning": "bitmask" if n in MASKS else "string enum" if scalar_kind(n) == "string" else "numeric discriminator, original source value"} for n in ast["SchemaEnums"]],
    "types": [MAPPED[n] for n in sorted(MAPPED)],
    "events": event_mapping,
    "api_reachable_types": [{"source_type": t["Name"], "classification": MAPPED[t["Name"]]["classification"], "wire_type": MAPPED[t["Name"]]["wire_type"]} for t in closure["namedTypes"]],
    "combined_reachable_types": combined_mapping,
    "wrappers": [{"wire_type": n, "shape": list(shape)} for n, shape in sorted(WRAPPERS.items())],
    "added_boundary_fields": [{"wire_type": "FileAttachment", "wire_field": "description", "classification": "safe-wrapper", "decision": "P1 optional upload description, absent versus explicit empty preserved."}, {"wire_type": "AttachmentEditEntry", "classification": "safe-wrapper", "decision": "P1 source oneof and optional metadata; index 0 selected is valid; each new index exactly once."}],
}
if not args.mapping_only:
    (ROOT / "proto/discord-v2").mkdir(parents=True, exist_ok=True)
    (ROOT / "proto/discord-v2/domain.proto").write_text("\n".join(lines))
(ROOT / "tools/protocol/domain-mapping.json").write_text(json.dumps(artifact, ensure_ascii=False, indent=2) + "\n")
print(f"Wrote {'domain-mapping.json' if args.mapping_only else 'domain.proto and domain-mapping.json'}: {len(MAPPED)} source types, {sum(len(t['fields']) for t in MAPPED.values())} fields, {len(legacy_mapping)} legacy messages, {len(ast['SchemaEnums'])} legacy enums.")
