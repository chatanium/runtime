#!/usr/bin/env python3
"""Emit P1 typed event contracts from the complete reviewed SDK inventory.

Run from the repository root: python3 tools/protocol/generate_events.py
No SDK decoding, protobuf generation, or runtime validation is performed here.
"""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INVENTORY = ROOT / "tools/protocol/inventory"


def snake(name):
    name = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name).lower()


def emit(mapping_only=False):
    catalog = json.loads((INVENTORY / "source-events.json").read_text())
    ast = json.loads((INVENTORY / "source-ast.json").read_text())
    types = {t["Name"]: t for t in ast["Types"] if t["File"].startswith("discordgo/")}
    rows = catalog["events"]
    active = [r for r in rows if r["moduleFacing"]]
    if len(rows) != catalog["sourceCount"] or len(active) != catalog["moduleFacingCount"]:
        raise ValueError("event catalog counts must cover every source row")
    if len(rows) - len(active) != catalog["hostOnlyOrLegacyCount"]:
        raise ValueError("unclassified source event row")
    if len({r["canonicalName"] for r in active}) != len(active):
        raise ValueError("duplicate canonical event name")
    if len({r["projection"] for r in active}) != len(active):
        raise ValueError("duplicate concrete event projection")
    wrappers = {}
    lists = {}
    mapping = []
    messages = []
    removed_ready = {"SessionID": "host-only session credential", "Shard": "host-only connection control", "ResumeGatewayURL": "host-only resume endpoint"}
    scalar_types = {"string": ("String", "string"), "bool": ("Bool", "bool"), "int": ("Int64", "sint64"), "int64": ("Int64", "sint64"), "uint": ("Uint64", "uint64"), "uint32": ("Uint32", "uint32"), "uint64": ("Uint64", "uint64")}

    def field_type(source):
        if source.startswith("[]"):
            element = field_type(source[2:])
            name = element.removesuffix("Field") + "List"
            lists[name] = element
            result = name + "Field"
            wrappers[result] = name
            return result
        base = source.lstrip("*")
        if base in scalar_types:
            suffix, wire = scalar_types[base]
        elif base in types and types[base]["Kind"] == "struct":
            suffix, wire = base, "Partial" + base
        elif base in types and types[base]["Kind"] in scalar_types:
            suffix, wire = scalar_types[types[base]["Kind"]]
        else:
            raise ValueError("unclassified event field type: " + source)
        name = "Event" + suffix + "Field"
        wrappers[name] = wire
        return name

    for row in rows:
        record = dict(row)
        record["fields"] = []
        if not row["moduleFacing"]:
            record["classification"] = "host-only-or-legacy"
            mapping.append(record)
            continue
        projection = row["projection"]
        record["classification"] = "typed-module-event"
        record["typeURL"] = "type.googleapis.com/flexmodule.discord.v2." + projection
        record["presence"] = "nullable recursive Partial domain fields; absent wrapper=absent, oneof null=null, value preserves zero/false/empty; Before snapshots only if actually cached"
        message = ["// Source: discordgo." + row["sourceType"] + "; official " + row["canonicalName"] + ".", "message " + projection + " {"]
        for number, field in enumerate(types[row["sourceType"]]["Fields"], 1):
            source_name = field["Name"]
            item = {"sourceField": source_name, "sourceType": field["Type"], "sourceLine": field["Line"], "fieldNumber": number}
            if row["sourceType"] == "Ready" and source_name in removed_ready:
                item.update(classification="runtime-only-removed", reason=removed_ready[source_name])
                message.append("  reserved " + str(number) + "; // " + source_name + ": " + removed_ready[source_name])
            else:
                tag = re.search(r'json:"([^",]+)', field["Tag"])
                embedded = not field["Tag"]
                name = snake(source_name.lstrip("*")) if embedded or tag is None or tag[1] == "-" else tag[1]
                before = source_name in ("BeforeUpdate", "BeforeDelete")
                wire_type = field["Type"].lstrip("*") if before else field_type(field["Type"])
                if before:
                    message.append("  // Present only when this source cache snapshot actually exists; never fetched or invented.")
                if embedded:
                    message.append("  // Embedded source object; capture its original flattened JSON fields before SDK zero-filling.")
                message.append("  " + wire_type + " " + name + " = " + str(number) + ";")
                item.update(classification="actual-optional-cache-snapshot" if before else "typed-presence-projection", wireField=name, wireType=wire_type, sourceJSON="flattened-embedded" if embedded else ("local-cache-only" if before else tag[1] if tag else name))
                if field["Type"].lstrip("*") == "Interaction":
                    item["credentialPolicy"] = "PartialInteraction.credential_ref replaces token through authenticated runtime projection; no raw token"
            record["fields"].append(item)
        message.append("}")
        messages.append("\n".join(message))
        mapping.append(record)

    schema = ['syntax = "proto3";', '', 'package flexmodule.discord.v2;', 'option go_package = "github.com/thirdscam/chatanium/proto/discord-v2;discordv2";', '', 'import "discord-v2/domain.proto";', 'import "google/protobuf/struct.proto";', '', '// Generated by tools/protocol/generate_events.py. Do not edit.', '// Typed presence is captured before lossy SDK decoding, for every event (not just updates).', '// An absent wrapper means absent; null means explicit JSON null; value preserves zero,', '// false, and empty collections. Nested objects recursively use domain Partial<Type>.', '// Collection element wrappers also preserve explicit null elements. No raw JSON payload.', '// Before snapshots are independent optional cache values, never synthesized or fetched.', '']
    for name, element in sorted(lists.items()):
        schema.append("message " + name + " { repeated " + element + " values = 1; }")
    schema.append("")
    for name, value in sorted(wrappers.items()):
        schema.extend(["message " + name + " {", "  oneof kind {", "    " + value + " value = 1;", "    google.protobuf.NullValue null = 2;", "  }", "}"])
    schema.extend([""] + messages + [""])
    if not mapping_only:
        (ROOT / "proto/discord-v2/events.proto").write_text("\n".join(schema))
    artifact = {"sourceCount": len(rows), "moduleFacingCount": len(active), "hostOnlyOrLegacyCount": len(rows) - len(active), "sourceProvenance": catalog.get("sourceProvenance"), "contract": "P1 boundary policies applied to the complete reviewed current SDK inventory; historical counts are not limits; no aliases or raw fallback", "events": mapping}
    (ROOT / "tools/protocol/event-mapping.json").write_text(json.dumps(artifact, indent=2, ensure_ascii=False) + "\n")
    if not mapping_only:
        emit_registry(active)


def emit_registry(rows):
    go = ['// Code generated by tools/protocol/generate_events.py. DO NOT EDIT.', 'package discordv2', '', 'import (', '\t"fmt"', '', '\tcorev2 "github.com/thirdscam/chatanium/proto/core-v2"', '\twire "github.com/thirdscam/chatanium/proto/discord-v2"', '\t"google.golang.org/protobuf/proto"', ')', '', '// EventDescriptor registers one official module-visible event and its exact DTO.', '// IntentAlternatives contains alternative intent sets by event resource context;', '// not every alternative is required at once. Empty means no event-specific intent.', '// ConditionalIntents apply to expanded data, not base event delivery (for example', '// other users in THREAD_MEMBERS_UPDATE or non-exempt message content).', 'type EventDescriptor struct {', '\tName string', '\tTypeURL string', '\tCapability string', '\tIntentAlternatives [][]string', '\tConditionalIntents []string', '}', '', 'type eventRegistration struct {', '\tdescriptor EventDescriptor', '\tnewMessage func() proto.Message', '}', '', 'var eventRegistry = map[string]eventRegistration{']
    for row in rows:
        name = row["canonicalName"]
        intents = row["officialIntents"]
        conditional = []
        if name == "THREAD_MEMBERS_UPDATE":
            alternatives = [["GUILDS"]]
            conditional = ["GUILD_MEMBERS"]
        elif any(i.startswith("DIRECT_") for i in intents):
            alternatives = [[i] for i in intents]
        else:
            alternatives = [intents] if intents else []
        if name in ("MESSAGE_CREATE", "MESSAGE_UPDATE"):
            conditional.append("MESSAGE_CONTENT")
        intent_go = '[][]string{' + ', '.join('{' + ', '.join(json.dumps(i) for i in group) + '}' for group in alternatives) + '}'
        conditional_go = '[]string{' + ', '.join(json.dumps(i) for i in conditional) + '}'
        url = "type.googleapis.com/flexmodule.discord.v2." + row["projection"]
        go.extend(['\t' + json.dumps(name) + ': {', '\t\tdescriptor: EventDescriptor{Name: ' + json.dumps(name) + ', TypeURL: ' + json.dumps(url) + ', Capability: ' + json.dumps("discord.event." + name) + ', IntentAlternatives: ' + intent_go + ', ConditionalIntents: ' + conditional_go + '},', '\t\tnewMessage: func() proto.Message { return &wire.' + row["projection"] + '{} },', '\t},'])
    go.extend(['}', '', '// EventRegistry returns every registered descriptor in stable official-name order.', '// Returned slices are independent of the immutable decoder registry.', 'func EventRegistry() []EventDescriptor {', '\tresult := make([]EventDescriptor, 0, len(eventNames))', '\tfor _, name := range eventNames {', '\t\tresult = append(result, cloneEventDescriptor(eventRegistry[name].descriptor))', '\t}', '\treturn result', '}', '', 'var eventNames = [...]string{'])
    for row in sorted(rows, key=lambda r: r["canonicalName"]):
        go.append('\t' + json.dumps(row["canonicalName"]) + ',')
    go.extend(['}', '', '// LookupEvent recognizes only official module-visible names; no legacy aliases.', 'func LookupEvent(name string) (EventDescriptor, bool) {', '\tentry, ok := eventRegistry[name]', '\tif !ok { return EventDescriptor{}, false }', '\treturn cloneEventDescriptor(entry.descriptor), true', '}', '', 'func cloneEventDescriptor(source EventDescriptor) EventDescriptor {', '\tresult := source', '\tresult.IntentAlternatives = make([][]string, len(source.IntentAlternatives))', '\tfor i, intents := range source.IntentAlternatives {', '\t\tresult.IntentAlternatives[i] = append([]string(nil), intents...)', '\t}', '\tresult.ConditionalIntents = append([]string(nil), source.ConditionalIntents...)', '\treturn result', '}', '', '// DecodeEvent validates the backend, major, official event name and exact type URL', '// before unmarshalling into its registered concrete generated DTO. Callers use a', '// type switch on the result, never Any/raw dispatch. It does not infer field', '// presence from zero-filled SDK values or manufacture before snapshots.', 'func DecodeEvent(envelope *corev2.EventEnvelope) (proto.Message, error) {', '\treturn strictDecodeEvent(envelope)', '}', '', 'func strictDecodeEvent(envelope *corev2.EventEnvelope) (proto.Message, error) {', '\tif envelope == nil { return nil, fmt.Errorf("discord event: missing envelope") }', '\tif envelope.BackendId != "discord" || envelope.BackendMajor != 2 {', '\t\treturn nil, fmt.Errorf("discord event: unsupported backend or major")', '\t}', '\tentry, ok := eventRegistry[envelope.EventType]', '\tif !ok { return nil, fmt.Errorf("discord event: unregistered event type") }', '\tif envelope.Payload == nil || envelope.Payload.TypeUrl != entry.descriptor.TypeURL {', '\t\treturn nil, fmt.Errorf("discord event: payload type URL mismatch")', '\t}', '\tvalue := entry.newMessage()', '\tif err := proto.Unmarshal(envelope.Payload.Value, value); err != nil {', '\t\treturn nil, fmt.Errorf("discord event: malformed typed payload: %w", err)', '\t}', '\treturn value, nil', '}', ''])
    destination = ROOT / "shared/discord-v2/events.go"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text("\n".join(go))


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mapping-only", action="store_true", help="Refresh source mapping JSON without emitting shared protobuf/Go contracts")
    emit(mapping_only=parser.parse_args().mapping_only)
