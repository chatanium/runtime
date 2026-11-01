#!/usr/bin/env python3
"""Refresh reviewed source catalogs from the stdlib AST extraction.

Run from the repository root after extract-source.go. This emits JSON source
inventories only, never protobufs/converters. source-policy.json is the reviewed
allowlist; additions or changes must be reviewed there, not silently accepted.
The immutable source-baseline-v0.29.0.json and legacy conversion audit retain
historical declarations and original comparison provenance.
"""
import argparse
import copy
import hashlib
import json
from collections import Counter
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from sdk import provenance as sdk_provenance, resolve as resolve_sdk
DEFAULT = ROOT / "tools/protocol/inventory"
BUILTINS = set("bool byte complex64 complex128 error float32 float64 int int8 int16 int32 int64 rune string uint uint8 uint16 uint32 uint64 uintptr any comparable".split())
SOURCE_KEYS = {"name", "signature", "source", "endLine", "documentation", "body", "arguments", "results", "endpointExpressions"}


def load(path):
    return json.loads(path.read_text())


def sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def shape(record):
    # Locations/docs are preserved in output, but not mistaken for type changes.
    fields = lambda rows: [{k: f[k] for k in ("Name", "Type", "Tag")} for f in rows or []]
    return {"Kind": record["Kind"], "Alias": record["Alias"],
            "Fields": fields(record["Fields"]),
            "InterfaceMethods": fields(record.get("InterfaceMethods"))}


def method_shape(record):
    return {k: record[k] for k in ("signature", "body", "documentation")}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def exact_keys(actual, reviewed, label):
    added, removed = sorted(set(actual) - set(reviewed)), sorted(set(reviewed) - set(actual))
    require(not added and not removed, f"Unclassified {label}: added={added}, removed={removed}")


def unique(rows, key, label):
    result = {r[key]: r for r in rows}
    require(len(result) == len(rows), f"Duplicate {label}")
    return result


def kind(record):
    return "struct" if record["Kind"] == "struct" else "interface" if record["Kind"] == "interface{}" else "scalar_or_named_alias"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, default=DEFAULT)
    args = parser.parse_args()
    directory = args.inventory
    raw = load(directory / "source-extracted.json")
    policy = load(directory / "source-policy.json")
    historical = load(directory / "source-baseline-v0.29.0.json")
    baseline = historical["inventories"]
    audit = directory / "legacy-conversion-coverage.json"
    require(hashlib.sha256(audit.read_bytes()).hexdigest() == historical["provenance"]["inventorySHA256"][audit.name], "Historical conversion audit changed")
    historical_ast = baseline["source-ast.json"]
    require(len(historical_ast["SchemaMessages"]) == 154 and len(historical_ast["SchemaEnums"]) == 23, "Historical schema census changed")
    files = {f["path"]: f["sha256"] for f in raw["sourceFiles"]}
    require(len(files) == len(raw["sourceFiles"]), "Duplicate SDK source file")
    require(sha(raw["sourceFiles"]) == policy["provenance"]["sourcePackageSHA256"], "Source package revision digest disagrees with reviewed provenance")
    require(files == policy["sourceFiles"], "Source files do not match reviewed source pin; re-extract and review source-policy.json")
    sdk = resolve_sdk()
    require(raw["sdkModule"] == sdk_provenance(sdk), "Extraction does not match the required canonical SDK module")
    sdk_directory = Path(sdk["Dir"])
    for name, expected in files.items():
        require(Path(name).parent == Path("discordgo"), f"Unexpected logical SDK source identity: {name}")
        require(hashlib.sha256((sdk_directory / Path(name).name).read_bytes()).hexdigest() == expected, f"Stale extraction: {name}")
    current_files = {"discordgo/" + path.name for path in sdk_directory.glob("*.go") if not path.name.endswith("_test.go")}
    exact_keys(current_files, files, "SDK source file")
    require(raw["sourceFiles"] == policy["sourceFileBuildPolicies"], "Unreviewed SDK build constraints/profile membership")
    types = unique(raw["types"], "Name", "SDK type")
    methods = unique(raw["methods"], "name", "Session method")
    events = unique(raw["events"], "sourceName", "source event")
    exact_keys(types, policy["types"], "type")
    exact_keys(methods, policy["methods"], "method")
    exact_keys(events, policy["events"], "event")
    require(sha(raw["nestedTypes"]) == policy["nestedTypesSHA256"], "Unreviewed nested type/field syntax")
    require(raw["polymorphicExpansion"] == policy["polymorphicExpansion"], "Unclassified polymorphic variant")
    for name, t in types.items():
        reviewed = policy["types"][name]
        require(sha(shape(t)) == reviewed["shapeSHA256"], f"Unclassified type/field change: {name}")
        exact_keys([f["Name"] for f in t["Fields"] or []], reviewed["fields"], name + " field")
        require(reviewed["classification"] and all(reviewed["fields"].values()), f"Missing field/type policy for {name}")
        dependencies = set(t["References"]) - types.keys() - BUILTINS
        require(not dependencies, f"Unknown type references in {name}: {sorted(dependencies)}")
    for name, m in methods.items():
        require(sha(method_shape(m)) == policy["methods"][name]["sourceSHA256"], f"Unreviewed method signature/body/defaults/docs: {name}")
        for argument in m["arguments"] + m["results"]:
            unknown = set(argument["references"]) - types.keys() - BUILTINS
            require(not unknown, f"Unknown method types in {name}: {sorted(unknown)}")
    for name, e in events.items():
        require(sha(e) == policy["events"][name]["sourceSHA256"], f"Unreviewed event registration/wrapper: {name}")
    nested = {f"{t['File']}:{t['Line']}:{t['Column']}:{t['Name']}": t for t in raw["nestedTypes"]}
    require(len(nested) == len(raw["nestedTypes"]), "Duplicate nested declaration")
    nested_names = {t["Name"] for t in raw["nestedTypes"] if not t["Name"].startswith("anonymous@")}
    exact_keys(nested, policy["nestedTypes"], "nested declaration")
    for name, t in nested.items():
        require(sha(shape(t)) == policy["nestedTypes"][name]["shapeSHA256"], f"Unreviewed nested declaration: {name}")
        unknown = set(t["References"]) - types.keys() - nested_names - BUILTINS
        require(not unknown, f"Unknown nested type references in {name}: {sorted(unknown)}")
    for name, fields in policy["retiredTypeFields"].items():
        require(name in types, f"Unknown owner of retired source fields: {name}")
        current = {f["Name"] for f in types[name]["Fields"] or []}
        require(not current & fields.keys(), f"Retired source field reappeared: {name}")
        require(all(f["classification"] == "runtime-only" and f["decision"] for f in fields.values()), f"Unreviewed retired field disposition: {name}")
    declarations = {d["receiver"] + "." + d["name"]: d for d in raw["publicDeclarations"]}
    exact_keys(declarations, policy["publicDeclarations"], "public SDK declaration")
    profiles = {}
    public_rows = []
    for name, declaration in sorted(declarations.items()):
        reviewed = policy["publicDeclarations"][name]
        require(sha(declaration) == reviewed["sourceSHA256"], f"Unreviewed public SDK declaration: {name}")
        require(reviewed["classification"] and reviewed["decision"], f"Missing public SDK declaration policy: {name}")
        for implementation in declaration["implementations"]:
            for argument in implementation["arguments"] + implementation["results"]:
                unknown = set(argument["references"]) - types.keys() - BUILTINS
                require(not unknown, f"Unknown public declaration types in {name}: {sorted(unknown)}")
        public_rows.append({**copy.deepcopy(declaration), "classification": reviewed["classification"], "decision": reviewed["decision"]})
    for profile in ("ordinary", "native_voice"):
        active_files = {f["path"] for f in raw["sourceFiles"] if profile in f["buildProfiles"]}
        active_declarations = []
        for name, declaration in declarations.items():
            active = [m for m in declaration["implementations"] if m["source"].rsplit(":", 1)[0] in active_files]
            require(len(active) <= 1, f"Duplicate active declaration in {profile}: {name}")
            if active:
                active_declarations.append(name)
        profiles[profile] = {
            "GOOS": "linux", "GOARCH": "amd64", "CGO_ENABLED": profile == "native_voice",
            "tags": ["voice"] if profile == "native_voice" else [],
            "sourceFiles": sorted(active_files),
            "packageTypes": sorted(t["Name"] for t in types.values() if t["File"] in active_files),
            "publicDeclarations": sorted(active_declarations),
            "sessionMethods": sorted(m["name"] for m in methods.values() if m["source"].rsplit(":", 1)[0] in active_files),
            "evidence": "Go syntax and build-constraint selection only; not compiled or executed behavior.",
        }

    def dependencies(record):
        refs = set(record["References"])
        unknown = refs - types.keys() - BUILTINS
        require(not unknown, f"Unknown type references in {record['Name']}: {sorted(unknown)}")
        return sorted(refs & types.keys())

    def closure(roots):
        pending, selected = list(roots), set()
        while pending:
            name = pending.pop()
            require(name in types, f"Unknown type root: {name}")
            if name in selected:
                continue
            selected.add(name)
            pending.extend(dependencies(types[name]))
            pending.extend(raw["polymorphicExpansion"].get(name, []))
        return [{**copy.deepcopy(types[n]), "References": dependencies(types[n])} for n in sorted(selected)]

    api = copy.deepcopy(baseline["source-api.json"])
    rows, roots, external_roots = [], set(), set()
    for name, m in sorted(methods.items()):
        reviewed = policy["methods"][name]
        row = copy.deepcopy(reviewed["metadata"])
        row.update(copy.deepcopy(m))
        row["sourceSignature"] = m["signature"]
        row["sourceRange"] = f"{m['source']}-{m['endLine']}"
        row["sourceReview"] = reviewed["review"]
        method_roots = set()
        if row["exposed"]:
            for a in m["arguments"] + m["results"]:
                method_roots.update(set(a["references"]) - BUILTINS - {"RequestOption"})
                external_roots.update(a["externalReferences"])
            require(not method_roots - types.keys(), f"Unknown method roots: {name}: {sorted(method_roots - types.keys())}")
            roots.update(method_roots)
        row["typeRoots"] = sorted(method_roots)
        if row["classification"] == "convenience_alias":
            canonical = row["protoOperation"]
            require(canonical in methods, f"Missing alias target {name}: {canonical}")
            target = policy["methods"][canonical]["metadata"]
            require(target["exposed"] and target["classification"] != "convenience_alias", f"Alias target is not canonical: {name}")
            require(reviewed.get("aliasMapping"), f"Missing complete alias mapping: {name}")
            row["aliasMapping"] = reviewed["aliasMapping"]
        rows.append(row)
    reachable = closure(roots)
    event_roots = sorted({e["sourceType"] for e in events.values()})
    event_reachable = closure(event_roots)
    combined = closure(roots | set(event_roots))
    type_closure = copy.deepcopy(baseline["source-type-closure.json"])
    type_closure.update({
        "methodTypeRoots": sorted(roots), "methodTypeRootCount": len(roots),
        "externalTypeRoots": policy["externalTypePolicies"],
        "sourceExternalSignatureTypes": sorted(external_roots),
        "reachableNamedTypeCount": len(reachable),
        "reachableKindCounts": dict(sorted(Counter(kind(t) for t in reachable).items())),
        "namedTypes": reachable,
        "polymorphicExpansion": raw["polymorphicExpansion"],
        "componentDiscriminators": policy["componentDiscriminators"],
        "fieldBoundaryPolicies": policy["fieldBoundaryPolicies"],
        "eventTypeRoots": event_roots, "eventReachableNamedTypes": event_reachable,
        "eventReachableNamedTypeCount": len(event_reachable),
        "combinedReachableNamedTypeCount": len(combined),
        "combinedReachableNamedTypes": combined,
        "completeness": "Recursive closure of actual reviewed SDK syntax: canonical/alias/exposed-state method arguments and results; source-event closure is recorded separately. Explicit polymorphic variants are source-derived and policy-checked. SDK Session/RequestOption machinery is not a method root. Counts describe source named types, not protobuf messages or implemented converters.",
    })
    event_catalog = copy.deepcopy(baseline["source-events.json"])
    event_rows = []
    for name, e in sorted(events.items()):
        row = copy.deepcopy(policy["events"][name]["metadata"])
        row.update(copy.deepcopy(e))
        t = types[e["sourceType"]]
        row["source"] = f"{e['constantSource']}; {t['File']}:{t['Line']}-{t['End']}"
        row["sourceFields"] = copy.deepcopy(t["Fields"])
        row["beforeSnapshotFields"] = [f["Name"] for f in t["Fields"] or [] if f["Name"].startswith("Before")]
        event_rows.append(row)
    synthetic = sum(r["sourceName"].startswith("__") for r in event_rows)
    visible = sum(r["moduleFacing"] for r in event_rows)
    event_catalog.update({"sourceCount": len(event_rows), "syntheticCount": synthetic, "nonSyntheticCount": len(event_rows)-synthetic, "moduleFacingCount": visible, "hostOnlyOrLegacyCount": len(event_rows)-visible, "events": event_rows})
    api["methods"] = rows
    oldcounts = api["counts"]
    categories = Counter(r["classification"] for r in rows)
    canonical = [r for r in rows if r["classification"] == "canonical_typed_bot_rpc"]
    internal = [r for r in rows if r["classification"] == "backend_internal_control_helper"]
    allowed = set(api["classificationLegend"])
    require(not categories.keys() - allowed, "Unknown method classification")
    api["counts"] = {**oldcounts,
        "sourceMethods": len(rows), "canonicalTypedBotRPC": len(canonical),
        "convenienceAliases": categories["convenience_alias"], "backendInternalControlHelper": len(internal),
        "excluded": categories["excluded_user_account_oauth_owner_only_unsafe_http"],
        "exposedBackendStateHelpers": sum(r["exposed"] for r in internal),
        "nonExposedBackendInternalControlConveniences": sum(not r["exposed"] for r in internal),
        "distinctTypedRPCOperationsIncludingStateHelper": len({r["protoOperation"] for r in rows if r["exposed"]}),
        "retainedMethodsIncludingAliasesAndStateHelper": sum(r["exposed"] for r in rows),
        "sourceFiles": dict(sorted(Counter(r["source"].split(":")[0] for r in rows).items())),
        "canonicalTransports": dict(sorted(Counter(r["transportKind"] for r in canonical).items())),
        "typeRoots": len(roots), "reachableNamedTypes": len(reachable),
        "reachableTypeKinds": type_closure["reachableKindCounts"], "omittedMethods": 0, "unresolvedClassifications": 0,
    }
    api["authoritativeInput"] = "source-extracted.json from go/parser over the reviewed exact SDK source; historical denominator preserved in source-baseline-v0.29.0.json"
    api["transportTypeClosure"] = copy.deepcopy(type_closure)
    references = api["officialReferences"] + policy["officialReferences"]
    api["officialReferences"] = list({sha(r): r for r in references}.values())
    source_ast = copy.deepcopy(baseline["source-ast.json"])
    old_generated = [t for t in source_ast["Types"] if not t["File"].startswith("discordgo/")]
    for t in old_generated:
        t["Provenance"] = "historical generated Go declaration; not refreshed SDK syntax"
    source_ast["Types"] = copy.deepcopy(raw["types"]) + old_generated
    source_ast["NestedTypes"] = copy.deepcopy(raw["nestedTypes"])
    source_ast["HistoricalFunctions"] = source_ast["Functions"]
    source_ast["FunctionProvenance"] = "Original legacy conversion source audit; not refreshed or claimed current implementation"
    source_ast["HistoricalSchemaProvenance"] = "SchemaMessages/SchemaEnums are the unchanged original 154-message/23-enum legacy baseline from source-baseline-v0.29.0.json. Historical v1 source paths are provenance only: clean cutover removed those files; refresh never reads or requires them. Not a current SDK type or wire-schema denominator."
    source_ast["NestedTypePolicies"] = copy.deepcopy(policy["nestedTypes"])
    source_ast["BuildProfiles"] = profiles
    source_ast["TypePolicies"] = copy.deepcopy(policy["types"])
    source_ast["RetiredTypeFields"] = copy.deepcopy(policy["retiredTypeFields"])
    provenance = {**policy["provenance"], "sdkModule": raw["sdkModule"], "extraction": "go run -mod=readonly tools/protocol/extract-source.go -out tools/protocol/inventory/source-extracted.json", "refresh": "python3 tools/protocol/refresh-inventory.py", "sourceFiles": raw["sourceFiles"], "rawSHA256": hashlib.sha256((directory / "source-extracted.json").read_bytes()).hexdigest(), "historicalBaseline": "source-baseline-v0.29.0.json", "legacyConversionAudit": "legacy-conversion-coverage.json (unchanged historical audit)"}
    outputs = {"source-ast.json": source_ast, "source-api.json": api, "source-methods.json": {"sourceFiles": [Path(f["path"]).name for f in raw["sourceFiles"]], "count": len(methods), "methods": raw["methods"]}, "source-type-closure.json": type_closure, "source-events.json": event_catalog}
    outputs["source-public-declarations.json"] = {"scope": "All exported SDK package functions and methods on exported receiver types; one logical declaration per receiver/name, build-tagged implementations retained separately. Session dispositions are the source-api catalog, other declarations are domain conveniences or host-only SDK integrations, never additional module RPCs.", "count": len(public_rows), "declarations": public_rows, "buildProfiles": profiles, "unsupportedBuilds": {"voice_without_cgo": "Intentionally unsupported SDK build; voice_nocgo.go is retained in source hashes with no supported build profile."}}
    for catalog in outputs.values():
        catalog["sourceProvenance"] = provenance
    summary = {"upstreamBaseCommit": provenance["sdkCommit"], "sourceRevision": provenance["sourceRevision"], "sourceTypes": len(types), "historicalGeneratedTypes": len(old_generated), "nestedTypes": len(raw["nestedTypes"]), "methods": len(methods), "canonicalOperations": len(canonical), "aliases": categories["convenience_alias"], "events": len(events), "moduleFacingEvents": visible, "apiTypeRoots": len(roots), "apiTypeClosure": len(reachable), "eventTypeClosure": len(event_reachable), "combinedTypeClosure": len(combined), "componentVariants": len(raw["polymorphicExpansion"]["MessageComponent"]), "interactionVariants": len(raw["polymorphicExpansion"]["InteractionData"]), "delta": policy["delta"]}
    summary.update({"sourceProvenance": provenance, "publicSDKDeclarations": len(public_rows), "buildProfileCounts": {name: {key: len(profile[key]) for key in ("sourceFiles", "packageTypes", "publicDeclarations", "sessionMethods")} for name, profile in profiles.items()}})
    summary["moduleOperationsIncludingState"] = api["counts"]["distinctTypedRPCOperationsIncludingStateHelper"]
    require(summary["moduleOperationsIncludingState"] == policy["moduleContract"]["operations"], "Public operation count changed; owner decision required")
    require(visible == policy["moduleContract"]["events"], "Public event count changed; owner decision required")
    outputs["source-refresh-summary.json"] = summary
    # Compute everything, reject omissions, then publish. No input baseline/audit is overwritten.
    for name, value in outputs.items():
        (directory / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
