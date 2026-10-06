# JSON contract 1.0.0

> Release preparation update (2026-10-05): see [current executable qualification and package provenance](../RELEASE-QUALIFICATION.md). Historical validation and pending-test statements in this document describe the original development snapshot. The final ZIP is assembled after qualification and has not been run on Windows.


UTF-8 JSON, fixed object field order, no timestamps, environment variables, or random identifiers. Same acquired model produces byte-identical JSON. Live snapshots can differ when Windows configuration changes. Adapters sort by canonical GUID, index, name; paths sort by state and ordered (component ID, name) sequences; errors sort lexicographically. Interface order within a path is preserved as returned by NetCfg (upper-to-lower). Unknown/custom components are retained.

schema.json uses JSON Schema Draft 2020-12. Validation is offline: neither the schema URL nor any metadata identifier is dereferenced by the program.

Top-level interface and NetCfg completeness flags describe their respective enumeration sources, not adapter binding completeness. Adapter bindings_complete means all binding paths and their component identities were enumerated. A path IsEnabled failure is unknown with a diagnostic; it does not make component membership absent. NetCfg-only adapters have null index and unknown operational/classification metadata, empty description, and a display name in place of an interface alias. Global errors survive adapter filtering.

The known_components object contains:

- enabled: component appears on enabled paths only.
- disabled: component appears on disabled paths only.
- mixed: both enabled and disabled paths contain it.
- absent: no observed path contains it and membership enumeration is complete.
- unavailable: membership enumeration is incomplete or unavailable, even if some paths are present.
- unknown: membership is complete but at least one containing path has unknown state.

Raw paths preserve enabled, disabled, or unknown state, including any observations available in a partial acquisition. Components are IDs and display names, not global enablement values. ms_tcpip is IPv4, ms_tcpip6 IPv6, ms_msclient Microsoft client, ms_server Microsoft server, ms_pacer QoS, and vms_pp Hyper-V extensible switch protocol. Findings are explanatory English strings; automate against states and source flags instead of matching findings text.

Empty name/description means unavailable text. GUID and index identify local interfaces; index null means unavailable. Index values are local and can change. classification is hardware, non_hardware, loopback, tunnel, or unknown. operational_state is up, down, testing, unknown, dormant, not_present, or lower_layer_down.

Exit 1 still produces valid JSON. Invalid arguments and fatal errors are written to stderr without a JSON document. --summary --json and --adapters --json retain the full JSON contract.