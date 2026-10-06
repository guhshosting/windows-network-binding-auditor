# windows-network-binding-auditor 1.0.0

> Release preparation update (2026-10-05): see [current executable qualification and package provenance](RELEASE-QUALIFICATION.md). Historical validation and pending-test statements in this document describe the original development snapshot. The final ZIP is assembled after qualification and has not been run on Windows.


Windows-only C++17 command-line auditor for locally reported network interface and component binding paths. MIT licensed. No telemetry, intentional network traffic, configuration writes, or connectivity tests.

Run from a console:

    windows-network-binding-auditor
    windows-network-binding-auditor --summary
    windows-network-binding-auditor --adapters
    windows-network-binding-auditor --adapter "Ethernet 2"
    windows-network-binding-auditor --adapter 6 --json
    windows-network-binding-auditor --json
    windows-network-binding-auditor --help
    windows-network-binding-auditor --version

Identifiers are an interface GUID (case-insensitive, optional braces), decimal interface index, or exact case-sensitive Unicode friendly name. Ambiguous names are rejected; use a GUID or index. JSON combines with summary/adapters but always emits full detail for the selected adapters. Output is UTF-8; modern Windows Terminal is recommended.

Exit codes: 0 complete selected-adapter acquisition; 1 partial/unavailable acquisition; 2 invalid option or identifier; 3 fatal failure/output error. Exit 1 is expected when loopback, tunnel, or filter interfaces have no matching NetCfg component. No data is silently treated as an empty successful acquisition. Help/version do not acquire network configuration.

## Interpretation

GetIfTable2 supplies identity, alias, description, index, operational state, and hardware-interface flag. INetCfg supplies adapter components and paths above each adapter. IPv4 (ms_tcpip), IPv6 (ms_tcpip6), Microsoft client (ms_msclient), server (ms_server), QoS (ms_pacer), and Hyper-V switch (vms_pp) states summarize observed paths containing the component. All other exposed components remain in the path list, including filters, bridge, and team components.

A disabled path does not prove its upper component is globally disabled. On Windows 10 and later, disabling a lower binding can make a longer path report disabled. Mixed states are preserved. Absent means absent from the complete enumeration of paths above that adapter, not uninstalled from the machine. No state proves connectivity or a fault.

Hardware/non_hardware classifications describe the Windows hardware-interface flag. A virtual machine's emulated NIC may report hardware. Non_hardware does not prove Hyper-V, bridge, or team membership. Specific component identifiers provide limited role evidence; the tool does not reconstruct switch/team membership or third-party driver internals.

## Build and validation

Requires an x64 MSVC C++ toolchain, Windows SDK, and CMake 3.24+. No downloaded dependencies are required; the C++ runtime is statically linked.

    cmake -S . -B build -A x64
    cmake --build build --config Release
    ctest --test-dir build -C Release --output-on-failure

/W4 /WX, C++17, /permissive-, /sdl, and Control Flow Guard are enforced. scripts/analyze.cmd, tidy.cmd, cppcheck.cmd and imports.cmd provide reproducible local checks; tool locations/generator names in these scripts match the qualification host and can be adapted to another installed toolchain. scripts/validate.ps1 performs live local acquisition and independent JSON validation. scripts/package.ps1 stages and smoke-tests the extracted distribution.

Target API baseline: Windows 10/11 and currently supported Windows Server editions. The completed qualification is Server 2025 x64; Windows 10/11 and other supported Server releases require separate qualification. Consult docs/VALIDATION.md for exact evidence and remaining work.

See docs/JSON.md, docs/schema.json, and docs/SAFETY.md. The application creates no report files itself: redirect stdout explicitly when desired. Reports contain local adapter names/GUIDs and should be handled as local system inventory.