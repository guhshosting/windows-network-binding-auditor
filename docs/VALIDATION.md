# Validation record: version 1.0.0 x64

> Release preparation update (2026-10-05): see [current executable qualification and package provenance](../RELEASE-QUALIFICATION.md). Historical validation and pending-test statements in this document describe the original development snapshot. The final ZIP is assembled after qualification and has not been run on Windows.


Qualification host: Windows Server 2025 Standard Evaluation, 24H2, build 26100.32230. Validation date: 2026-10-03. Compiler: MSVC 19.51.36260.0; SDK 10.0.26100.0; CMake 4.4.3; clang-tidy 23.1.2; Cppcheck 2.22.0; PowerShell 7.6.6. No dependencies were downloaded and no socket-based tests were performed.

## Completed application checks

- x64 MSVC Release C++17 build: /W4 /WX /permissive- /utf-8 /sdl /guard:cf, static C++ runtime. No warnings or errors.
- CTest: 3/3 passed (fixtures, version, help). Fixture executable: 80 assertions.
- Separate MSVC Release /analyze build: no diagnostics.
- clang-tidy: clang-analyzer-*, bugprone-*, performance-* with warnings treated as errors. No project diagnostics. Its final log reports 722 suppressed diagnostics in external SDK/STL headers; these are not presented as project findings.
- Cppcheck warning/style/performance/portability checks: clean.
- Independent Python standard-library JSON parsing, duplicate-key detection, UTF-8 decoding, Unicode fixture checks, all six states, stable fixture output, CLI error channels, selector behavior, and independent component aggregation checks: passed.
- Offline PowerShell Test-Json against Draft 2020-12 schema: live and fixture documents passed; invalid version and component-state documents rejected.
- Application source prohibited-call scan plus manual review of all acquisition calls: passed. No intentional communication or configuration mutation APIs.
- PE imports: only IPHLPAPI.DLL, ole32.dll and KERNEL32.dll. IP Helper imports are GetIfTable2 and FreeMibTable. No Winsock, DNS resolver, ICMP, HTTP or network mutation imports.
- PE headers: x64, ASLR, high-entropy address space, NX and Control Flow Guard confirmed.
- CRT imports include CreateFileW, WriteFile, LoadLibraryExW, GetProcAddress, and process-local runtime helpers. These support the static runtime/console and do not establish application configuration writes. Application source contains no file creation, dynamic loading or resolver calls.

## Live observations

GetIfTable2 enumerated nine interfaces. INetCfg adapter enumeration completed, and two adapters had complete binding data, each with 27 paths and 19 distinct component IDs. Seven loopback, tunnel or filter interfaces had no matching NetCfg adapter component; they correctly report unavailable binding information.

The active Ethernet adapter exposed enabled IPv4, IPv6, client, server, QoS and documented filter paths, plus disabled Hyper-V switch and multiplexor paths. The not-present kernel debugger adapter still exposed configured paths. No component's disabled state was called a fault and no connectivity conclusion was made.

A separately acquired local Get-NetAdapterBinding -AllBindings reference agreed with all 19 component states for the active adapter. This read-only cmdlet was used for independent validation only; it is not called by, linked into, or required by the application.

Whole-system audit returned exit 1 for unavailable pseudo-interface bindings. GUID, index, exact-name selection, help/version, summary/adapters/full output, JSON, and invalid identifiers/options were exercised.

A validation-only existing restricted-token launcher ran the application at medium integrity with Administrators disabled: valid schema output, nine interfaces, NetCfg complete, two adapters with complete bindings, exit 1. This demonstrates restricted-token operation on this host, not complete standard-user qualification on other Windows editions. The launcher is external to this project and is not distributed.

## Fixtures and abstraction

The platform-neutral model/reporting boundary accepts snapshots without invoking Windows acquisition. Fixtures cover Ethernet/Wi-Fi, disconnected/not-up adapters, virtualization protocol evidence, IPv4-only and IPv6-only style path states, disabled client/server components, custom filters, bridge observations, absent and unavailable data, mixed and unknown paths, duplicate names, Unicode names, all JSON control-byte escapes, deterministic ordering, NetCfg-only partial acquisition and invalid/ambiguous identifiers.

Fixture tests do not configure adapters, modify bindings or create sockets. Live acquisition uses existing machine configuration and performs no negative network probes.

## Packaging gate and evidence

scripts/package.ps1 stages the Release executable, README, MIT LICENSE, JSON contract/schema, safety and validation documentation, plus an executable SHA-256 manifest. It creates the versioned x64 ZIP, extracts it to a fresh directory, verifies the executable hash, runs the extracted executable through the independent CLI/JSON/semantic checker, validates output with the extracted schema and checks required documents. A failure stops packaging. The ZIP SHA-256 sidecar is written after these checks pass.

Raw evidence is retained in the development workspace's artifacts directory:
release-build.txt, ctest.txt, msvc-analyze.txt, clang-tidy.txt, cppcheck.txt, binary-inspection.txt, safety-audit.txt, json-validation.txt, live.json, fixture.json, live-summary.txt, host.txt, binding-reference.json, binding-comparison.txt, restricted-token.txt, restricted-live.json and package-validation.txt. Machine inventory is not included in the distribution ZIP.

## Remaining qualification and limitations

Windows 11 and Windows 10 x64 require live qualification, including Ethernet/Wi-Fi, disconnected interfaces, Unicode/duplicate friendly names and standard-user acquisition. Other supported Windows Server releases also require qualification. API compatibility is the intended Windows 10+ baseline; only Server 2025 was executed here.

Enabled/disabled are path observations, not assertions of connectivity or globally enabled components. Absent is relative to complete paths above the selected adapter. Lightweight filters and vendor internals may not all be represented by the same NetCfg path interface. Virtual machine hardware flags cannot reliably identify a physical host device. Hyper-V/bridge/team identifiers provide component evidence, not topology or membership.

Acquisition is not atomic across APIs and can race independent configuration changes. OS DLL/provider internals and unrelated OS activity are beyond a direct import/source audit; the application itself makes only documented local queries and no intentional network traffic. The ZIP contains an unsigned executable; hashes record artifact integrity.