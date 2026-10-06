# Read-only safety boundary

> Release preparation update (2026-10-05): see [current executable qualification and package provenance](../RELEASE-QUALIFICATION.md). Historical validation and pending-test statements in this document describe the original development snapshot. The final ZIP is assembled after qualification and has not been run on Windows.


Application native calls are limited to GetIfTable2/FreeMibTable; in-process CNetCfg COM initialization; enumerator Next; INetCfg EnumComponents; component GetInstanceGuid/GetId/GetDisplayName and QueryInterface; EnumBindingPaths(EBP_ABOVE); IsEnabled; EnumBindingInterfaces; GetUpperComponent; Uninitialize; Unicode/GUID conversion; and normal memory/console/runtime operations.

No INetCfgLock/write lock, Apply, Cancel, Enable, binding reorder, installation, adapter state change, registry writes, IP/DNS/metric changes, DHCP renewal, cache flush, Winsock reset, firewall/route mutation, or service control is used. No WSAStartup, socket creation, resolver, ICMP, send/receive, WinHTTP/WinINet, URL download, or connectivity test is used. The Winsock headers provide SDK types only; the executable does not link ws2_32.

COM uses CLSCTX_INPROC_SERVER, never remote activation. Read-only Initialize is followed by Uninitialize. HRESULT failures preserve diagnostics; they do not trigger repair or retries that change configuration. No application files are created or changed. stdout/stderr can be redirected by the caller.

Source and PE import inspection support the direct-call safety boundary. Imports cannot prove all behavior inside Windows DLLs, installed providers, or drivers; this application makes no intentional network calls and invokes only local documented queries. Ordinary OS activity can occur independently of the process. No socket-based negative test is used.

Binding acquisition is a local snapshot across two APIs, not an atomic transaction. Concurrent configuration changes can make metadata inconsistent. Third-party components may not expose all internals through NetCfg. Enabled protocol paths do not establish address assignment, routes, DNS health, packet delivery, server reachability, or correct firewall policy.

Documented facilities:
- https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getiftable2
- https://learn.microsoft.com/en-us/previous-versions/windows/hardware/network/ff547718(v=vs.85)
- https://learn.microsoft.com/en-us/previous-versions/windows/hardware/network/ff547705(v=vs.85)
- https://learn.microsoft.com/en-us/previous-versions/windows/hardware/network/ff547699(v=vs.85)
- https://learn.microsoft.com/en-us/previous-versions/windows/hardware/network/ff547698(v=vs.85)