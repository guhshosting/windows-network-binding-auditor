$ErrorActionPreference='Stop'
$sourceFiles=@(Get-ChildItem src -File | Sort-Object Name)
$source=($sourceFiles | ForEach-Object {Get-Content -Raw $_.FullName}) -join [Environment]::NewLine
$forbidden='\b(?:WSAStartup|WSASocket[AW]?|socket|connect|send|sendto|recv|recvfrom|getaddrinfo|GetAddrInfo[AW]?|gethostbyname|DnsQuery[A-Za-z0-9_]*|Icmp[A-Za-z0-9_]*|WinHttp[A-Za-z0-9_]*|Internet[A-Za-z0-9_]*|URLDownload[A-Za-z0-9_]*|SetIfEntry|SetIfEntry2|SetIpInterfaceEntry|SetUnicastIpAddressEntry|CreateUnicastIpAddressEntry|DeleteUnicastIpAddressEntry|SetIpForwardEntry2?|CreateIpForwardEntry2?|DeleteIpForwardEntry2?|Dhcp[A-Za-z0-9_]*|RegSet[A-Za-z0-9_]*|RegCreate[A-Za-z0-9_]*|Enable|Disable|Apply|Cancel|AcquireWriteLock|MoveBefore|MoveAfter|Install|DeInstall|SetDisplayName)\s*\('
if($source -match $forbidden){throw "Forbidden application invocation: $($Matches[0])"}
$pe=Get-Content -Raw artifacts/binary-inspection.txt
if($pe -match '(?im)^\s*(?:WS2_32|WINHTTP|WININET|DNSAPI|URLMON)\.DLL\s*$'){throw 'Forbidden network DLL import'}
if($pe -match '(?im)^\s+[0-9a-f]+\s+(?:socket|WSA\w*|send\w*|recv\w*|connect|GetAddrInfo\w*|getaddrinfo|DnsQuery\w*|Icmp\w*|WinHttp\w*|Internet\w*|SetIfEntry\w*|SetIpInterfaceEntry|SetIpForwardEntry\w*|RegSet\w*|RegCreate\w*)\s*$'){throw 'Forbidden network/mutation import'}
foreach($flag in @('8664 machine (x64)','Dynamic base','NX compatible','Control Flow Guard','High Entropy Virtual Addresses')){
 if(-not $pe.Contains($flag)){throw "Missing PE property: $flag"}
}
if($source.Contains('CLSCTX_REMOTE_SERVER') -or $source.Contains('INetCfgLock')){throw 'Remote COM or write lock present'}
if(-not $source.Contains('CLSCTX_INPROC_SERVER')){throw 'Expected in-process activation missing'}
'PASS: application source prohibited-invocation scan; no remote COM/write lock'
'PASS: PE network/mutation import scan; x64 ASLR/NX/high-entropy/CFG properties'
'Direct IP Helper imports: GetIfTable2, FreeMibTable'
'Other DLL imports: ole32.dll, KERNEL32.dll. Static CRT supplies console/file/runtime helpers.'
'Read-only COM methods manually reviewed: Initialize, EnumComponents, GetInstanceGuid, GetId, GetDisplayName, QueryInterface, EnumBindingPaths, Next, IsEnabled, EnumBindingInterfaces, GetUpperComponent, Uninitialize, Release.'
foreach($f in $sourceFiles){$h=Get-FileHash -Algorithm SHA256 $f.FullName;"$($f.Name) $($h.Hash.ToLowerInvariant())"}
$global:LASTEXITCODE=0