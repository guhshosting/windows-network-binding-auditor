param([string]$Executable='build/Release/windows-network-binding-auditor.exe',
      [string]$Python='python',
      [switch]$PackageOnly)
$ErrorActionPreference='Stop'
New-Item -ItemType Directory -Force artifacts | Out-Null
if($PackageOnly) {
 & $Python scripts/check_json.py $Executable
} else {
 & $Python scripts/check_json.py $Executable build/Release/audit_tests.exe
}
if($LASTEXITCODE -ne 0){throw 'Independent JSON/CLI checks failed'}
foreach($file in @('artifacts/live.json','artifacts/fixture.json')){
 if(Test-Path $file){
  if(-not (Get-Content -Raw $file | Test-Json -SchemaFile docs/schema.json)){throw "Schema rejected $file"}
 }
}
$bad=(Get-Content -Raw artifacts/live.json | ConvertFrom-Json)
$bad.application_version='invalid'
$rejected=($bad | ConvertTo-Json -Depth 50 | Test-Json -SchemaFile docs/schema.json -ErrorAction SilentlyContinue)
if($rejected){throw 'Schema failed to reject invalid version'}
$bad=(Get-Content -Raw artifacts/live.json | ConvertFrom-Json)
if($bad.adapters.Count -gt 0) {
 $bad.adapters[0].known_components.ms_tcpip='invalid'
 if($bad | ConvertTo-Json -Depth 50 | Test-Json -SchemaFile docs/schema.json -ErrorAction SilentlyContinue){throw 'Schema accepted invalid state'}
}
& $Executable --summary | Set-Content -Encoding utf8 artifacts/live-summary.txt
if($LASTEXITCODE -notin 0,1){throw 'Live summary failed'}
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' |
 Select-Object ProductName,DisplayVersion,CurrentBuild,UBR | Format-List |
 Out-String | Set-Content -Encoding utf8 artifacts/host.txt
Write-Output 'Offline JSON Schema positive/negative and live local checks passed'
$global:LASTEXITCODE=0