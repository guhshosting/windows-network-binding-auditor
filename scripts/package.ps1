param([string]$Python='python')
$ErrorActionPreference='Stop'
$root=(Get-Location).Path
$version='windows-network-binding-auditor-1.0.0-x64'
$stage=Join-Path $root ('dist/stage-'+[Guid]::NewGuid().ToString('N'))
$extract=Join-Path $root ('dist/smoke-'+[Guid]::NewGuid().ToString('N'))
$zip=Join-Path $root ('dist/'+$version+'.zip')
New-Item -ItemType Directory -Force $stage,$extract | Out-Null
Copy-Item -LiteralPath build/Release/windows-network-binding-auditor.exe,README.md,LICENSE -Destination $stage
Copy-Item -LiteralPath docs -Destination $stage -Recurse
$exeHash=(Get-FileHash -Algorithm SHA256 (Join-Path $stage 'windows-network-binding-auditor.exe')).Hash.ToLowerInvariant()
[IO.File]::WriteAllText((Join-Path $stage 'SHA256SUMS.txt'),$exeHash+'  windows-network-binding-auditor.exe'+[Environment]::NewLine)
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip -Force
Expand-Archive -LiteralPath $zip -DestinationPath $extract
$executable=Join-Path $extract 'windows-network-binding-auditor.exe'
if((Get-FileHash -Algorithm SHA256 $executable).Hash.ToLowerInvariant() -ne $exeHash){throw 'Extracted binary hash mismatch'}
& $Python scripts/check_json.py $executable
if($LASTEXITCODE){throw 'Extracted executable CLI/JSON smoke tests failed'}
if(-not (Get-Content -Raw artifacts/live.json | Test-Json -SchemaFile (Join-Path $extract 'docs/schema.json'))){throw 'Packaged schema rejected extracted live JSON'}
foreach($f in @('README.md','LICENSE','docs/schema.json','docs/SAFETY.md','docs/JSON.md','docs/VALIDATION.md')){
 if(-not (Test-Path -LiteralPath (Join-Path $extract $f))){throw "Missing package file $f"}
}
$hash=(Get-FileHash -Algorithm SHA256 $zip).Hash.ToLowerInvariant()
[IO.File]::WriteAllText(($zip+'.sha256'),$hash+'  '+$version+'.zip'+[Environment]::NewLine)
"Package extracted successfully; CLI, JSON, schema, manifest hashes and required documents pass."
"ZIP: $zip"
"SHA-256: $hash"
"Executable SHA-256: $exeHash"
$global:LASTEXITCODE=0