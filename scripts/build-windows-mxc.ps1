$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$module = Join-Path $root 'src/sandbox/backend/windows/mxc'
$manifestPath = Join-Path $module 'Cargo.toml'
cargo build --release --locked --manifest-path $manifestPath
if ($LASTEXITCODE -ne 0) { throw "MXC build failed with exit code $LASTEXITCODE" }
$binary = Join-Path $module 'pi-sandbox-windows-mxc.exe'
Copy-Item -LiteralPath (Join-Path $module 'target/release/pi-sandbox-windows-mxc.exe') -Destination $binary -Force
$sha256 = [System.Security.Cryptography.SHA256]::Create()
try { $hash = [BitConverter]::ToString($sha256.ComputeHash([System.IO.File]::ReadAllBytes($binary))).Replace('-', '').ToLowerInvariant() }
finally { $sha256.Dispose() }
$runtime = @{
  schemaVersion = 1
  backend = 'windows-mxc'
  version = '1.0.0'
  sdkRevision = 'b21120168d70befe12356411423266bfef168446'
  build = 'cargo build --release --locked'
  sha256 = $hash
}
$runtime | ConvertTo-Json | Set-Content -Encoding ASCII -LiteralPath (Join-Path $module 'mxc-runtime.json')
Write-Output "MXC runtime SHA-256: $hash"
