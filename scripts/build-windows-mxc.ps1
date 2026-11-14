$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$module = Join-Path $root 'src/sandbox/backend/windows/mxc'
$manifestPath = Join-Path $module 'Cargo.toml'
$arch = if ($env:PI_SANDBOX_RUNTIME_ARCH) { $env:PI_SANDBOX_RUNTIME_ARCH } else {
  switch ($env:PROCESSOR_ARCHITECTURE) {
    'AMD64' { 'x64' }
    'ARM64' { 'arm64' }
    default { throw "Unsupported Windows architecture: $env:PROCESSOR_ARCHITECTURE" }
  }
}
$target = switch ($arch) {
  'x64' { 'x86_64-pc-windows-msvc' }
  'arm64' { 'aarch64-pc-windows-msvc' }
  default { throw "Unsupported Windows runtime architecture: $arch" }
}
cargo build --release --locked --manifest-path $manifestPath --target $target
if ($LASTEXITCODE -ne 0) { throw "MXC build failed with exit code $LASTEXITCODE" }
$binary = Join-Path $module 'pi-sandbox-windows-mxc.exe'
Copy-Item -LiteralPath (Join-Path $module "target/$target/release/pi-sandbox-windows-mxc.exe") -Destination $binary -Force
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
$package = Get-Content -Raw -LiteralPath (Join-Path $root 'package.json') | ConvertFrom-Json
$runtimeVersion = if ($env:PI_SANDBOX_RUNTIME_VERSION) { $env:PI_SANDBOX_RUNTIME_VERSION } else { $package.version }
$minPluginVersion = if ($env:PI_SANDBOX_MIN_PLUGIN_VERSION) { $env:PI_SANDBOX_MIN_PLUGIN_VERSION } else { $package.version }
$major = [int]($package.version.Split('.')[0])
$maxPluginVersion = if ($env:PI_SANDBOX_MAX_PLUGIN_VERSION) { $env:PI_SANDBOX_MAX_PLUGIN_VERSION } else { "$($major + 1).0.0" }
& node (Join-Path $PSScriptRoot 'write-runtime-manifest.mjs') $module 'win32' $arch $runtimeVersion $minPluginVersion $maxPluginVersion
if ($LASTEXITCODE -ne 0) { throw "Runtime manifest generation failed with exit code $LASTEXITCODE" }
Write-Output "MXC runtime SHA-256: $hash"
