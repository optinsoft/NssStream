# Builds the native NSS wrapper (proxymap_nss.dll) on Windows.
#
# By default the script expects NSS/NSPR built from source into ..\dist
# (the output of "cd nss; ./build.sh" run next to the nspr checkout):
#
#   <repo>\dist\public\nss            (NSS headers, nss.h, ssl.h, ...)
#   <repo>\dist\<Cfg>\include\nspr    (NSPR headers, nspr.h, prio.h, ...)
#   <repo>\dist\<Cfg>\lib             (nss3.dll.lib, ssl3.dll.lib, ...)
#
# where <Cfg> is "Release" (an --opt build) or "Debug" — the script picks
# Release if it exists, otherwise Debug. Explicit paths always win:
#
#   .\build.ps1 -NssIncludeDir "C:\nss\dist\public\nss" ...
#
# The result is placed into build\<Rid> (proxymap_nss.dll ends up in
# build\<Rid>\Release because of the Visual Studio generator) so that native
# artifacts of different platforms can live side by side in the repository
# without overwriting each other. The default RID is win-x64:
#
#   .\build.ps1 [-Rid win-x64]
#
# At runtime the process must be able to load the NSS/NSPR DLLs
# (nss3.dll, ssl3.dll, smime3.dll, nssutil3.dll, freebl3.dll, softokn3.dll,
# libnspr4.dll, libplc4.dll, libplds4.dll) — place them next to
# proxymap_nss.dll or make them reachable via PATH.

param(
    [string]$Rid = "win-x64",
    [string]$NssIncludeDir = "",
    [string]$NssLibraryDir = "",
    [string]$NsprIncludeDir = "",
    [string]$NsprLibraryDir = ""
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path $PSScriptRoot -Parent
$dist = Join-Path $repoRoot "dist"

function Resolve-FirstExisting([string[]]$candidates, [string]$what)
{
    foreach ($c in $candidates)
    {
        if (Test-Path $c) { return $c }
    }
    return $null
}

if (-not $NssIncludeDir)
{
    $NssIncludeDir = Resolve-FirstExisting @(
        (Join-Path $dist "public\nss"),
        (Join-Path $dist "Release\public\nss"),
        (Join-Path $dist "Debug\public\nss")
    ) | Select-Object -First 1
}

if (-not $NsprIncludeDir)
{
    $NsprIncludeDir = Resolve-FirstExisting @(
        (Join-Path $dist "Release\include\nspr"),
        (Join-Path $dist "Debug\include\nspr")
    ) | Select-Object -First 1
}

if (-not $NssLibraryDir)
{
    $NssLibraryDir = Resolve-FirstExisting @(
        (Join-Path $dist "Release\lib"),
        (Join-Path $dist "Debug\lib")
    ) | Select-Object -First 1
}

if (-not $NsprLibraryDir)
{
    $NsprLibraryDir = $NssLibraryDir
}

foreach ($d in @($NssIncludeDir, $NsprIncludeDir, $NssLibraryDir))
{
    if ($d -and -not (Test-Path $d))
    {
        Write-Warning "Path not found: $d"
    }
}

if ($NssIncludeDir)   { Write-Host "NSS  headers: $NssIncludeDir" }
if ($NsprIncludeDir)  { Write-Host "NSPR headers: $NsprIncludeDir" }
if ($NssLibraryDir)   { Write-Host "Libraries:    $NssLibraryDir" }
Write-Host "RID:          $Rid"
if (-not ($NssIncludeDir -and $NsprIncludeDir -and $NssLibraryDir))
{
    Write-Warning "NSS/NSPR development files were not found in $dist."
    Write-Warning "Build them first (cd nss; ./build.sh) or pass"
    Write-Warning "-NssIncludeDir / -NssLibraryDir / -NsprIncludeDir / -NsprLibraryDir."
}

$cmakeArgs = @()

if ($NssIncludeDir)   { $cmakeArgs += "-DNSS_INCLUDE_DIR=$NssIncludeDir" }
if ($NssLibraryDir)   { $cmakeArgs += "-DNSS_LIBRARY_DIR=$NssLibraryDir" }
if ($NsprIncludeDir)  { $cmakeArgs += "-DNSPR_INCLUDE_DIR=$NsprIncludeDir" }
if ($NsprLibraryDir)  { $cmakeArgs += "-DNSPR_LIBRARY_DIR=$NsprLibraryDir" }

$buildDir = Join-Path "build" $Rid
if (Test-Path $buildDir) { Remove-Item -Recurse -Force $buildDir }

cmake -G "Visual Studio 17 2022" -A x64 -B $buildDir $cmakeArgs
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

cmake --build $buildDir --config Release
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
