# build_all.ps1 - Automated build & test across MSVC, GCC, and Clang
$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " AES Suite - Cross-Compiler Build & Test Verification " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $RepoRoot

$compilers = @(
    @{ Name = "MSVC";  Preset = "msvc-release";  BuildDir = "Build_msvc";  Config = "Release" },
    @{ Name = "GCC";   Preset = "gcc-release";   BuildDir = "Build_gcc";   Config = "" },
    @{ Name = "Clang"; Preset = "clang-release"; BuildDir = "Build_clang"; Config = "" }
)

$results = @()

foreach ($comp in $compilers) {
    Write-Host "`n----------------------------------------------------------" -ForegroundColor Yellow
    Write-Host " Configuring and Building with $($comp.Name)..." -ForegroundColor Yellow
    Write-Host "----------------------------------------------------------" -ForegroundColor Yellow

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        # 1. Configure
        & cmake --preset $($comp.Preset)
        if ($LASTEXITCODE -ne 0) { throw "CMake configure failed for $($comp.Name)" }

        # 2. Build
        & cmake --build --preset $($comp.Preset)
        if ($LASTEXITCODE -ne 0) { throw "CMake build failed for $($comp.Name)" }

        # 3. Test
        Push-Location $comp.BuildDir
        if ($comp.Config -ne "") {
            & ctest -C $comp.Config --output-on-failure
        } else {
            & ctest --output-on-failure
        }
        $testExit = $LASTEXITCODE
        Pop-Location

        if ($testExit -ne 0) { throw "CTest failed for $($comp.Name)" }

        $sw.Stop()
        $results += [PSCustomObject]@{
            Compiler = $comp.Name
            Status   = "PASS"
            TimeSec  = [math]::Round($sw.Elapsed.TotalSeconds, 2)
        }
    } catch {
        $sw.Stop()
        $results += [PSCustomObject]@{
            Compiler = $comp.Name
            Status   = "FAIL: $_"
            TimeSec  = [math]::Round($sw.Elapsed.TotalSeconds, 2)
        }
        Write-Host "Error with $($comp.Name): $_" -ForegroundColor Red
        break
    }
}

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host " SUMMARY OF BUILD & TEST RESULTS" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
$results | Format-Table -AutoSize

$allPass = ($results | Where-Object { $_.Status -ne "PASS" }).Count -eq 0 -and $results.Count -eq 3
if ($allPass) {
    Write-Host "`nALL 3 COMPILERS PASSED 100%!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`nBUILD / TEST FAILED!" -ForegroundColor Red
    exit 1
}

