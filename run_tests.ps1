$ErrorActionPreference = "Continue"
Set-Location $PSScriptRoot
$fail = 0
foreach ($t in "test_sources","test_detect","test_respond","test_report","test_luretrace") {
    Write-Host "`n==== $t ====" -ForegroundColor Cyan
    python "tests/$t.py"
    if ($LASTEXITCODE -ne 0) { $fail = 1 }
}
Write-Host "`n==== demo ====" -ForegroundColor Cyan
python demo.py
if ($fail) { Write-Host "TESTS FAILED" -ForegroundColor Red; exit 1 }
Write-Host "ALL TESTS PASSED" -ForegroundColor Green
