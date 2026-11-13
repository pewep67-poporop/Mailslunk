# =============================================================================
# MailSleuth Python — chạy toàn bộ bộ kiểm thử tự động
#
#   PowerShell:  .\tests\run-all.ps1
#   Linux/macOS: bash tests/run-all.sh
#
# Mỗi bộ test chạy trên một server RIÊNG (DATA_DIR tạm) để:
#   - không đụng dữ liệu thật (data/ của bạn)
#   - reset bộ đếm rate-limit giữa các bộ (login giới hạn 10 lần/phút)
#   - readpst stub trong tests/pstbin chỉ dùng cho máy không có libpst
# =============================================================================
param(
  [int]$Port = 8100,
  [string]$Host_ = "127.0.0.1",
  [switch]$KeepData
)

$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
$tests = $PSScriptRoot
$data = Join-Path $root "data-test"
$stub = Join-Path $tests "pstbin"

$env:PORT = "$Port"
$env:ADMIN_PASS = "TestSmoke-123456"
$env:DATA_DIR = "./data-test"
$env:GEOIP_DIR = "../mailsleuth/geoip"
$env:LIVE_DNS = "0"
$env:PATH = "$stub;$env:PATH"
$env:PYTHONIOENCODING = "utf-8"
$env:SMOKE_BASE = "http://$Host_`:$Port"
$env:DATA_DIR = "./data-test"

$suites = @(
  @{ name = "PST/OST + MBOX";        cmd = "python";   args = @("$tests\smoke-pst.py") },
  @{ name = "Backend regress";       cmd = "node";     args = @("$tests\smoke-regress.mjs") },
  @{ name = "Avatar API";            cmd = "node";     args = @("$tests\smoke-avatar.mjs") },
  @{ name = "Avatar UI (dashboard)"; cmd = "node";     args = @("$tests\smoke-avatar-ui.mjs") },
  @{ name = "UI controls";           cmd = "node";     args = @("$tests\smoke-ui-controls.mjs") },
  @{ name = "Audit toàn diện";       cmd = "python";   args = @("$tests\audit.py") },
  @{ name = "M2 SPF/DKIM/DMARC (unit)"; cmd = "python"; args = @("$tests\auth-live.py") },
  @{ name = "Tầng mới (breaker/ML/LLM)"; cmd = "python"; args = @("$tests\layers-offline.py") },
  @{ name = "Rò rỉ dữ liệu";        cmd = "python";   args = @("$tests\leak-audit.py") },
  @{ name = "Chống crash (chaos)";   cmd = "python";   args = @("$tests\resilience.py") }
)

# ML end-to-end cần scikit-learn (không bắt buộc cho phần còn lại)
$hasSklearn = $false
try { python -c "import sklearn" 2>$null; if ($LASTEXITCODE -eq 0) { $hasSklearn = $true } } catch {}
if ($hasSklearn) {
  $suites += @{ name = "ML end-to-end (train→verify→server)"; cmd = "python"; args = @("$tests\ml-e2e.py") }
} else {
  Write-Host "`n(!) bỏ qua bộ ML end-to-end: chưa cài scikit-learn (pip install scikit-learn onnxruntime)" -ForegroundColor Yellow
}

function Stop-Server {
  $procs = Get-CimInstance Win32_Process -Filter "Name='python.exe'" -ErrorAction SilentlyContinue |
           Where-Object { $_.CommandLine -like "*--port $Port*" }
  foreach ($p in $procs) { taskkill /F /PID $p.ProcessId 2>$null | Out-Null }
  Start-Sleep -Seconds 2
}

function Start-Server {
  Stop-Server
  if (Test-Path $data) { Remove-Item -Recurse -Force $data -ErrorAction SilentlyContinue }
  $log = Join-Path $env:TEMP ("mailsleuth-test-" + [guid]::NewGuid().ToString("N") + ".log")
  # Redirect the output: otherwise the child keeps the parent's stdout pipe open
  # and the runner never returns.
  $p = Start-Process -FilePath "python" -ArgumentList "-m","uvicorn","app.main:app","--host",$Host_,"--port","$Port","--log-level","warning" `
        -WorkingDirectory $root -PassThru -WindowStyle Hidden -RedirectStandardOutput $log -RedirectStandardError "$log.err"
  for ($i = 0; $i -lt 60; $i++) {
    Start-Sleep -Milliseconds 300
    try { $r = Invoke-WebRequest -Uri "$($env:SMOKE_BASE)/api/health" -UseBasicParsing -TimeoutSec 2
          if ($r.StatusCode -eq 200) { return } } catch {}
  }
  Write-Host "  !! server khong len (xem $log)" -ForegroundColor Red
  if (Test-Path "$log.err") { Get-Content "$log.err" -Tail 20 | ForEach-Object { Write-Host "     $_" } }
}

$results = @()
foreach ($s in $suites) {
  Write-Host "`n=== $($s.name) ===" -ForegroundColor Cyan
  Start-Server
  Push-Location $root
  & $s.cmd @($s.args)
  $code = $LASTEXITCODE
  Pop-Location
  $results += [pscustomobject]@{ Suite = $s.name; Code = $code }
}

Stop-Server
if (-not $KeepData -and (Test-Path $data)) { Remove-Item -Recurse -Force $data -ErrorAction SilentlyContinue }

# ---- Extra: M2 end-to-end qua API với LIVE_DNS=1 (cần Internet) ----
Write-Host "`n=== M2 SPF/DKIM/DMARC qua API (LIVE_DNS=1, cần Internet) ===" -ForegroundColor Cyan
$env:LIVE_DNS = "1"
Start-Server
Push-Location $root
& python @("$tests\auth-api-live.py")
$liveCode = $LASTEXITCODE
Pop-Location
Stop-Server
if (-not $KeepData -and (Test-Path $data)) { Remove-Item -Recurse -Force $data -ErrorAction SilentlyContinue }
$env:LIVE_DNS = "0"

Write-Host "`n================= TONG KET =================" -ForegroundColor Cyan
$fail = 0
foreach ($r in $results) {
  $mark = if ($r.Code -eq 0) { "PASS" } else { $fail++; "FAIL" }
  Write-Host ("  {0,-4} {1}" -f $mark, $r.Suite)
}
$mark = if ($liveCode -eq 0) { "PASS" } else { $fail++; "FAIL" }
Write-Host ("  {0,-4} {1}" -f $mark, "M2 live qua API (LIVE_DNS=1)")
Write-Host ("  => {0}/{1} bo test dat" -f ($results.Count + 1 - $fail), ($results.Count + 1)) -ForegroundColor Cyan
exit $(if ($fail) { 1 } else { 0 })
