# Установка серверного публикатора Reels. Запуск на сервере (PowerShell от администратора):
#   powershell -ExecutionPolicy Bypass -File C:\ig-publisher\install.ps1
# Убрать задачу из планировщика (файлы и ролики остаются):
#   powershell -ExecutionPolicy Bypass -File C:\ig-publisher\install.ps1 -Remove
param(
  [string]$Dir = $PSScriptRoot,
  [switch]$Remove,
  [switch]$SkipCheck
)
$ErrorActionPreference = 'Stop'
$task = 'IgPublisher'

if ($Remove) {
  schtasks /Delete /TN $task /F | Out-Null
  Write-Host 'Задача IgPublisher удалена из планировщика. Файлы и ролики остались на месте.'
  exit 0
}

function Find-Python {
  $cmd = Get-Command python.exe -ErrorAction SilentlyContinue
  if ($cmd -and $cmd.Source -notlike '*WindowsApps*') { return $cmd.Source }
  $launcher = Get-Command py.exe -ErrorAction SilentlyContinue
  if ($launcher) {
    $exe = & $launcher.Source -3 -c "import sys; print(sys.executable)" 2>$null
    if ($exe) { return ([string]$exe).Trim() }
  }
  foreach ($mask in @('C:\Python3*\python.exe', 'C:\Program Files\Python3*\python.exe', "$env:LOCALAPPDATA\Programs\Python\Python3*\python.exe")) {
    $hit = Get-ChildItem $mask -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1
    if ($hit) { return $hit.FullName }
  }
  return $null
}

# 1. Python 3.8+
$py = Find-Python
if (-not $py) { throw 'Не нашёл Python. Установите Python 3.8 или новее (python.org) и запустите установку снова.' }
& $py -c "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)"
if ($LASTEXITCODE -ne 0) { throw "Python по адресу $py старше 3.8. Нужен 3.8 или новее." }
Write-Host "Python: $py"

# 2. config.json: из образца, если ещё нет; с незаполненными токенами не ставим
$script = Join-Path $Dir 'ig_publisher.py'
if (-not (Test-Path $script)) { throw "Не вижу $script. Запускайте install.ps1 из папки, где лежит ig_publisher.py." }
$cfgPath = Join-Path $Dir 'config.json'
if (-not (Test-Path $cfgPath)) {
  Copy-Item (Join-Path $Dir 'config.example.json') $cfgPath
  throw "Создал $cfgPath из образца. Откройте его, вставьте токены Instagram и GitHub вместо слов ВСТАВЬТЕ…, сохраните (UTF-8) и запустите установку снова."
}
$text = [System.IO.File]::ReadAllText($cfgPath, [System.Text.Encoding]::UTF8)
if ($text -match 'ВСТАВЬТЕ') { throw 'В config.json остались слова ВСТАВЬТЕ… — вставьте настоящие токены и запустите установку снова.' }
$cfg = $text | ConvertFrom-Json

# 3. Папки с роликами
foreach ($acc in $cfg.accounts) {
  if ($acc.videos_dir -and -not (Test-Path $acc.videos_dir)) {
    New-Item -ItemType Directory -Path $acc.videos_dir -Force | Out-Null
    Write-Host ("Создал папку для роликов: " + $acc.videos_dir)
  }
}

# 4. Проверка без публикации: адреса, токены, доступ на запись в GitHub, ролик в очереди
if (-not $SkipCheck) {
  & $py $script check
  if ($LASTEXITCODE -ne 0) { throw 'Проверка нашла проблемы (см. выше). Исправьте и запустите установку снова. Если нужно поставить задачу несмотря на это: -SkipCheck' }
}

# 5. Планировщик: раз в минуту, без окна, от имени SYSTEM (работает без входа в систему)
$runCmd = Join-Path $Dir 'run.cmd'
$lines = @('@echo off', "cd /d `"$Dir`"", "`"$py`" ig_publisher.py run >> task.out 2>&1")
Set-Content -Path $runCmd -Value $lines -Encoding ASCII
schtasks /Create /TN $task /SC MINUTE /MO 1 /RU SYSTEM /RL HIGHEST /TR "`"$runCmd`"" /F
if ($LASTEXITCODE -ne 0) { throw 'Планировщик не принял задачу. Запустите PowerShell от имени администратора.' }
schtasks /Run /TN $task | Out-Null
Write-Host ''
Write-Host 'Готово: задача IgPublisher будет запускаться каждую минуту.'
& $py $script status
