
$LogFile = "C:\Users\Public\yara_debug.log"
$CacheFile = "C:\Users\Public\.usb_override_cache.json"

function Write-Log {
  param([string]$Msg)
  try {
    Add-Content $LogFile $Msg -ErrorAction Stop
  } catch {}
}

try {
  $alert = ([Console]::In.ReadLine() | ConvertFrom-Json)
  $FilePath = $alert.parameters.alert.data.win.eventdata.targetFilename

  if (-not $FilePath) {
    $FilePath = $alert.data.win.eventdata.targetFilename
  }

  if (-not $FilePath) { exit }
} catch { exit }

$YaraExe = "C:\Program Files (x86)\ossec-agent\dependencies\yara\yara64.exe"
$RuleFile = "C:\Program Files (x86)\ossec-agent\shared\sensitive_data.yar"
$LabUsbDrive = 'E:'

$rootPath = [IO.Path]::GetPathRoot($FilePath)

if ($rootPath -ne "$LabUsbDrive\" -or -not (Test-Path -LiteralPath $FilePath -PathType Leaf)) {
  exit
}

$drive = New-Object System.IO.DriveInfo($rootPath)

if ($drive.DriveType -ne [IO.DriveType]::Removable) {
  Write-Log "ERROR: Target is not a removable lab drive: $rootPath"
  exit
}

if (-not (Test-Path -LiteralPath $YaraExe) -or -not (Test-Path -LiteralPath $RuleFile)) {
  Write-Log 'ERROR: Missing YARA dependency.'
  exit
}

$IsOverride = $false

try {
  $now = (Get-Date).Ticks
  $cache = @{}

  if (Test-Path $CacheFile) {
    $raw = Get-Content $CacheFile -Raw | ConvertFrom-Json

    foreach ($p in $raw.psobject.properties) {
      $cache[$p.Name] = $p.Value
    }
  }

  foreach ($key in @($cache.Keys)) {
    if (($now - $cache[$key].LastTick) -gt 1200000000) {
      $cache.Remove($key)
    }
  }

  if ($cache.ContainsKey($FilePath)) {
    $cache[$FilePath].Count += 1
    $cache[$FilePath].LastTick = $now
  } else {
    $cache[$FilePath] = @{ Count = 1; LastTick = $now }
  }

  if ($cache[$FilePath].Count -ge 5) {
    $IsOverride = $true
    $cache.Remove($FilePath)
  }

  $cache | ConvertTo-Json | Set-Content $CacheFile -Force
} catch {}

if (Test-Path -LiteralPath $FilePath) {
  $AlertTriggered = ((& $YaraExe -w $RuleFile $FilePath 2>&1) -match 'Detect_Sensitive_Info')

  if (-not $AlertTriggered -and $FilePath -match '\.(docx|xlsx|pptx)$') {
    $id = [guid]::NewGuid()
    $dir = "$env:TEMP\wazuh_usb_$id"
    $zip = "$dir.zip"

    try {
      New-Item -ItemType Directory $dir -Force | Out-Null
      Copy-Item -LiteralPath $FilePath -Destination $zip -Force
      Expand-Archive $zip $dir -Force

      $AlertTriggered = ((& $YaraExe -w -r $RuleFile $dir 2>&1) -match 'Detect_Sensitive_Info')
    } finally {
      Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
      Remove-Item $zip -Force -ErrorAction SilentlyContinue
    }
  }

  if ($AlertTriggered) {
    if ($IsOverride) {
      Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') wazuh-dlp: alert - Emergency override activated. Target Path: [$FilePath] | App: [USB_Copy]"
    } else {
      Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') wazuh-dlp: alert - SENSITIVE DATA DETECTED ON USB! Target Path: [$FilePath]"

      Remove-Item -LiteralPath $FilePath -Force -ErrorAction SilentlyContinue

      if (-not (Test-Path -LiteralPath $FilePath)) {
        Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') wazuh-dlp: action_success - USB file deleted. Target Path: [$FilePath]"
      } else {
        Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ERROR: Failed to delete USB file: Target Path: [$FilePath]"
      }
    }
  }
}
