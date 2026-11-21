$LogFile = "C:\Users\Public\yara_debug.log"
$BlacklistFile = "C:\Users\Public\blacklist.txt"
$QuarantineDir = "C:\Wazuh_Quarantine"
$YaraExe = "C:\Program Files (x86)\ossec-agent\dependencies\yara\yara64.exe"
$RuleFile = "C:\Program Files (x86)\ossec-agent\shared\sensitive_data.yar"

function Write-Log {
  param([string]$Msg)
  try {
    $fs = New-Object System.IO.FileStream($LogFile, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
    $sw = New-Object System.IO.StreamWriter($fs)
    $sw.WriteLine($Msg)
    $sw.Close()
    $fs.Close()
  } catch {}
}

try {
  $inputJSON = [Console]::In.ReadLine()
  if ([string]::IsNullOrWhiteSpace($inputJSON)) {
    Write-Log "ERROR: Empty stdin."
    exit
  }

  $alert = $inputJSON | ConvertFrom-Json
  if ($alert.command -ne "add") { exit }

  $SearchName = $null

  if ($alert.parameters.alert.data.file_path) {
    $SearchName = $alert.parameters.alert.data.file_path
  }
  elseif ($alert.parameters.extra_args -and $alert.parameters.extra_args.Count -gt 0) {
    $SearchName = [System.Uri]::UnescapeDataString(($alert.parameters.extra_args -join " "))
  }

  if ([string]::IsNullOrWhiteSpace($SearchName)) {
    Write-Log "ERROR: Search name is empty."
    exit
  }

  if ($SearchName -ne [IO.Path]::GetFileName($SearchName) -or $SearchName -in @(".","..")) {
    throw "Use a filename only."
  }

  $QuarantinedFilePath = $null
  $candidates = @()

  if ($SearchName -like "QUARANTINED_*") {
    $candidate = Join-Path $QuarantineDir $SearchName
    if (Test-Path -LiteralPath $candidate -PathType Leaf) {
      $QuarantinedFilePath = $candidate
    }
  }
  else {
    foreach ($metaFile in (Get-ChildItem -Path $QuarantineDir -Filter "*.meta" -ErrorAction SilentlyContinue)) {
      $metaContent = (Get-Content -LiteralPath $metaFile.FullName -Encoding UTF8 -Raw).Trim()

      if ((Split-Path $metaContent -Leaf) -eq $SearchName) {
        $candidates += ($metaFile.FullName -replace "\.meta$", "")
      }
    }
  }

  if ($candidates.Count -gt 1) {
    throw "Ambiguous filename. Use the exact QUARANTINED_ filename."
  }

  if ($candidates.Count -eq 1) {
    $QuarantinedFilePath = $candidates[0]
  }

  if (-not $QuarantinedFilePath -or -not (Test-Path -LiteralPath $QuarantinedFilePath -PathType Leaf)) {
    Write-Log "ERROR: Cannot find quarantine file matching: $SearchName"
    exit
  }

  $MetaFilePath = "$QuarantinedFilePath.meta"

  if (-not (Test-Path -LiteralPath $MetaFilePath)) {
    Write-Log "ERROR: Meta file not found: $MetaFilePath"
    exit
  }

  $OriginalPath = (Get-Content -LiteralPath $MetaFilePath -Encoding UTF8 -Raw).Trim()

  if (-not [IO.Path]::IsPathRooted($OriginalPath)) {
    throw "Invalid original path in metadata."
  }

  if (Test-Path -LiteralPath $OriginalPath) {
    throw "Original path already exists; restore cancelled to avoid overwrite."
  }

  $OriginalDir = Split-Path $OriginalPath -Parent

  if (-not (Test-Path $OriginalDir)) {
    New-Item -ItemType Directory -Force -Path $OriginalDir | Out-Null
  }

  Move-Item -LiteralPath $QuarantinedFilePath -Destination $OriginalPath -ErrorAction Stop
  Remove-Item -LiteralPath $MetaFilePath -Force -ErrorAction SilentlyContinue

  if (-not (Test-Path $YaraExe)) {
    Write-Log "WARNING: YARA exe not found. File restored but blacklist NOT updated."
    exit
  }

  $Result = & $YaraExe -w $RuleFile "$OriginalPath" 2>&1

  if ($LASTEXITCODE -ne 0) {
    throw "File restored, but YARA scan failed; not classified as clean."
  }

  if ($Result -match "Detect_Sensitive_Info") {
    if ((-not (Test-Path $BlacklistFile)) -or ((Get-Content $BlacklistFile) -notcontains $OriginalPath)) {
      Add-Content -Path $BlacklistFile -Value $OriginalPath -Force
    }

    Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') wazuh-yara: restore_blacklisted - Restored and re-added to blacklist: $OriginalPath"
  }
  else {
    Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') wazuh-yara: restore_clean - File restored and CLEAN: $OriginalPath"
  }

} catch {
  Write-Log "ERROR: Restore failed - $_"
}