$LogFile = "C:\Users\Public\yara_debug.log"

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

Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') INFO: QUARANTINE script started."

try {
  $inputJSON = [Console]::In.ReadLine()

  if ([string]::IsNullOrWhiteSpace($inputJSON)) {
    Write-Log "ERROR: STDIN data is empty."
    exit
  }

  $alert = $inputJSON | ConvertFrom-Json

  if ($alert.command -ne "add") { exit }

  $FilePath = $null

  if ($alert.parameters.alert.data.file_path) {
    $FilePath = $alert.parameters.alert.data.file_path
  }
  elseif ($alert.parameters.extra_args -and $alert.parameters.extra_args.Count -gt 0) {
    $FilePath = [System.Uri]::UnescapeDataString($alert.parameters.extra_args[0])
  }
  elseif ($alert.parameters.alert.syscheck.path) {
    $FilePath = $alert.parameters.alert.syscheck.path
  }

  if ([string]::IsNullOrWhiteSpace($FilePath)) {
    Write-Log "ERROR: File path is empty after all extraction attempts."
    exit
  }

  if (Test-Path -LiteralPath $FilePath -PathType Leaf) {
    $FilePath = (Get-Item -LiteralPath $FilePath).FullName
  }

  $QuarantineDir = "C:\Wazuh_Quarantine"

  if (-not (Test-Path $QuarantineDir)) {
    New-Item -ItemType Directory -Force -Path $QuarantineDir | Out-Null
  }

  if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) {
    Write-Log "ERROR: Target file does not exist: $FilePath"
    exit
  }

  $FileName = Split-Path $FilePath -Leaf
  $Timestamp = (Get-Date -Format "yyyyMMdd_HHmmss") + "_" + [guid]::NewGuid().ToString("N")
  $DestPath = "$QuarantineDir\QUARANTINED_${Timestamp}_$FileName"

  $FilePath | Set-Content -LiteralPath "$DestPath.meta" -Encoding UTF8 -ErrorAction Stop

  try {
    Move-Item -LiteralPath $FilePath -Destination $DestPath -ErrorAction Stop
  }
  catch {
    Remove-Item -LiteralPath "$DestPath.meta" -ErrorAction SilentlyContinue
    throw
  }

  if (Test-Path $DestPath) {
    Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') wazuh-yara: quarantine_success - File quarantined: $FilePath -> $DestPath"
  }
  else {
    Write-Log "ERROR: Move-Item failed, file not found in destination."
  }

} catch {
  Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ERROR: Quarantine failed - $_"
}