$LogFile = "C:\Users\Public\yara_debug.log"

function Write-Log {
  param([string]$Msg)
  Add-Content -Path $LogFile -Value $Msg -ErrorAction SilentlyContinue
}

Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') INFO: Initiating Session 0 Bypass Lockdown..."

try {
  $qwinstaPath = "$env:windir\System32\qwinsta.exe"

  if (Test-Path "$env:windir\sysnative\qwinsta.exe") {
    $qwinstaPath = "$env:windir\sysnative\qwinsta.exe"
  }

  $sessions = & $qwinstaPath 2>&1
  Write-Log "Sessions found: $($sessions -join ' | ')"

  foreach ($line in $sessions) {
    if ($line -match "Active") {
      $sessionId = ""

      foreach ($part in (-split $line)) {
        if ($part -match "^\d+$") {
          $sessionId = $part
          break
        }
      }

      if ($sessionId -ne "") {
        Write-Log "Found Active Target -> Disconnecting Session ID: $sessionId"

        $tsdisconPath = "$env:windir\System32\tsdiscon.exe"

        if (Test-Path "$env:windir\sysnative\tsdiscon.exe") {
          $tsdisconPath = "$env:windir\sysnative\tsdiscon.exe"
        }

        Start-Process -FilePath $tsdisconPath -ArgumentList $sessionId -Wait -NoNewWindow
      }
    }
  }

  Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') wazuh-dlp: action_success - Target neutralized."
} catch {
  Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ERROR: $_"
}
