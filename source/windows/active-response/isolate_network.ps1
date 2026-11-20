$LogFile = "C:\Users\Public\yara_debug.log"

function Write-Log {
  param([string]$Msg)
  try {
    Add-Content -Path $LogFile -Value $Msg -ErrorAction Stop
  } catch {}
}

try {
  Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') INFO: Initiating NETWORK ISOLATION protocol from Server..."

  Get-NetAdapter | Where-Object {
    $_.Status -eq "Up"
  } | Disable-NetAdapter -Confirm:$false

  Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') wazuh-dlp: action_success - Network isolated successfully."

  $msgText = "[WAZUH DLP] SECURITY BREACH: Phat hien rui ro bao mat nghiem trong! May tinh nay da bi NGAT KET NOI MANG de co lap."

  Start-Process "msg.exe" -ArgumentList "*", "`"$msgText`"" -NoNewWindow

} catch {
  Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ERROR: Network isolation failed - $_"
}