
$LogFile = "C:\Users\Public\yara_debug.log"
$BlacklistFile = "C:\Users\Public\blacklist.txt"

function Write-Log {
    param([string]$Message)
    try {
        Add-Content -Path $LogFile -Value $Message -ErrorAction Stop
    } catch {}
}

function Add-ToBlacklist {
    param([string]$PathToAdd)
    try {
        if ((-not (Test-Path $BlacklistFile)) -or ((Get-Content $BlacklistFile) -notcontains $PathToAdd)) {
            Add-Content -Path $BlacklistFile -Value $PathToAdd -Force
        }
    } catch {}
}

try {
    $inputJSON = [Console]::In.ReadLine()

    if ([string]::IsNullOrWhiteSpace($inputJSON)) { exit }

    $alert = $inputJSON | ConvertFrom-Json

    if ($alert.command -and $alert.command -ne "add") { exit }

    $FilePath = if ($alert.parameters.alert.syscheck.path) {
        $alert.parameters.alert.syscheck.path
    } elseif ($alert.syscheck.path) {
        $alert.syscheck.path
    } else {
        $null
    }

    if ([string]::IsNullOrWhiteSpace($FilePath)) { exit }
} catch { exit }

$SharedDir = "C:\Program Files (x86)\ossec-agent\shared"
$RuleFile = "$SharedDir\sensitive_data.yar"
$InstallDir = "C:\Program Files (x86)\ossec-agent\dependencies\yara"
$YaraExe = "$InstallDir\yara64.exe"
$YaraUrl = "https://github.com/VirusTotal/yara/releases/download/v4.5.5/yara-4.5.5-2368-win64.zip"

if (-not (Test-Path $YaraExe)) {
    try {
        New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

        $downloadId = [guid]::NewGuid().ToString("N")
        $ZipPath = "$env:TEMP\yara_$downloadId.zip"
        $TempYara = "$env:TEMP\yara_$downloadId"

        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        Invoke-WebRequest -Uri $YaraUrl -OutFile $ZipPath
        Expand-Archive -Path $ZipPath -DestinationPath $TempYara -Force

        Copy-Item "$TempYara\yara64.exe" -Destination $YaraExe -Force

        Remove-Item $ZipPath -Force
        Remove-Item $TempYara -Recurse -Force
    } catch { exit }
}

if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) { exit }

$AlertTriggered = $false
$Result = & $YaraExe -w $RuleFile "$FilePath" 2>&1

if ($Result -match "Detect_Sensitive_Info") {
    Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') wazuh-yara: alert - Found Sensitive Data in $FilePath"
    Add-ToBlacklist $FilePath
    $AlertTriggered = $true
}

if (-not $AlertTriggered -and $FilePath -match "\.(docx|xlsx|pptx)$") {
    $id = [guid]::NewGuid().ToString()
    $dir = "$env:TEMP\wazuh_dlp_$id"
    $zip = "$dir.zip"

    try {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Copy-Item -LiteralPath $FilePath -Destination $zip -Force
        Expand-Archive $zip $dir -Force

        if ((& $YaraExe -w -r $RuleFile $dir 2>&1) -match "Detect_Sensitive_Info") {
            Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') wazuh-yara: alert - Found Sensitive Data in $FilePath (Deep Scan Office)"
            Add-ToBlacklist $FilePath
            $AlertTriggered = $true
        }
    } finally {
        Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item $zip -Force -ErrorAction SilentlyContinue
    }
}

if (-not $AlertTriggered -and $FilePath -match "\.pdf$") {
    $PdfToText = "C:\Program Files (x86)\ossec-agent\dependencies\xpdf\pdftotext.exe"

    if (Test-Path $PdfToText) {
        $txt = "$env:TEMP\wazuh_pdf_$([guid]::NewGuid()).txt"

        try {
            & $PdfToText $FilePath $txt | Out-Null

            if ((Test-Path $txt) -and ((& $YaraExe -w $RuleFile $txt 2>&1) -match "Detect_Sensitive_Info")) {
                Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') wazuh-yara: alert - Found Sensitive Data in $FilePath (PDF Scan)"
                Add-ToBlacklist $FilePath
            }
        } finally {
            Remove-Item $txt -Force -ErrorAction SilentlyContinue
        }
    }
}
