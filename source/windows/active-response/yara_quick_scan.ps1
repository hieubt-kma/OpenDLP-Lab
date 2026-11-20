
$LogFile = "C:\Users\Public\yara_debug.log"
$BlacklistFile = "C:\Users\Public\blacklist.txt"

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

function Add-ToBlacklist {
    param([string]$PathToAdd)
    try {
        $Exists = $false

        if (Test-Path $BlacklistFile) {
            $content = Get-Content $BlacklistFile
            if ($content -contains $PathToAdd) {
                $Exists = $true
            }
        }

        if (-not $Exists) {
            Add-Content -Path $BlacklistFile -Value $PathToAdd -Force
            Write-Log "DEBUG: Auto-added to Blacklist -> $PathToAdd"
        }
    } catch {}
}

$YaraExe = "C:\Program Files (x86)\ossec-agent\dependencies\yara\yara64.exe"
$RuleFile = "C:\Program Files (x86)\ossec-agent\shared\sensitive_data.yar"

$TargetFolders = @('C:\SecretData')

$Users = Get-ChildItem -Path "C:\Users" -Directory | Where-Object {
    $_.Name -notin @("Public", "Default", "Default User", "All Users")
}

foreach ($user in $Users) {
    $TargetFolders += "$($user.FullName)\Desktop"
    $TargetFolders += "$($user.FullName)\Documents"
}

Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') INFO: Starting QUICK SCAN..."

foreach ($Folder in $TargetFolders) {
    if (Test-Path $Folder) {

        $Result = & $YaraExe -w -r $RuleFile "$Folder" 2>&1

        foreach ($line in $Result) {
            if ($line -match "Detect_Sensitive_Info") {
                $FilePath = ($line -split '\s+', 2)[1]
                Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') wazuh-yara: alert - Found Sensitive Data in $FilePath"
                Add-ToBlacklist -PathToAdd $FilePath
            }
        }

        $OfficeFiles = Get-ChildItem -Path $Folder -Include *.docx, *.xlsx, *.pptx -Recurse -File -ErrorAction SilentlyContinue

        foreach ($doc in $OfficeFiles) {
            $TempGuid = [guid]::NewGuid().ToString()
            $TempExtractPath = "$env:TEMP\wazuh_dlp_$TempGuid"
            $TempZipPath = "$env:TEMP\wazuh_dlp_$TempGuid.zip"

            try {
                New-Item -ItemType Directory -Path $TempExtractPath -Force | Out-Null
                Copy-Item -LiteralPath $doc.FullName -Destination $TempZipPath -Force
                Expand-Archive -Path $TempZipPath -DestinationPath $TempExtractPath -Force -ErrorAction Stop

                $DeepResult = & $YaraExe -w -r $RuleFile "$TempExtractPath" 2>&1

                foreach ($dLine in $DeepResult) {
                    if ($dLine -match "Detect_Sensitive_Info") {
                        Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') wazuh-yara: alert - Found Sensitive Data in $($doc.FullName) (Deep Scan Office)"
                        Add-ToBlacklist -PathToAdd $doc.FullName
                        break
                    }
                }
            } catch {
            } finally {
                if (Test-Path $TempExtractPath) {
                    Remove-Item -Path $TempExtractPath -Recurse -Force -ErrorAction SilentlyContinue
                }
                if (Test-Path $TempZipPath) {
                    Remove-Item -Path $TempZipPath -Force -ErrorAction SilentlyContinue
                }
            }
        }

        $PdfToText = "C:\Program Files (x86)\ossec-agent\dependencies\xpdf\pdftotext.exe"
        $PdfFiles = Get-ChildItem -Path $Folder -Include *.pdf -Recurse -File -ErrorAction SilentlyContinue

        foreach ($pdf in $PdfFiles) {
            if (-not (Test-Path $PdfToText)) {
                Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') WARNING: xpdf not found. Skipping PDF: $($pdf.FullName)"
                break
            }

            $TempPdfTxt = "$env:TEMP\wazuh_pdf_$([guid]::NewGuid().ToString()).txt"

            try {
                & $PdfToText "$($pdf.FullName)" "$TempPdfTxt" 2>&1 | Out-Null

                if (Test-Path $TempPdfTxt) {
                    $PdfResult = & $YaraExe -w $RuleFile "$TempPdfTxt" 2>&1

                    foreach ($pLine in $PdfResult) {
                        if ($pLine -match "Detect_Sensitive_Info") {
                            Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') wazuh-yara: alert - Found Sensitive Data in $($pdf.FullName) (PDF Scan)"
                            Add-ToBlacklist -PathToAdd $pdf.FullName
                            break
                        }
                    }
                }
            } catch {
                Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ERROR PDF SCAN: $($pdf.FullName) - $_"
            } finally {
                if (Test-Path $TempPdfTxt) {
                    Remove-Item -Path $TempPdfTxt -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }
}

Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') INFO: QUICK SCAN completed."
