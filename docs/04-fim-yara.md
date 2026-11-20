# FIM, YARA & Active Response
- Cấu hình FIM để giám sát thay đổi file trên Windows
- Sử dụng YARA để phát hiện dữ liệu nhạy cảm
- Cấu hình Active Response để tự động thực thi script khi phát hiện sự kiện
- Gửi log và cảnh báo về Wazuh Dashboard
---

## Cài đặt YARA
- Các file source nằm trong `source/windows` của repository.
- Chuyển source vào Windows VM (192.168.32.204) tại `C:\DLP-Lab\repo\source\windows`
- Tải **YARA v4.5.5** từ [Github](https://github.com/VirusTotal/yara/releases/tag/v4.5.5).
- Giải nén yara64.exe, yarac64.exe và các DLL đi kèm vào `C:\Program Files (x86)\ossec-agent\dependencies\yara`
- Mở **PowerShell Administrator**, tạo thư mục và copy source vào **Wazuh Agen**:
```powershell
$agentRoot = 'C:\Program Files (x86)\ossec-agent'
$repoRoot = 'C:\DLP-Lab\repo'

Copy-Item "$repoRoot\source\windows\yara\sensitive_data.yar" "$agentRoot\shared"

Copy-Item "$repoRoot\source\windows\active-response\*.ps1" "$agentRoot\shared"

Copy-Item "$repoRoot\source\windows\active-response\*.bat" "$agentRoot\active-response\bin"

Copy-Item "$repoRoot\source\windows\active-response\*.cmd" "$agentRoot\active-response\bin"
```

---
## Cấu hình FIM trên Windows
- Trên **Windows VM (192.168.32.204)**, mở **PowerShell Administrator**
- Sao lưu và mở cấu hình Wazuh Agent:
```powershell
$agentRoot = 'C:\Program Files (x86)\ossec-agent'

Copy-Item "$agentRoot\ossec.conf" "$agentRoot\ossec.conf.before-dlp"

notepad "$agentRoot\ossec.conf"
```

-  file `source/windows/wazuh-agent-ossec.fragment.xml`

- Tìm block `<syscheck>` đã có, bật FIM theo dõi thư mục C:\SecretData:
```notepad
<disabled>no</disabled>
<directories realtime="yes" check_all="yes">C:\SecretData</directories>
<frequency>43200</frequency>
<scan_on_start>yes</scan_on_start>
```

- Ghép các block `<localfile>` từ fragment vào ossec.conf để thu thập:
    - Log YARA: C:\Users\Public\yara_debug.log
    - Log Active Response
    - Sự kiện Sysmon

- Không tạo cấu hình trùng. Giữ nguyên địa chỉ Wazuh Manager 192.168.32.205.

- Lưu file và khởi động lại Wazuh Agent:
```powershell
Restart-Service WazuhSvc

Get-Service WazuhSvc

Get-Content "$agentRoot\ossec.log" -Tail 40
```

---
## Cấu hình Wazuh Manager
- Trên **Ubuntu VM (192.168.32.205)**, chuyển các file `source/wazuh/manager-ossec.fragment.xml` và s`ource/wazuh/local_rules.xml` vào thư mục `~/dlp-source/wazuh/`.




---
## Kiểm tra FIM và YARA