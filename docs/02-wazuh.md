# Wazuh
- Cài **Wazuh** trên Ubuntu như một giải pháp **SIEM (Security Information and Event Management)**, bao gồm ba thành phần chính: `Wazuh Manager`, `Wazuh Indexer` và `Wazuh Dashboard`.
- Hệ thống được triển khai trên Ubuntu nhằm thu thập, giám sát, phân tích và quản lý các event. 

## Cấu hình 

- Cài công cụ và tải **Wazuh**
```cmd
sudo apt update
sudo apt install -y curl ca-certificates unzip
mkdir -p ~/dlp-install
cd ~/dlp-install
curl -fLO https://packages.wazuh.com/4.3/wazuh-install.sh
```
- Tạo file cấu hình:
```cmd
nano config.yml
```
```cmd
nodes:
  # Wazuh Indexer
  indexer:
    - name: wazuh-indexernodes
      ip: 192.168.32.205

  # Wazuh Manager
  server:
    - name: wazuh-managernodes
      ip: 192.168.32.205

  # Wazuh Dashboard
  dashboard:
    - name: wazuh-dashboard
      ip: 192.168.32.205
```

---
## Cài đặt 
- Tạo file cấu hình và chứng thư
```cmd
sudo bash wazuh-install.sh --generate-config-files
```
- Cài Indexer
```cmd
sudo bash wazuh-install.sh --wazuh-indexer wazuh-indexer
```
- Khởi tạo cluster
```cmd
sudo bash wazuh-install.sh --start-cluster
```
- Cài Manager
```cmd
sudo bash wazuh-install.sh --wazuh-server wazuh-manager
```
- Cài Dashboard
```cmd
sudo bash wazuh-install.sh --wazuh-dashboard wazuh-dashboard
```
![alt text](Images/image-5.png)

---
## Kiểm tra
- Kiểm tra trạng thái các dịch vụ của Wazuh:
```cmd
sudo systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard filebeat
```

![active - manager, indexer, dashboard](Images/image-7.png)

- Kiểm tra kết nối Filebeat đến Wazuh Indexer:
```cmd
sudo filebeat test output
```

Từ máy host (Windows ngoài máy thật), truy cập https://192.168.32.205 và đăng nhập Wazuh Dashboard thành công.

![Wazuh Login](Images/image-6.png)