# OpenDLP – Internal Data Loss Prevention Lab

## Giới thiệu

**OpenDLP** là mô hình thực nghiệm phòng chống thất thoát dữ liệu nội bộ (Data Loss Prevention), được xây dựng dựa trên đề tài nghiên cứu khoa học **“Nghiên cứu cơ chế giám sát hành vi chia sẻ tập tin và ứng dụng trong mô hình DLP nội bộ”** của nhóm sinh viên [Học viện Kỹ thuật Mật mã](https://actvn.edu.vn/).

Dự án tập trung nghiên cứu, triển khai và mô phỏng các cơ chế **giám sát, phát hiện và ngăn chặn hành vi rò rỉ dữ liệu nhạy cảm** trong môi trường nội bộ.

## Mục tiêu

- Giám sát hành vi truy cập và chia sẻ tập tin.
- Phát hiện dữ liệu nhạy cảm bằng các quy tắc nhận diện nội dung.
- Ngăn chặn rò rỉ dữ liệu qua USB, Clipboard, Screenshot và Web/Cloud.
- Quản lý cảnh báo tập trung và hỗ trợ phản ứng sự cố.



## Tech Stack Core

<table align="center">
  <tr>
    <td align="center" width="110">
      <img src="./assets/logo/wazuh.svg" height="40" alt="Wazuh"/>
      <br/><b>Wazuh</b>
    </td>
    <td align="center" width="110">
      <img src="./assets/logo/yara.svg" height="40" alt="YARA"/>
      <br/><b>YARA</b>
    </td>
    <td align="center" width="110">
      <img src="./assets/logo/sysmon.png" height="40" alt="Sysmon"/>
      <br/><b>Sysmon</b>
    </td>
    <td align="center" width="110">
      <img src="./assets/logo/squid.png" height="40" alt="Squid Proxy"/>
      <br/><b>Squid Proxy</b>
    </td>
    <td align="center" width="110">
      <img src="./assets/logo/icap.svg" height="40" alt="ICAP"/>
      <br/><b>ICAP</b>
    </td>
    <td align="center" width="110">
      <img src="./assets/logo/telegram.webp" height="40" alt="Telegram"/>
      <br/><b>Telegram</b>
    </td>
  </tr>
</table>



## Nhóm nghiên cứu

**Project Leader:** Bùi Tấn Hiếu

**Thành viên thực hiện:**
- Đỗ Quốc Hưng
- Bùi Tấn Hiếu
- Hồ Ngọc Hoà
- Nguyễn Ngọc Thanh Hà

**Giảng viên hướng dẫn:** ThS. Nguyễn Anh Khôi

---

*Dự án phục vụ mục đích nghiên cứu, học tập và thực nghiệm an toàn thông tin.*