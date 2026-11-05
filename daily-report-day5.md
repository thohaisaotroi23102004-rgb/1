# Báo Cáo Ngày 5

**Ngày:** 05/11/2026

---

- Đọc bài EDR Internals Research & Bypass của DBGMAN
- Học các loại hook EDR dùng: inline hook, IAT hook
- Tìm hiểu kỹ thuật NTDLL unhooking và lý do nó đã bị detect
- Học Direct Syscall vs Indirect Syscall và các họ SSN resolution (Hell's Gate, Halo's Gate...)
- Tìm hiểu AMSI bypass patchless qua VEH + hardware breakpoint
- Hiểu tại sao patch ETW user-mode không hiệu quả với ETW-TI
- Nắm được các counter-detection hiện đại EDR đang dùng

**Code:**
- Viết EduLoader V2 bằng C# dựa trên kiến trúc từ bài DBGMAN
- Tích hợp: hook detection, VEH concept, XOR encrypt, Assembly.Load fileless
- File: `EduLoader.cs` — loader giáo dục, payload vô hại
