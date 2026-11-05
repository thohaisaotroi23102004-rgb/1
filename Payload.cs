// ============================================================
// FILE: Payload.cs
// Đây là chương trình "nạn nhân" — sẽ được load bởi Loader.cs
// Hoàn toàn vô hại, chỉ in ra màn hình
// ============================================================

using System;

namespace EduPayload
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("[Payload] Xin chào! Tôi đang chạy trong RAM.");
            Console.WriteLine("[Payload] Không có file nào được tạo trên ổ cứng.");

            if (args != null && args.Length > 0)
                Console.WriteLine($"[Payload] Nhận được argument: {args[0]}");
        }
    }
}

// CÁCH COMPILE FILE NÀY:
// C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:Payload.exe Payload.cs
// → ra file Payload.exe (cái này sẽ được Loader đọc vào RAM)
