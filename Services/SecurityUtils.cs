using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;

namespace ApkAnalyzerPro.Services
{
    public static class SecurityUtils
    {
        // Shannon Entropy Hesaplama (Rastgelelik / Şifre Tespiti)
        public static double CalculateShannonEntropy(string s)
        {
            if (string.IsNullOrEmpty(s)) return 0;
            var map = new Dictionary<char, int>();
            foreach (char c in s)
            {
                if (!map.ContainsKey(c)) map[c] = 0;
                map[c]++;
            }
            double entropy = 0.0;
            int length = s.Length;
            foreach (var kv in map)
            {
                double p = (double)kv.Value / length;
                entropy -= p * Math.Log(p, 2);
            }
            return entropy;
        }

        // Pasif JWT (JSON Web Token) Doğrulayıcı
        public static bool IsValidJwt(string token)
        {
            var parts = token.Split('.');
            if (parts.Length != 3) return false;
            try
            {
                string header = parts[0];
                header = header.PadRight(header.Length + (4 - header.Length % 4) % 4, '=');
                var headerBytes = Convert.FromBase64String(header);
                string headerJson = Encoding.UTF8.GetString(headerBytes);
                // Header geçerli bir JSON mu ve tip JWT mi?
                return headerJson.Contains("\"typ\":\"JWT\"", StringComparison.OrdinalIgnoreCase) ||
                       headerJson.Contains("\"alg\"", StringComparison.OrdinalIgnoreCase);
            }
            catch { return false; }
        }

        // Binary (.so) dosyalardan ASCII/UTF-8 String çıkarma (Gelişmiş Native Analiz)
        public static List<string> ExtractStringsFromBinary(byte[] bytes, int minLength = 6)
        {
            var results = new List<string>();
            var currentString = new StringBuilder();

            for (int i = 0; i < bytes.Length; i++)
            {
                char c = (char)bytes[i];
                // Sadece yazdırılabilir (Printable) karakterleri al
                if (c >= 32 && c <= 126)
                {
                    currentString.Append(c);
                }
                else
                {
                    if (currentString.Length >= minLength)
                        results.Add(currentString.ToString());

                    currentString.Clear();
                }
            }
            if (currentString.Length >= minLength)
                results.Add(currentString.ToString());

            return results;
        }
    }
}