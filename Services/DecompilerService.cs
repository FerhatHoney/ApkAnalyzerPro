using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace ApkAnalyzerPro.Services
{
    public class DecompilerService
    {
        private readonly string _jadxPath;

        public DecompilerService(string jadxPath)
        {
            _jadxPath = jadxPath;
        }

        // APK'yı asenkron olarak decompile eder
        public async Task<string> DecompileApkAsync(string apkPath, IProgress<string> progress)
        {
            if (!File.Exists(apkPath))
                throw new FileNotFoundException("APK dosyası bulunamadı.");

            if (!File.Exists(_jadxPath))
                throw new FileNotFoundException("JADX çalıştırılabilir dosyası bulunamadı. Lütfen yolu kontrol edin.");

            // Geçici bir klasör oluştur
            string tempDir = Path.Combine(Path.GetTempPath(), "ApkAnalyzer_" + Guid.NewGuid().ToString());
            Directory.CreateDirectory(tempDir);

            progress?.Report($"JADX başlatılıyor... Hedef klasör: {tempDir}");

            return await Task.Run(() =>
            {
                var processInfo = new ProcessStartInfo
                {
                    FileName = _jadxPath,
                    // Çalışma dizini sorunu ve boşluk karakteri sorunu çözüldü
                    Arguments = $"--show-bad-code -d \"{tempDir}\" \"{apkPath}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true, // Cmd ekranını gizle
                    WorkingDirectory = Path.GetDirectoryName(_jadxPath)
                };

                using (var process = new Process { StartInfo = processInfo })
                {
                    process.Start();

                    // HATA DEĞİŞKENİ BURADA TANIMLANIYOR
                    string errorMessage = "";

                    // Hata akışını asenkron olarak dinle ve kaydet
                    process.ErrorDataReceived += (sender, e) =>
                    {
                        if (!string.IsNullOrEmpty(e.Data))
                        {
                            errorMessage += e.Data + Environment.NewLine;
                        }
                    };

                    process.BeginOutputReadLine(); // Normal çıktıları oku (kilitlenmeyi önler)
                    process.BeginErrorReadLine();  // Hata çıktılarını oku

                    process.WaitForExit();

                    // Hedef klasörde en az 1 tane decompile edilmiş dosya var mı kontrol et
                    bool hasOutputFiles = Directory.Exists(tempDir) && Directory.EnumerateFiles(tempDir, "*.*", SearchOption.AllDirectories).Any();

                    if (process.ExitCode != 0)
                    {
                        if (hasOutputFiles)
                        {
                            // JADX bazı dosyaları okuyamadı (obfuscation vs. nedeniyle) ama büyük kısmını çıkardı. Analize devam ediyoruz!
                            progress?.Report($"Decompile bitti (Bazı dosyalar atlandı). API taramasına geçiliyor...");
                            System.Diagnostics.Debug.WriteLine($"JADX Kısmi Başarı: Çıkış Kodu {process.ExitCode}. Log: {errorMessage}");
                        }
                        else
                        {
                            // Klasör bomboş, işlem gerçekten başarısız oldu
                            if (string.IsNullOrWhiteSpace(errorMessage))
                                errorMessage = "JADX bilinmeyen bir nedenle çöktü ve hiçbir dosya çıkaramadı (Örn: Yetersiz RAM).";

                            throw new Exception($"JADX Çıkış Kodu: {process.ExitCode}\n\nJADX Hata Çıktısı:\n{errorMessage}");
                        }
                    }
                    else
                    {
                        progress?.Report("Decompile işlemi tamamen kayıpsız başarıyla tamamlandı.");
                    }
                }

                return tempDir;
            });
        }

        // Çöp toplama (Garbage Collection / Cleanup)
        public void CleanupTempDirectory(string directoryPath)
        {
            try
            {
                if (Directory.Exists(directoryPath))
                {
                    Directory.Delete(directoryPath, true);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Geçici klasör silinemedi: {ex.Message}");
            }
        }
    }
}