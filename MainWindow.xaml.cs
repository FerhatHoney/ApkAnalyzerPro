using ApkAnalyzerPro.Models;
using ApkAnalyzerPro.Services;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;

namespace ApkAnalyzerPro
{
    public partial class MainWindow : Window
    {
        private readonly DecompilerService _decompilerService;
        private readonly SmartAnalyzerService _analyzerService;
        private string? _lastTempDir;
        private List<EndpointResult> _currentResults;

        public MainWindow()
        {
            InitializeComponent();

            // JADX yolunu kendi sisteminize göre ayarlayın (Örn: projenin yanındaki klasör)
            // Bu örnekte uygulamanın çalıştığı klasördeki jadx/bin/jadx.bat varsayılmıştır.
            string jadxPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "jadx", "bin", "jadx.bat");

            _decompilerService = new DecompilerService(jadxPath);
            _analyzerService = new SmartAnalyzerService();
            _currentResults = new List<EndpointResult>();
        }

        private void BtnBrowse_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog
            {
                Filter = "APK Dosyaları (*.apk)|*.apk",
                Title = "Analiz edilecek APK'yı seçin"
            };

            if (openFileDialog.ShowDialog() == true)
            {
                TxtApkPath.Text = openFileDialog.FileName;
            }
        }

        private void Window_Drop(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                string[] files = (string[])e.Data.GetData(DataFormats.FileDrop);
                if (files.Length > 0 && Path.GetExtension(files[0]).ToLower() == ".apk")
                {
                    TxtApkPath.Text = files[0];
                }
                else
                {
                    MessageBox.Show("Lütfen geçerli bir .apk dosyası bırakın.", "Hata", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            }
        }

        private async void BtnAnalyze_Click(object sender, RoutedEventArgs e)
        {
            string apkPath = TxtApkPath.Text;
            if (string.IsNullOrWhiteSpace(apkPath) || !File.Exists(apkPath))
            {
                MessageBox.Show("Lütfen geçerli bir APK yolu belirtin.", "Uyarı", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            try
            {
                // UI'ı kilitle
                BtnAnalyze.IsEnabled = false;
                BtnBrowse.IsEnabled = false;
                ProgressBar.IsIndeterminate = true;
                DgResults.ItemsSource = null;

                // Progress update mekanizması
                var progress = new Progress<string>(status => TxtStatus.Text = status);

                // 1. Adım: Decompile İşlemi
                _lastTempDir = await _decompilerService.DecompileApkAsync(apkPath, progress);

                // 2. Adım: Kodları Tarama İşlemi
                _currentResults = await _analyzerService.AnalyzeDirectoryAsync(_lastTempDir, progress);

                // Sonuçları UI'a bağla
                DgResults.ItemsSource = _currentResults;
                TxtStatus.Text = $"Analiz tamamlandı. Bulunan kritik uç nokta sayısı: {_currentResults.Count}";
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Analiz sırasında bir hata oluştu:\n{ex.Message}", "Hata", MessageBoxButton.OK, MessageBoxImage.Error);
                TxtStatus.Text = "Hata oluştu.";
            }
            finally
            {
                // UI kilidini aç
                ProgressBar.IsIndeterminate = false;
                BtnAnalyze.IsEnabled = true;
                BtnBrowse.IsEnabled = true;

                // Temizlik yap (isteğe bağlı olarak uygulama kapanırken de yapılabilir)
                if (!string.IsNullOrEmpty(_lastTempDir))
                {
                    _decompilerService.CleanupTempDirectory(_lastTempDir);
                }
            }
        }

        private async void BtnExport_Click(object sender, RoutedEventArgs e)
        {
            if (_currentResults == null || _currentResults.Count == 0)
            {
                MessageBox.Show("Dışa aktarılacak veri bulunamadı.", "Uyarı", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            SaveFileDialog saveFileDialog = new SaveFileDialog
            {
                Filter = "JSON Dosyası (*.json)|*.json",
                Title = "Sonuçları Kaydet",
                FileName = "ApkAnalysisResults.json"
            };

            if (saveFileDialog.ShowDialog() == true)
            {
                try
                {
                    var options = new JsonSerializerOptions { WriteIndented = true };
                    string jsonString = JsonSerializer.Serialize(_currentResults, options);
                    await File.WriteAllTextAsync(saveFileDialog.FileName, jsonString);
                    MessageBox.Show("Sonuçlar başarıyla kaydedildi.", "Başarılı", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Dosya kaydedilirken hata oluştu: {ex.Message}", "Hata", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }
    }
}