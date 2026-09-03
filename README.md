# 🕵️‍♂️ APK Analyzer Pro - Advanced Security Recon Tool

![Version](https://img.shields.io/badge/version-v1.0.0-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20.NET%208.0-lightgrey.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

**APK Analyzer Pro**, siber güvenlik analistleri, sızma testi uzmanları (Penetration Testers) ve Bug Bounty avcıları için özel olarak tasarlanmış, Android uygulamaları (.apk) üzerinde derinlemesine statik analiz (SAST) yapan **kurumsal düzeyde** bir keşif (Reconnaissance) aracıdır.

Standart Regex scriptlerinin çok ötesine geçen bu araç; **10-Boyutlu AST-Lite Mimarisi**, Entropy (Rastgelelik) analizi ve Zero-Garbage (Sıfır Çöp) politikasıyla çalışır. Uygulama içindeki şifrelenmiş kodları çözer, Native (`.so`) kütüphaneleri tarar ve saldırı yüzeyini doğrudan tespit eder.

---

## 🚀 Temel Yetenekler (Core Capabilities)

### 1. Akıllı Uç Nokta Birleştirici (AST-Lite Data Flow)
Ayrı dosyalarda tutulan `BASE_URL` değişkenleri ile `@GET("/api/v1/login")` veya `Endpoints.USER_LOGIN` gibi bağıl rotaları (relative paths) tespit eder, hafızasında eşleştirir ve sızma testine hazır tam URL olarak size sunar.

### 2. Shannon Entropy & Secret Hunter
Sadece URL'leri değil; AWS Access Key, Google API Key, Stripe Token, JWT ve yüksek entropiye (karmaşıklığa) sahip özel kriptografik şifreleri / anahtarları tespit ederek sızıntıları (Secrets Exposure) bulur.

### 3. Multi-Layer Deobfuscation (Şifre Çözücü)
Uygulama geliştiricilerin statik analizi atlatmak için kullandığı yöntemleri etkisiz hale getirir:
*   String Parçalamaları (`"ht" + "tps://"`)
*   Hexadecimal Gizleme (`\x68\x74\x74...`)
*   Unicode ve URL Encoding (`\u002F`)
*   Base64 Payload'lar

### 4. Native (.so) ve Deep Link Analizi
*   **Native Kütüphaneler:** JADX'in çözemediği C/C++ derlenmiş `.so` dosyalarındaki (NDK) gömülü (hardcoded) anahtarları ASCII seviyesinde çeker.
*   **Saldırı Yüzeyi Genişletme:** `AndroidManifest.xml` içerisindeki Deep Link ve Intent yapılarını (`android:scheme`) parse ederek dışarıdan tetiklenebilen zafiyet noktalarını listeler.

### 5. Zero-Garbage Policy (Katı Filtreleme)
Google Ads, Firebase, Crashlytics veya ProGuard/R8 tarafından üretilen anlamsız sınıf adları (`a.b.c`) gibi gürültüleri (Noise) %100 engeller. Ekranda anlamsız sayılar veya bozuk linkler görmezsiniz.

---

## ⚙️ Mimari: "10-Dimensional Scan Engine"

Araç arka planda şu sofistike adımları izler:
1.  **JADX CLI Entegrasyonu:** Hedef APK arka planda sessizce decompile edilir.
2.  **Symbol Table Generation:** Tüm proje taranır, `R.string.x` kaynakları ve sabit değişkenler bir sözlüğe (AST Map) haritalandırılır.
3.  **Method Chaining Parsing:** `Uri.Builder().scheme("https").host("api.com")` yapıları sanal olarak yeniden inşa edilir.
4.  **Cross-Reference Assembly:** Bulunan değişkenler (Örn: `@POST(LOGIN_URL)`) sembol tablosundan çekilerek asıl değerleriyle birleştirilir.
5.  **Validation (Strict):** Çıkan sonuç Microsoft `Uri` kütüphanesiyle doğrulanır ve sadece geçerli hedefler DataGrid'e yansıtılır.

---

## 🛠️ Kurulum ve Kullanım

### Gereksinimler
*   Windows İşletim Sistemi
*   [.NET 8.0 Desktop Runtime](https://dotnet.microsoft.com/download/dotnet/8.0)
*   [Java 11 veya üzeri](https://adoptium.net/) (JADX için zorunludur)

### Kurulum Adımları
1.  Projeyi klonlayın: `git clone https://github.com/KULLANICI_ADINIZ/ApkAnalyzerPro.git`
2.  [JADX Releases](https://github.com/skylot/jadx/releases) sayfasından en son **jadx-x.x.x.zip** (CLI sürümü) dosyasını indirin.
3.  İndirdiğiniz JADX ZIP dosyasının içindeki her şeyi, projenizdeki `jadx` klasörünün içine çıkartın (`ApkAnalyzerPro/jadx/bin/jadx.bat` yolu oluşmalıdır).
4.  Uygulamayı derleyin ve çalıştırın.

### Kullanım
*   Sürükle-Bırak (Drag & Drop) veya "Gözat" ile APK dosyasını seçin.
*   **"Analiz Et"** butonuna basın.
*   Araç, API'leri, şifreleri, Deep Link'leri tespit edip Skorlarına (Confidence Score) göre listeleyecektir.
*   **"Export JSON"** ile bulguları raporlayın.

---

## ⚠️ Yasal Uyarı (Legal Disclaimer)

Bu araç **yalnızca eğitim, yasal güvenlik araştırmaları (Bug Bounty) ve yetkili sızma testleri (Pentesting)** amacıyla geliştirilmiştir. Analiz edilen uygulamalar üzerinde açık yetkiniz bulunmalıdır. Geliştirici, bu aracın kötüye kullanımından doğabilecek hiçbir yasal sorumluluğu kabul etmez.

---

## 📝 Lisans

Bu proje [MIT Lisansı](LICENSE) altında lisanslanmıştır. Özgürce kullanabilir, geliştirebilir ve kendi Red Team araç setinize entegre edebilirsiniz. Pull Request'ler (PR) her zaman memnuniyetle karşılanır!
