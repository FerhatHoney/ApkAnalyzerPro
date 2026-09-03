using ApkAnalyzerPro.Models;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace ApkAnalyzerPro.Services
{
    public class SmartAnalyzerService
    {
        // =================================================================================
        // BOYUT 1-4: EXTRACTORS (Çıkarıcılar ve Tanımlayıcılar)
        // =================================================================================

        private readonly Regex _xmlResourceExtractor = new Regex(@"<string\s+name=""([^""]+)""[^>]*>([^<]+)<\/string>", RegexOptions.Compiled);
        private readonly Regex _variableExtractor = new Regex(@"(?:const\s+val|public\s+static\s+final\s+String|val|var|String)\s+([a-zA-Z0-9_]+)\s*=\s*[""']([^""']+)[""']", RegexOptions.Compiled);
        private readonly Regex _stringConcatExtractor = new Regex(@"(?:[""'][^""']*[""']\s*\+\s*)+[""'][^""']*[""']", RegexOptions.Compiled);
        private readonly Regex _intentFilterExtractor = new Regex(@"android:scheme=""([^""]+)""(?:\s+android:host=""([^""]+)"")?(?:\s+android:pathPrefix=""([^""]+)"")?", RegexOptions.Compiled);
        private readonly Regex _uriBuilderExtractor = new Regex(@"(?:Uri\.parse|Builder\(\)|HttpUrl)\s*((?:\.(?:scheme|authority|host|appendPath|appendQueryParameter)\([""'][^""']+[""']\))+)", RegexOptions.Compiled);

        private readonly Dictionary<string, Regex> _endpointPatterns = new Dictionary<string, Regex>
        {
            { "Full URL", new Regex(@"(?:https?:\/\/|www\.)[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:\/[a-zA-Z0-9\-\._~:\/?#\[\]@!$&'\(\)\*\+,;=%]*)?", RegexOptions.Compiled | RegexOptions.IgnoreCase) },
            { "Retrofit/Route", new Regex(@"@(?:GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\(\s*(?:[""']([^""'\s]+)[""']|([a-zA-Z0-9_\.]+))\s*\)", RegexOptions.Compiled) }, // Boşluksuz Path regex'i güncellendi
            { "GraphQL Query", new Regex(@"(?:query|mutation)\s+[a-zA-Z0-9_]+\s*\{[^}]+\}", RegexOptions.Compiled | RegexOptions.IgnoreCase) },
            { "Dynamic Path", new Regex(@"(?<=[""'])\/?(?:api|v[1-9]|rest|graphql|auth|users|login|config|sync|checkout|pay)(?:\/[a-zA-Z0-9\-_]+)+(?=[""'])", RegexOptions.Compiled | RegexOptions.IgnoreCase) },
            { "Obfuscated Payload", new Regex(@"(?:aHR0cHM6Ly|aHR0cDovLy)[a-zA-Z0-9\+\/\=]+|(?:\\x[0-9a-fA-F]{2}){5,}|(?:\\u00[0-9a-fA-F]{2}){5,}", RegexOptions.Compiled) }
        };

        private readonly Dictionary<string, Regex> _secretPatterns = new Dictionary<string, Regex>
        {
            { "Slack Token", new Regex(@"(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})", RegexOptions.Compiled) },
            { "RSA Private Key", new Regex(@"-----BEGIN RSA PRIVATE KEY-----", RegexOptions.Compiled) },
            { "Stripe Key", new Regex(@"(?:sk_live|rk_live)_[0-9a-zA-Z]{24}", RegexOptions.Compiled) },
            { "Twilio API Key", new Regex(@"SK[0-9a-fA-F]{32}", RegexOptions.Compiled) },
            { "GitHub PAT", new Regex(@"ghp_[0-9a-zA-Z]{36}", RegexOptions.Compiled) },
            { "Google API Key", new Regex(@"AIza[0-9A-Za-z\-_]{35}", RegexOptions.Compiled) },
            { "AWS Access Key", new Regex(@"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}", RegexOptions.Compiled) }
        };

        // =================================================================================
        // BOYUT 5-8: KATMANLI FİLTRELER (Gürültü, Çöp ve ProGuard Temizleyiciler)
        // =================================================================================

        private readonly HashSet<string> _aggressiveNoiseFilter = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "googleapis.com", "firebase.com", "firebaseio.com", "crashlytics.com", "app-measurement.com",
            "facebook.com", "instagram.com", "admob", "applovin.com", "unity3d.com", "appsflyer.com",
            "w3.org", "android.com", "schemas.android.com", "github.com", "apache.org", "w3c.org", "fabric.io",
            "example.com", "test.com" // Pentest sırasında istenmeyen varsayılan değerler
        };

        private readonly string[] _targetExtensions = { ".java", ".xml", ".json", ".kt", ".js", ".html", ".svg", ".properties", ".gradle", ".yml", ".smali", ".so" };

        // =================================================================================
        // BOYUT 9-10: ULTIMATE ENGINE (Ana Tarama ve Kurşun Geçirmez Doğrulama)
        // =================================================================================

        public async Task<List<EndpointResult>> AnalyzeDirectoryAsync(string directoryPath, IProgress<string> progress)
        {
            progress?.Report("Boyut 10: Kurşun Geçirmez (Zero-Garbage) SAST Motoru Başlatılıyor...");

            var results = new ConcurrentBag<EndpointResult>();
            var files = Directory.EnumerateFiles(directoryPath, "*.*", SearchOption.AllDirectories)
                                 .Where(f => _targetExtensions.Contains(Path.GetExtension(f).ToLower()))
                                 .ToList();

            var symbolTable = new ConcurrentDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var globalBaseUrls = new ConcurrentBag<string>();

            // --- AŞAMA 1: SÖZLÜK VE GLOBAL URL DERLEMESİ ---
            await Task.Run(() =>
            {
                Parallel.ForEach(files, new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount }, file =>
                {
                    try
                    {
                        if (file.EndsWith(".so")) return;
                        string content = File.ReadAllText(file);

                        if (file.EndsWith(".xml"))
                        {
                            foreach (Match m in _xmlResourceExtractor.Matches(content))
                            {
                                symbolTable[$"R.string.{m.Groups[1].Value}"] = m.Groups[2].Value;
                                if (IsValidHttpUrl(m.Groups[2].Value)) globalBaseUrls.Add(m.Groups[2].Value);
                            }
                        }

                        if (file.EndsWith(".java") || file.EndsWith(".kt") || file.EndsWith(".js"))
                        {
                            foreach (Match m in _variableExtractor.Matches(content))
                            {
                                symbolTable[m.Groups[1].Value] = m.Groups[2].Value;
                                if (IsValidHttpUrl(m.Groups[2].Value)) globalBaseUrls.Add(m.Groups[2].Value);
                            }
                        }
                    }
                    catch { }
                });
            });

            var validBaseUrls = globalBaseUrls.Where(u => !IsNoise(u)).Distinct().ToList();

            // --- AŞAMA 2: DERİNLEMESİNE TARAMA VE ÇÖP (GARBAGE) TEMİZLİĞİ ---
            await Task.Run(() =>
            {
                Parallel.ForEach(files, new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount }, file =>
                {
                    try
                    {
                        string content = "";
                        string fileName = Path.GetFileName(file);
                        bool isNativeBinary = fileName.EndsWith(".so");
                        bool isNetworkContext = false;

                        if (isNativeBinary)
                        {
                            byte[] fileBytes = File.ReadAllBytes(file);
                            content = string.Join("\n", ExtractCleanStringsFromBinary(fileBytes)); // Sadece temiz stringler
                        }
                        else
                        {
                            content = File.ReadAllText(file);
                            isNetworkContext = CheckIfNetworkContext(content);
                            content = ResolveStringConcatenations(content);

                            // Manifest Deep Link
                            if (fileName.Equals("AndroidManifest.xml", StringComparison.OrdinalIgnoreCase))
                            {
                                foreach (Match m in _intentFilterExtractor.Matches(content))
                                {
                                    string scheme = m.Groups[1].Value;
                                    string host = m.Groups[2].Value;
                                    string path = m.Groups[3].Success ? m.Groups[3].Value : "";

                                    if (!string.IsNullOrEmpty(scheme) && !string.IsNullOrEmpty(host))
                                    {
                                        string deepLink = $"{scheme}://{host}{path}";
                                        if (IsValidUri(deepLink))
                                            results.Add(new EndpointResult(deepLink, m.Value, fileName, 100, "Manifest Deep Link"));
                                    }
                                }
                            }
                        }

                        // Uri.Builder Çözümleme
                        foreach (Match m in _uriBuilderExtractor.Matches(content))
                        {
                            string reconstructedUrl = ReconstructUriBuilder(m.Groups[1].Value);
                            if (IsValidHttpUrl(reconstructedUrl) && !IsNoise(reconstructedUrl))
                                results.Add(new EndpointResult(reconstructedUrl, m.Value, fileName, 95, "Uri Builder Assembly"));
                        }

                        // Cloud Secrets (Bunlar ayrı tutulur, URL ile birleştirilmez!)
                        foreach (var secretPattern in _secretPatterns)
                        {
                            foreach (Match match in secretPattern.Value.Matches(content))
                            {
                                results.Add(new EndpointResult(match.Value, match.Value, fileName, 100, $"Exposed {secretPattern.Key}"));
                            }
                        }

                        // Entropy Secrets (JWT ve benzerleri)
                        var words = content.Split(new[] { ' ', '\n', '\r', '\t', '"', '\'', '=', ';', '(', ')' }, StringSplitOptions.RemoveEmptyEntries);
                        foreach (var word in words)
                        {
                            if (word.Length > 20 && word.Length < 250 && IsValidStringFormat(word))
                            {
                                double entropy = CalculateShannonEntropy(word);
                                if (entropy > 4.6 && !IsNoise(word))
                                {
                                    if (IsValidJwt(word))
                                        results.Add(new EndpointResult(word, word, fileName, 100, "Verified JWT Token"));
                                    // Rastgele sayı ve harflerin URL olarak eklenmesini engelledik. Saf secret olarak kalır.
                                }
                            }
                        }

                        // AST TABANLI URL VE ENDPOINT BİRLEŞTİRME
                        foreach (var pattern in _endpointPatterns)
                        {
                            foreach (Match match in pattern.Value.Matches(content))
                            {
                                string originalFragment = match.Value;
                                string extractedString = originalFragment;
                                string type = pattern.Key;

                                if (type == "Retrofit/Route")
                                {
                                    if (!string.IsNullOrEmpty(match.Groups[1].Value))
                                        extractedString = match.Groups[1].Value;
                                    else if (!string.IsNullOrEmpty(match.Groups[2].Value))
                                    {
                                        string varName = match.Groups[2].Value.Split('.').Last();
                                        if (symbolTable.TryGetValue(varName, out string resolvedValue))
                                        {
                                            extractedString = resolvedValue;
                                            type = "AST Resolved Variable";
                                        }
                                        else extractedString = varName;
                                    }
                                }

                                extractedString = CleanExtractedString(extractedString);

                                if (type == "Obfuscated Payload")
                                {
                                    string decoded = AdvancedDeobfuscator(extractedString);
                                    if (!string.IsNullOrEmpty(decoded))
                                    {
                                        extractedString = decoded;
                                        type = "De-obfuscated Payload";
                                    }
                                }

                                // Gürültü ve ProGuard (a/b/c) Filtresi
                                if (IsNoise(extractedString) || IsProGuardArtifact(extractedString)) continue;

                                // === BOYUT 10: ZERO-GARBAGE BİRLEŞTİRİCİ ===
                                string finalAssembledUrl = extractedString;

                                // Sadece gerçekten bir path formatında olanları (başında / olan veya kelime ile başlayıp url standartlarına uyanları) birleştir.
                                if ((type.Contains("Route") || type == "Dynamic Path" || type == "AST Resolved Variable") && !extractedString.StartsWith("http") && IsValidRoutePath(extractedString))
                                {
                                    if (validBaseUrls.Any())
                                    {
                                        string baseUrl = validBaseUrls.First().TrimEnd('/');
                                        string path = extractedString.TrimStart('/');
                                        finalAssembledUrl = $"{baseUrl}/{path}";
                                        type = isNativeBinary ? "Native AST Route" : "Deep Assembled (AST)";
                                    }
                                    else
                                    {
                                        finalAssembledUrl = "[UNRESOLVED_BASE]/" + extractedString.TrimStart('/');
                                    }
                                }

                                // SON KONTROL (Validasyon): Sadece geçerli, Fuzz-Ready linkleri ve Route'ları al!
                                if (IsValidOutput(finalAssembledUrl, type))
                                {
                                    int score = CalculateConfidenceScore(finalAssembledUrl, fileName, isNetworkContext, type);
                                    if (score >= 45)
                                        results.Add(new EndpointResult(finalAssembledUrl, originalFragment, fileName, score, type));
                                }
                            }
                        }
                    }
                    catch { }
                });
            });

            // Temizlik ve Tekilleştirme
            return results
                .Where(r => !string.IsNullOrWhiteSpace(r.UrlOrPath))
                .GroupBy(r => r.UrlOrPath)
                .Select(g => g.OrderByDescending(r => r.ConfidenceScore).First())
                .OrderByDescending(r => r.ConfidenceScore)
                .ToList();
        }

        // =================================================================================
        // BOYUT 10 ÖZEL METOTLARI: KURŞUN GEÇİRMEZ TEMİZLİK VE DOĞRULAMA (SANITIZERS)
        // =================================================================================

        private string CleanExtractedString(string raw)
        {
            // Tırnakları, boşlukları ve gereksiz kaçış karakterlerini yok eder
            return raw.TrimEnd('/', '\\', '.', ',', '"', '\'', ';').TrimStart('"', '\'').Trim();
        }

        private bool IsValidHttpUrl(string url)
        {
            // C# Core motoru ile %100 URL doğrulaması (Çöpleri engeller)
            return Uri.TryCreate(url, UriKind.Absolute, out Uri uriResult) &&
                   (uriResult.Scheme == Uri.UriSchemeHttp || uriResult.Scheme == Uri.UriSchemeHttps);
        }

        private bool IsValidUri(string uri)
        {
            return Uri.TryCreate(uri, UriKind.Absolute, out _);
        }

        private bool IsValidRoutePath(string path)
        {
            // YALNIZCA geçerli URL yolları (A-Z, rakam, slash, tire, alt çizgi vb.)
            // Rastgele şifreli metinlerin (örn: a5b6c7d8e9) veya karmaşık sayıların base URL'e eklenmesini engeller.
            return Regex.IsMatch(path, @"^[\/a-zA-Z0-9_\-\.\?\&\=]+$") && !path.Contains("\n") && !path.Contains(" ");
        }

        private bool IsValidStringFormat(string str)
        {
            // Binary çöpleri engellemek için stringin içindeki karakterlerin yazdırılabilir ASCII olup olmadığını denetler
            return Regex.IsMatch(str, @"^[a-zA-Z0-9\-_+=]+$");
        }

        private bool IsProGuardArtifact(string path)
        {
            // ProGuard / R8 tarafından şifrelenmiş anlamsız class harflerini (a/b/c veya x.y.z) yoksay
            return Regex.IsMatch(path, @"^(\/[a-z]{1,2})+$") || Regex.IsMatch(path, @"^([a-z]{1,2}\.){2,}[a-z]{1,2}$");
        }

        private bool IsValidOutput(string finalUrl, string type)
        {
            // Sırları (Secrets) ve Query'leri URL gibi doğrulamaya zorlama, onlar her türlü geçerlidir.
            if (type.Contains("Secret") || type.Contains("GraphQL") || finalUrl.StartsWith("[UNRESOLVED_BASE]")) return true;

            // Eğer URL birleştirilmişse veya Http içeriyorsa, bunun GEÇERLİ BİR WEB LİNKİ olması ZORUNLUDUR!
            if (finalUrl.StartsWith("http", StringComparison.OrdinalIgnoreCase))
            {
                return IsValidHttpUrl(finalUrl);
            }

            return IsValidRoutePath(finalUrl);
        }

        // =================================================================================
        // YARDIMCI GÜVENLİK, DEOBFUSCATOR VE ENTROPY METOTLARI
        // =================================================================================

        private string ResolveStringConcatenations(string content)
        {
            return _stringConcatExtractor.Replace(content, match => match.Value.Replace("\"", "").Replace("'", "").Replace("+", "").Replace(" ", ""));
        }

        private string ReconstructUriBuilder(string builderChain)
        {
            string scheme = "https";
            string host = "";
            var paths = new List<string>();

            var matches = Regex.Matches(builderChain, @"\.(scheme|authority|host|appendPath)\([""']([^""']+)[""']\)");
            foreach (Match m in matches)
            {
                string method = m.Groups[1].Value;
                string val = m.Groups[2].Value;

                if (method == "scheme") scheme = val;
                else if (method == "authority" || method == "host") host = val;
                else if (method == "appendPath") paths.Add(val);
            }

            if (!string.IsNullOrEmpty(host))
                return $"{scheme}://{host}/{string.Join("/", paths)}".TrimEnd('/');

            return string.Empty;
        }

        private string AdvancedDeobfuscator(string data)
        {
            try
            {
                data = Regex.Replace(data, @"\\u([0-9A-Fa-f]{4})", m => ((char)Convert.ToInt32(m.Groups[1].Value, 16)).ToString());
                data = Uri.UnescapeDataString(data);

                if (data.Contains("\\x"))
                {
                    data = data.Replace("\\x", "");
                    byte[] bytes = new byte[data.Length / 2];
                    for (int i = 0; i < bytes.Length; i++) bytes[i] = Convert.ToByte(data.Substring(i * 2, 2), 16);
                    string decodedHex = Encoding.UTF8.GetString(bytes);
                    if (decodedHex.StartsWith("http")) return decodedHex;
                }

                string paddedData = data.PadRight(data.Length + (4 - data.Length % 4) % 4, '=');
                var base64Bytes = Convert.FromBase64String(paddedData);
                string decodedBase64 = Encoding.UTF8.GetString(base64Bytes);
                if (decodedBase64.StartsWith("http")) return decodedBase64;

                return string.Empty;
            }
            catch { return string.Empty; }
        }

        private bool CheckIfNetworkContext(string content)
        {
            string[] kw = { "Retrofit", "OkHttp", "HttpURLConnection", "Volley", "HttpClient", "ktor", "WebSocket", "GraphQL", "Request.Builder" };
            return kw.Any(k => content.Contains(k, StringComparison.OrdinalIgnoreCase));
        }

        private bool IsNoise(string input)
        {
            string lowerInput = input.ToLower();
            if (_aggressiveNoiseFilter.Any(noise => lowerInput.Contains(noise))) return true;
            if (lowerInput.StartsWith("java/") || lowerInput.StartsWith("android/") || lowerInput.StartsWith("kotlin/") || lowerInput.StartsWith("androidx/")) return true;

            string[] mediaExtensions = { ".png", ".jpg", ".jpeg", ".gif", ".css", ".ttf", ".woff", ".mp3", ".mp4", ".ico", ".webp", ".so" };
            return mediaExtensions.Any(ext => lowerInput.EndsWith(ext));
        }

        private int CalculateConfidenceScore(string endpoint, string fileName, bool isNetworkContext, string type)
        {
            int score = 20;
            string lowerEndpoint = endpoint.ToLower();

            if (type.Contains("Manifest Deep Link") || type.Contains("Exposed") || type.Contains("Verified JWT")) return 100;
            if (type.Contains("Assembled") || type == "AST Resolved Variable") return 100;
            if (type == "De-obfuscated Payload" || type == "Uri Builder Assembly") return 95;
            if (type == "Retrofit/Route" || type == "GraphQL Query") return 90;

            string[] attackSurface = { "api", "v1", "v2", "graphql", "admin", "login", "auth", "register", "upload", "token", "password", "user", "payment", "checkout" };
            foreach (var kw in attackSurface) if (lowerEndpoint.Contains(kw)) score += 25;

            if (isNetworkContext) score += 35;
            if (fileName.Contains("Constants") || fileName.Contains("Endpoints") || fileName.Contains("Api") || fileName.Contains("Config")) score += 30;
            if (fileName.EndsWith(".so")) score += 20;

            return Math.Clamp(score, 0, 100);
        }

        private double CalculateShannonEntropy(string s)
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

        private bool IsValidJwt(string token)
        {
            var parts = token.Split('.');
            if (parts.Length != 3) return false;
            try
            {
                string header = parts[0];
                header = header.PadRight(header.Length + (4 - header.Length % 4) % 4, '=');
                var headerBytes = Convert.FromBase64String(header);
                string headerJson = Encoding.UTF8.GetString(headerBytes);
                return headerJson.Contains("\"typ\":\"JWT\"", StringComparison.OrdinalIgnoreCase) ||
                       headerJson.Contains("\"alg\"", StringComparison.OrdinalIgnoreCase);
            }
            catch { return false; }
        }

        private List<string> ExtractCleanStringsFromBinary(byte[] bytes, int minLength = 6)
        {
            var results = new List<string>();
            var currentString = new StringBuilder();

            for (int i = 0; i < bytes.Length; i++)
            {
                char c = (char)bytes[i];
                // Sadece harf, rakam ve standart url/özel karakterleri al (Native çöpleri engeller)
                if (c >= 32 && c <= 126 && c != '\\' && c != '\"')
                    currentString.Append(c);
                else
                {
                    if (currentString.Length >= minLength && IsValidStringFormat(currentString.ToString()))
                        results.Add(currentString.ToString());
                    currentString.Clear();
                }
            }
            if (currentString.Length >= minLength && IsValidStringFormat(currentString.ToString()))
                results.Add(currentString.ToString());
            return results;
        }
    }
}