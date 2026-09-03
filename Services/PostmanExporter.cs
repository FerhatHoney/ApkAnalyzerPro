using ApkAnalyzerPro.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

namespace ApkAnalyzerPro.Services
{
    public class PostmanExporter
    {
        public async Task ExportToPostmanCollectionAsync(List<EndpointResult> endpoints, string outputPath)
        {
            // Sadece birleştirilmiş ve tam URL'leri dışa aktar
            var validEndpoints = endpoints.Where(e => e.UrlOrPath.StartsWith("http")).ToList();

            var collection = new
            {
                info = new
                {
                    name = $"APK Recon Target - {DateTime.Now:yyyy-MM-dd}",
                    description = "ApkAnalyzerPro tarafından otomatik üretilmiş saldırı yüzeyi koleksiyonu.",
                    schema = "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
                },
                item = validEndpoints.Select(e => new
                {
                    name = e.Type + " - " + e.UrlOrPath.Split('?')[0],
                    request = new
                    {
                        method = DetermineMethod(e.OriginalFragment),
                        url = new
                        {
                            raw = e.UrlOrPath,
                            host = e.UrlOrPath.Split('/').Take(3).ToList(), // http, "", domain
                            path = e.UrlOrPath.Split('/').Skip(3).ToList()  // Path kısımları
                        }
                    }
                }).ToList()
            };

            var options = new JsonSerializerOptions { WriteIndented = true };
            string json = JsonSerializer.Serialize(collection, options);
            await File.WriteAllTextAsync(outputPath, json);
        }

        private string DetermineMethod(string originalFragment)
        {
            if (string.IsNullOrEmpty(originalFragment)) return "GET";
            if (originalFragment.Contains("@POST")) return "POST";
            if (originalFragment.Contains("@PUT")) return "PUT";
            if (originalFragment.Contains("@DELETE")) return "DELETE";
            return "GET"; // Varsayılan
        }
    }
}