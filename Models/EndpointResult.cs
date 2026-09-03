namespace ApkAnalyzerPro.Models
{
    public class EndpointResult
    {
        // Kullanıcıya arayüzde gösterilecek olan ana sütun (Birleştirilmiş Nihai Hali)
        public string UrlOrPath { get; set; }
        public string OriginalFragment { get; set; } // Kodun içindeki asıl hali (Örn: @GET("/users"))
        public string FilePath { get; set; }
        public int ConfidenceScore { get; set; }
        public string Type { get; set; }

        public EndpointResult(string urlOrPath, string originalFragment, string filePath, int confidenceScore, string type)
        {
            UrlOrPath = urlOrPath;
            OriginalFragment = originalFragment;
            FilePath = filePath;
            ConfidenceScore = confidenceScore;
            Type = type;
        }
    }
}