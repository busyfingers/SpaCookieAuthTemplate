namespace SpaCookieAuthTemplate.Helpers
{
    public class Cors
    {
        public const string SectionName = "cors";

        public string[] Methods { get; set; }
        public string[] Origins { get; set; }
        public string[] Headers { get; set; }
    }
}

