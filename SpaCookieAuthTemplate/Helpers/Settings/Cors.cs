namespace SpaCookieAuthTemplate.Helpers.Settings
{
    public class Cors
    {
        public const string SectionName = "Cors";

        public string[] Methods { get; set; }
        public string[] Origins { get; set; }
        public string[] Headers { get; set; }
    }
}
