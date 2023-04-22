using System;

namespace SpaCookieAuthTemplate.Helpers.Settings
{
    public class Authentication
    {
        public const string SectionName = "Authentication";

        public Google Google { get; set; }
    }

    public class Google
    {
        public const string SectionName = "Google";

        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
    }
}

