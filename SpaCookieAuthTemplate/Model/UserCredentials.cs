using System.ComponentModel.DataAnnotations;

namespace SpaCookieAuthTemplate.Model
{
    public class UserCredentials
    {
        [Required]
        public string Email { get; set; }

        [Required]
        public string Password { get; set; }
    }
}
