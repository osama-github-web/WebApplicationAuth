using System.ComponentModel.DataAnnotations;

namespace WebApplication3.Models
{
    public class LoginModel
    {
        [Required(ErrorMessage = "Enter UserName")]
        public string? UserName { get; set; }

        [Required(ErrorMessage = "Enter Password")]
        public string? Password { get; set; }
    }
}
