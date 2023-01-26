using System.ComponentModel.DataAnnotations;

namespace WebApplication3.Models
{
    public class RegisterModel
    {
        [Required(ErrorMessage = "Enter UserName")]
        public string? UserName { get; set; }

        [Required(ErrorMessage = "Enter Email")]
        public string? Email { get; set; }

        [Required(ErrorMessage = "Enter Password")]
        public string? Password { get; set; }

    }
}
