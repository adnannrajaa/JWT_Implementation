using System.ComponentModel.DataAnnotations;
using Newtonsoft.Json;

namespace Jwt_Implementation.Models
{
    // DTO Clasess 
    public class Login
    {
        [Required]
        public string UserName { get; set; }
        [Required]
        public string Password { get; set; }
        [Required]
        public string Device { get; set; }
        [Required]
        public string IpAddress { get; set; }
    }

    public class LoginResponse
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Token { get; set; }

        [JsonIgnore] // refresh token is returned in http only cookie
        public string RefreshToken { get; set; }

        public LoginResponse(User user, string token, string refreshToken)
        {
            FirstName = user.FirstName;
            LastName = user.LastName;
            Token = token;
            RefreshToken = refreshToken;
        }
    }

    public class SignUp
    {

        [Required]
        public string UserName { get; set; }
        [Required]
        public string Password { get; set; }
        [Required]
        public string FirstName { get; set; }
        [Required]
        public string LastName { get; set; }
        [Required]
        public string Device { get; set; }
        [Required]
        public string IpAddress { get; set; }
    }
    public class RevokeTokenRequest
    {
        public string Token { get; set; }
    }
}
