using System;
using System.ComponentModel.DataAnnotations;
using Newtonsoft.Json;

namespace Jwt_Implementation.Models
{
    //Data Model 
    public class User
    {
        [Key]
        public int Id { get; set; }
        public string UserName { get; set; }
        [JsonIgnore]
        public string Password { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Device { get; set; }
        public string IpAddress { get; set; }
    }

    public class RefreshToken
    {
        [Key]
        public int Id { get; set; }
        public int UserId { get; set; }
        public string Token { get; set; }
        public DateTime Expires { get; set; }
        public bool IsExpired => DateTime.UtcNow >= Expires;
        public DateTime Created { get; set; }
        public string CreatedByIp { get; set; }
        public DateTime? Revoked { get; set; }
        public string RevokedByIp { get; set; }
        public string ReplacedByToken { get; set; }
        public bool IsActive => Revoked == null && !IsExpired;
    }

}
