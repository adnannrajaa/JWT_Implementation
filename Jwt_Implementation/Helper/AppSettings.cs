namespace Jwt_Implementation.Helper
{
    public class AppSettings
    {
        public string Secret { get; set; }
        public string JwtExpireMinutes { get; set; }
        public string JwtIssuer { get; set; }
        public string JwtAudience { get; set; }
    }
}
