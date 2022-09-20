using Dapper;
using Jwt_Implementation.Helper;
using Jwt_Implementation.Models;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Jwt_Implementation.Services
{
    public interface IUserService : IDisposable
    {
        Task<User> GetUserById(int id);
        Task<bool> SaveUser(SignUp model);
        Task<LoginResponse> Authenticate(Login model);
        Task<LoginResponse> RefreshToken(string token, string ipAddress);
        Task<bool> RevokeToken(string token, string ipAddress);
    }

    public class UserService : IUserService
    {
        private readonly ApplicationDbContext _context;
        private readonly IDapperService _dapperService;
        private readonly AppSettings _appSettings;
        public UserService(ApplicationDbContext context, IDapperService dapperService, IOptions<AppSettings> appSettings)
        {
            _context = context;
            _dapperService = dapperService;
            _appSettings = appSettings.Value;
        }

        public async Task<LoginResponse> Authenticate(Login model)
        {
            try
            {
                string hashPassword = PasswordMd5(model.Password);
                string query = $"select * from Users where UserName = @UserName and Password= @Password and Device= @Device and IpAddress = @IpAddress limit 1;";

                DynamicParameters parameters = new DynamicParameters();
                parameters.Add("@UserName", model.UserName);
                parameters.Add("@Password", hashPassword);
                parameters.Add("@Device", model.Device);
                parameters.Add("@IpAddress", model.IpAddress);

                var user = await _dapperService.ReturnRowAsync<User>(query, parameters);
                // check if user not exists
                if (user == null)
                    return null;
                // authentication successful
                var jwtToken = GenerateJwtToken(user);

                var refreshToken = await GenerateRefreshToken(user.Id, user.IpAddress);

                if (refreshToken == null)
                    return null; // unable to generate refresh Token

                return new LoginResponse(user, jwtToken, refreshToken.Token);
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        public async Task<bool> SaveUser(SignUp model)
        {
            try
            {
                string hashPassword = PasswordMd5(model.Password);
                string query = $"insert into Users values(@Id,@UserName,@Password,@FirstName,@LastName,@Device,@IpAddress)";

                DynamicParameters parameters = new DynamicParameters();
                parameters.Add("@Id", 0);
                parameters.Add("@UserName", model.UserName);
                parameters.Add("@Password", hashPassword);
                parameters.Add("@Device", model.Device);
                parameters.Add("@IpAddress", model.IpAddress);
                parameters.Add("@FirstName", model.FirstName);
                parameters.Add("@LastName", model.LastName);
                return await _dapperService.ExecuteAsync(query, parameters);
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        public async Task<LoginResponse> RefreshToken(string token, string ipAddress)
        {

            var refreshToken = await GetRefreshTokenInfo(token);
            // return null if no refreshToken found or if token is no longer active
            if (refreshToken == null || !refreshToken.IsActive) return null;

            var newRefreshToken = await GenerateRefreshToken(refreshToken.UserId, ipAddress);
            // replace old refresh token with a new one and save
            bool status = await UpdateRefreshToken(refreshToken.Id, newRefreshToken.Token, ipAddress);
            if (status == false) return null;

            // Get User Information to generate new JWT token
            var user = await GetUserById(refreshToken.UserId);
            // generate new jwt
            var jwtToken = GenerateJwtToken(user);

            return new LoginResponse(user, jwtToken, newRefreshToken.Token);
        }
        public async Task<bool> RevokeToken(string token, string ipAddress)
        {
            var refreshToken = await GetRefreshTokenInfo(token); ;
            // return null if no refreshToken found or if token is no longer active
            if (refreshToken == null || !refreshToken.IsActive) return false;
            // revoke token and save
            return await UpdateRefreshToken(refreshToken.Id, null, ipAddress);
        }
        public async Task<User> GetUserById(int id)
        {
            string query = $"select * from Users where Id = @Id;";
            DynamicParameters parameters = new DynamicParameters();
            parameters.Add("@Id", id);
            return await _dapperService.ReturnRowAsync<User>(query, parameters);
        }

        #region Private Functions
        private static string PasswordMd5(string password)
        {
            if (password == null) throw new ArgumentNullException("password");
            if (string.IsNullOrWhiteSpace(password)) throw new ArgumentException("Value cannot be empty or whitespace only string.", "password");

            using (System.Security.Cryptography.MD5 md5 = System.Security.Cryptography.MD5.Create())
            {
                byte[] inputBytes = System.Text.Encoding.ASCII.GetBytes(password);
                byte[] hashBytes = md5.ComputeHash(inputBytes);

                // Convert the byte array to hexadecimal string
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < hashBytes.Length; i++)
                {
                    sb.Append(hashBytes[i].ToString("X2"));
                }
                var result = sb.ToString();
                return result.ToLower();
            }
        }
        private string GenerateJwtToken(User user)
        {
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim("UserId", user.Id.ToString()),
                new Claim("FirstName", user.FirstName),
                new Claim("LastName",  user.LastName),
                new Claim("UserName",  user.UserName)
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_appSettings.Secret));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var expires = DateTime.Now.AddMinutes(Convert.ToDouble(_appSettings.JwtExpireMinutes));

            var token = new JwtSecurityToken(
                _appSettings.JwtIssuer,
                _appSettings.JwtIssuer,
                claims,
                expires: expires,
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        private async Task<RefreshToken> GenerateRefreshToken(int UserId, string ipAddress)
        {
            using (var rngCryptoServiceProvider = new RNGCryptoServiceProvider())
            {
                var randomBytes = new byte[64];
                rngCryptoServiceProvider.GetBytes(randomBytes);
                var refreshToken = new RefreshToken
                {
                    Token = Convert.ToBase64String(randomBytes),
                    Expires = DateTime.UtcNow.AddDays(1),
                    Created = DateTime.UtcNow,
                    CreatedByIp = ipAddress
                };
                string query = @"insert into RefreshTokens(UserId,Token,Expires,Created,CreatedByIp)
                                                  Values(@UserId, @Token,@Expires,@Created,@CreatedByIp)";
                DynamicParameters parameters = new DynamicParameters();
                parameters.Add("@UserId", UserId);
                parameters.Add("@Token", refreshToken.Token);
                parameters.Add("@Expires", refreshToken.Expires);
                parameters.Add("@Created", refreshToken.Created);
                parameters.Add("@CreatedByIp", refreshToken.CreatedByIp);
                var result = await _dapperService.ExecuteAsync(query, parameters);
                return result == true ? refreshToken : null;
            }
        }
        private async Task<bool> UpdateRefreshToken(int RefreshTokenId, string token, string ipAddress)
        {
            string query = @"update RefreshTokens set Revoked = @Revoked, RevokedByIp= @RevokedByIp,ReplacedByToken=@ReplacedByToken where Id=@RefreshTokenId;";
            DynamicParameters parameters = new DynamicParameters();
            parameters.Add("@RefreshTokenId", RefreshTokenId);
            parameters.Add("@Revoked", DateTime.UtcNow);
            parameters.Add("@RevokedByIp", ipAddress);
            parameters.Add("@ReplacedByToken", token);
            var result = await _dapperService.ExecuteAsync(query, parameters);
            return result;
        }
        private async Task<RefreshToken> GetRefreshTokenInfo(string token)
        {
            string query = $"select * from RefreshTokens where Token = @Token;";
            DynamicParameters parameters = new DynamicParameters();
            parameters.Add("@Token", token);
            return await _dapperService.ReturnRowAsync<RefreshToken>(query, parameters);
        }
        #endregion

        public void Dispose()
        {
            _context.Dispose();
        }
    }
}
