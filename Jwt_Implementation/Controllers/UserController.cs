using System;
using System.Threading.Tasks;
using Jwt_Implementation.Helper;
using Jwt_Implementation.Models;
using Jwt_Implementation.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Jwt_Implementation.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IUserService _userService;
        private readonly ActiveUser _activeUser;
        public UserController(IUserService userService, ActiveUser activeUser)
        {
            _userService = userService;
            _activeUser = activeUser;
        }
        /// <summary>
        /// this endpoint is for testing purposes if the JWT token is valid then it will return 
        /// the requesting user information otherwise it will return unauthorized 
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        public IActionResult Index()
        {
            return new JsonResult(_activeUser);
        }

        [AllowAnonymous]
        [HttpPost("signup")]
        public async Task<IActionResult> SaveUser([FromBody] SignUp model)
        {
            var response = await _userService.SaveUser(model);
            if (response == false)
                return StatusCode(500);
            return Ok();
        }

        [AllowAnonymous]
        [HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate([FromBody] Login model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userService.Authenticate(model);
                if (user == null)
                    return Unauthorized(new { message = "Invalid_Credentials" });
                setTokenCookie(user.RefreshToken);

                return Ok(user);
            }
            else
            {
                return ValidationProblem();
            }
        }

        [AllowAnonymous]
        [HttpPost("RefreshToken")]
        public async Task<IActionResult> RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];
            var response = await _userService.RefreshToken(refreshToken, ipAddress());

            if (response == null)
                return Unauthorized(new { message = "Invalid token" });

            setTokenCookie(response.RefreshToken);

            return Ok(response);
        }

        [HttpPost("RevokeToken")]
        public async Task<IActionResult> RevokeToken([FromBody] RevokeTokenRequest model)
        {
            // accept token from request body or cookie
            var token = model.Token ?? Request.Cookies["refreshToken"];

            if (string.IsNullOrEmpty(token))
                return BadRequest(new { message = "Token is required" });

            var response = await _userService.RevokeToken(token, ipAddress());

            if (!response)
                return NotFound(new { message = "Token not found" });

            return Ok(new { message = "Token revoked" });
        }

        #region Private helper methods
        private void setTokenCookie(string token)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = DateTime.UtcNow.AddDays(1)
            };
            Response.Cookies.Append("refreshToken", token, cookieOptions);
        }

        private string ipAddress()
        {
            if (Request.Headers.ContainsKey("X-Forwarded-For"))
                return Request.Headers["X-Forwarded-For"];
            else
                return HttpContext.Connection.RemoteIpAddress.MapToIPv4().ToString();
        }
        #endregion

    }
}
