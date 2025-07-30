using Authentication.API.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Authentication.API.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AccountController : ControllerBase
    {
        private readonly ILogger<AccountController> _logger;
        private readonly IConfiguration _config;

        public AccountController(ILogger<AccountController> logger, IConfiguration config)
        {
            _logger = logger;
            _config = config;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="userModel"></param>
        /// <returns></returns>
        [HttpPost("login")]
        public IActionResult Login([FromBody] UserModel userModel)
        {
            if (userModel == null || string.IsNullOrEmpty(userModel.Username))
                return BadRequest("Invalid login request.");
     
            User user;
            switch (userModel.Username)
            {
                case "user1":
                    user = new User { Username = "user1", Role = UserRole.User };
                    break;
                case "admin1":
                    user = new User { Username = "admin1", Role = UserRole.Admin };
                    break;
                default:
                    return Unauthorized();
            }

            var accessToken = GenerateAccessToken(user);
            return Ok(new
            {
                accessToken
            });
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        private string GenerateAccessToken(User user)
        {
            if (user == null)
                throw new ArgumentNullException(nameof(user), "User cannot be null.");

            var claims = new[]
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Role, user.Role.ToString()),              
            };

            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Authentication:Schemes:Bearer:Key"]!));

            var jwtSecurityToken = new JwtSecurityToken(
                claims: claims,
                issuer: _config["Authentication:Schemes:Bearer:Issuer"],
                audience: _config["Authentication:Schemes:Bearer:Audience"],
                expires: DateTime.UtcNow.AddMinutes(30),
                signingCredentials: new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256)
            );

            var accessToken = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);

            return accessToken;
        }

    }
}
