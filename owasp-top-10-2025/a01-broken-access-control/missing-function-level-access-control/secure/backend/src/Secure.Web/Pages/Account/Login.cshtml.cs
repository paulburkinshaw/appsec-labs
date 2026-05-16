using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.IdentityModel.JsonWebTokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace Secure.Web.Pages.Acount
{
    public class LoginModel : PageModel
    {
        private readonly ILogger<IndexModel> _logger;
        private readonly IMemoryCache _memoryCache;

        [BindProperty]
        public string Username { get; set; }

        public LoginModel(ILogger<IndexModel> logger, IHttpClientFactory httpClientFactory, IMemoryCache memoryCache)
        {
            _logger = logger;
            _memoryCache = memoryCache;
        }

        public void OnGet()
        {

        }

        public async Task<IActionResult> OnPostAsync(string username)
        {
            // Simulate getting JWT from an Identity Provider       
            var jsonWebToken = new JsonWebToken(GetJwt(username) ?? string.Empty);   

            var identity = new ClaimsIdentity(jsonWebToken.Claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var principal = new ClaimsPrincipal(identity);
            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);       

            _memoryCache.Set($"jwt:{username}", jsonWebToken.EncodedToken, TimeSpan.FromMinutes(10));

            return RedirectToPage("/Index");
        }

        private string GetJwt(string username)
        {
            var claims = new List<Claim>()
            {
               new Claim(ClaimTypes.Name, username)
            };

            switch (username)
            {
                case "user1":
                    claims.Add(new Claim(ClaimTypes.Role, "User"));
                    break;
                case "admin1":
                    claims.Add(new Claim(ClaimTypes.Role, "Admin"));
                    break;
                default:
                    throw new UnauthorizedAccessException($"User {username} is not authorized.");
            }

            if (username == null)
                throw new ArgumentNullException(nameof(username), "username cannot be null.");

            var jwtSecurityToken = new JwtSecurityToken(
               claims: claims
             );

            return new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
        }
    }
}
