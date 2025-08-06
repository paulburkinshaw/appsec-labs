using Authentication.API.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

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
        /// Authenticates a user based on the provided credentials and returns an access token. 
        /// </summary>
        /// <remarks>This method supports authentication for predefined users only. If the username
        /// matches "user1" or "admin1",  the user is authenticated and assigned a role. Otherwise, the request is
        /// denied.</remarks>
        /// <param name="userModel">The user credentials submitted for authentication. The <see cref="UserModel.Username"/> property must be
        /// provided.</param>
        /// <returns>An HTTP response containing an access token if authentication is successful.  Returns <see
        /// cref="BadRequestResult"/> if the request is invalid, or <see cref="UnauthorizedResult"/> if authentication
        /// fails.</returns>
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
        /// Retrieves the JSON Web Key Set (JWKS) containing the public RSA key used for verifying JWT signatures.
        /// </summary>
        /// <remarks>This endpoint returns a JWKS document in JSON format, which includes the public RSA
        /// key and associated metadata. The JWKS can be used by clients or external systems to verify the authenticity
        /// of JWTs issued by this application.</remarks>
        /// <returns>A JSON Web Key Set (JWKS) document containing the public RSA key and its metadata.</returns>
        [HttpGet("/.well-known/jwks.json")]
        public IResult WellKnownJwks()
        {
            var publicKey = _config["Authentication:Schemes:Bearer:RsaKeyPair:PublicKey:Value"];

            var rsaKey = RSA.Create();
            rsaKey.ImportFromPem(publicKey);
            var rsaParameters = rsaKey.ExportParameters(false);

            var jwk = new JsonWebKey
            {
                Kty = "RSA",
                E = Base64UrlEncoder.Encode(rsaParameters.Exponent),
                N = Base64UrlEncoder.Encode(rsaParameters.Modulus),
                Kid = _config["Authentication:Schemes:Bearer:RsaKeyPair:PublicKey:Kid"],
                Use = "sig",
                KeyOps = { "verify" },
                Alg = SecurityAlgorithms.RsaSha256
            };

            var jwks = new
            {
                Keys = new[] { jwk }
            };

            return Results.Json(jwks);
        }

        /// <summary>
        /// Generates a JWT access token for the specified user.   
        /// </summary>
        /// <remarks>The generated token includes claims for the user's username and role, as well as
        /// audience claims  retrieved from the application's configuration. The token is signed using RSA SHA-256 with
        /// a private key  specified in the configuration.  The token is valid for 30 minutes from the time of
        /// generation.</remarks>
        /// <param name="user">The user for whom the access token is generated. Cannot be <see langword="null"/>.</param>
        /// <returns>A JWT access token as a string, containing claims for the user's identity and role,  as well as audience and
        /// issuer information.</returns>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="user"/> is <see langword="null"/>.</exception>
        private string GenerateAccessToken(User user)
        {
            if (user == null)
                throw new ArgumentNullException(nameof(user), "User cannot be null.");

            var claims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Role, user.Role.ToString()),
            };

            foreach (var audience in _config.GetSection("Authentication:Schemes:Bearer:Audiences").Get<string[]>())
                claims.Add(new Claim(JwtRegisteredClaimNames.Aud, audience));

            var rsa = RSA.Create();
            rsa.ImportFromPem(_config["Authentication:Schemes:Bearer:RsaKeyPair:PrivateKey:Value"]);

            var rsaSecurityKey = new RsaSecurityKey(rsa);
            rsaSecurityKey.KeyId = _config["Authentication:Schemes:Bearer:RsaKeyPair:PublicKey:Kid"];

            var signingCredentials = new SigningCredentials(
                rsaSecurityKey,
                SecurityAlgorithms.RsaSha256);

            var jwtSecurityToken = new JwtSecurityToken(
               claims: claims,
               issuer: _config["Authentication:Schemes:Bearer:Issuer"],
               expires: DateTime.UtcNow.AddMinutes(30),
               signingCredentials: signingCredentials
             );

            var accessToken = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
            return accessToken;
        }

        [HttpGet("/rotate-rsa-key-pair")]
        public IActionResult RotateRsaKeyPair(string keyId)
        {
            using (var publicPrivate = new RSACryptoServiceProvider(2048))
            {
                _config["Authentication:Schemes:Bearer:RsaKeyPair:PublicKey:Value"] = publicPrivate.ExportRSAPublicKeyPem();
                _config["Authentication:Schemes:Bearer:RsaKeyPair:PrivateKey:Value"] = publicPrivate.ExportRSAPrivateKeyPem();
                _config["Authentication:Schemes:Bearer:RsaKeyPair:PublicKey:Kid"] = keyId;
            }

            return Ok(new
            {
                message = "RSA key pair rotated successfully."
            });
        }

    }
}
