using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Caching.Memory;
using Newtonsoft.Json;
using Secure.API.Models;
using Secure.Web.Models;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;

namespace Secure.Web.Pages
{
    [Authorize]
    public class IndexModel : PageModel
    {
        private readonly ILogger<IndexModel> _logger;
        private IHttpClientFactory _httpClientFactory { get; set; }
        private readonly IMemoryCache _memoryCache;

        [BindProperty]
        public ViewModel ViewModel { get; set; } = new();

        JsonSerializerSettings JsonSerializerSettings = new JsonSerializerSettings
        {
            TypeNameHandling = TypeNameHandling.None
        };

        // In a real application, store this securely (e.g., environment variable, secure vault)
        private readonly string _secretKey = "strongsecret";

        public IndexModel(ILogger<IndexModel> logger, IHttpClientFactory httpClientFactory, IMemoryCache memoryCache)
        {
            _logger = logger;
            _httpClientFactory = httpClientFactory;
            _memoryCache = memoryCache;
        }

        public async Task<IActionResult> OnGetAsync()
        {
            #region Signin
            if (User.Identity == null)
                throw new UnauthorizedAccessException();

            var jwt = _memoryCache.Get<string>($"jwt:{User.Identity.Name}");
            if (String.IsNullOrEmpty(jwt))
            {
                _logger.LogWarning("JWT not found in cache for user {Username}. Redirecting to login.", User.Identity.Name);
                return RedirectToPage("/Account/Login");
            }

            ViewModel.Username = User.Identity.Name;
            #endregion

            #region Get Cookie  
            var dashboardSortSettings = new DashboardSortSettings();
            var serializedData = Request.Cookies["dashboardSortSettings"];
            var signature = Request.Cookies["dashboardSortSettings.sig"];
            if (!string.IsNullOrEmpty(serializedData) && !string.IsNullOrEmpty(signature))
            {
                try
                {
                    #region Validate Signature
                    if(!ValidateSignature(serializedData, signature))
                        throw new Exception("Invalid cookie signature");
                    #endregion

                    dashboardSortSettings = JsonConvert.DeserializeObject<DashboardSortSettings>(serializedData, JsonSerializerSettings);
                    if (dashboardSortSettings == null)
                        throw new Exception($"unable to deserialize cookie value: {serializedData}");

                    ViewModel.DashboardSortSettings = dashboardSortSettings;
                }
                catch (JsonSerializationException ex)
                {                   
                    throw new JsonSerializationException(
                        $"Dashboard settings type mismatch",
                        ex
                    );
                }
            }
            #endregion

            #region Send API Request
            await SendApiRequest(jwt, dashboardSortSettings);
            #endregion

            return Page();
        }

        public async Task<IActionResult> OnPostSortAsync()
        {
            if (ViewModel.DashboardSortSettings == null)
                throw new ArgumentNullException(nameof(ViewModel.DashboardSortSettings));

            if (!Enum.IsDefined(typeof(WorkItemsSortBy), ViewModel.DashboardSortSettings.WorkItemsSortBy))
                throw new ArgumentException("Invalid sort by.");

            if (!Enum.IsDefined(typeof(WorkItemsSortOrder), ViewModel.DashboardSortSettings.WorkItemsSortOrder))
                throw new ArgumentException("Invalid sort order.");

            var jwt = _memoryCache.Get<string>($"jwt:{User?.Identity?.Name}");
            if (String.IsNullOrEmpty(jwt))
            {
                _logger.LogWarning("JWT not found in cache for user {Username}. Redirecting to login.", User?.Identity?.Name);
                return RedirectToPage("/Account/Login");
            }

            #region Sign Data
            var serializedData = JsonConvert.SerializeObject(ViewModel.DashboardSortSettings, JsonSerializerSettings);
            var signature = SignData(serializedData);
            #endregion

            #region Set Cookie                    
            Response.Cookies.Append("dashboardSortSettings", serializedData, new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict });
            Response.Cookies.Append("dashboardSortSettings.sig", signature, new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict });
            #endregion

            #region Send API Request
            await SendApiRequest(jwt, ViewModel.DashboardSortSettings);
            #endregion

            return Page();
        }

        private async Task SendApiRequest(string jwt, DashboardSortSettings dashboardSortSettings)
        {
            string dashboardSortSettingsStr = JsonConvert.SerializeObject(dashboardSortSettings, JsonSerializerSettings);

            using StringContent jsonContent = new(
            dashboardSortSettingsStr,
            Encoding.UTF8,
            "application/json");

            var httpClient = _httpClientFactory.CreateClient("Secure.API" ?? "");
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
            using HttpResponseMessage response = await httpClient.PostAsync("user/dashboard", jsonContent);

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogInformation($"Failed to load user/dashboard. Status code: {response.StatusCode}");
                RedirectToPage("/Error");
            }

            var dashboard = await response.Content.ReadFromJsonAsync<Dashboard>();
            ViewModel.WorkItems = dashboard?.WorkItems ?? new List<WorkItem>();
        }

        private string SignData(string data)
        {
            // Create a content hash - a SHA-256 hash of the data being signed
            var contentHash = SHA256.HashData(Encoding.UTF8.GetBytes(data));

            // Compute a signature using HMAC with the secret key, the signature is unique to both the data and the key.
            using var hmacsha256 = new HMACSHA256(Encoding.UTF8.GetBytes(_secretKey));          
            var hash = hmacsha256.ComputeHash(contentHash);
            var signature = Convert.ToBase64String(hash);

            return signature;
        }

        private bool ValidateSignature(string data, string signature)
        {         
            if (string.IsNullOrEmpty(data) || string.IsNullOrEmpty(data))
                return false;

            var expectedSignature = SignData(data);
            return expectedSignature == signature;
        }
    }
}
