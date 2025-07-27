using ECoremmerce.Web.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Text;
using System.Text.Json;

namespace ECoremmerce.Web.Pages
{
    public class IndexModel : PageModel
    {
        private readonly ILogger<IndexModel> _logger;
        private IHttpClientFactory _httpClientFactory { get; set; }

        [BindProperty]
        public string Username { get; set; }

        public IndexModel(ILogger<IndexModel> logger, IHttpClientFactory httpClientFactory)
        {
            _logger = logger;
            _httpClientFactory = httpClientFactory;
        }

        public void OnGet()
        {

        }

        public async Task<IActionResult> OnPostAsync()
        {
            var httpClient = _httpClientFactory.CreateClient("Appsec-Labs-IDP.Authentication.API" ?? "");
            using HttpResponseMessage response = await httpClient.PostAsync("account/login",
                new StringContent(JsonSerializer.Serialize(new User { Username = Username }),
                Encoding.UTF8, "application/json"
                ));

            if (response.IsSuccessStatusCode)
            {              
                var json = await response.Content.ReadAsStringAsync();
                var obj = JsonDocument.Parse(json);
                var jwt = obj.RootElement.GetProperty("accessToken").GetString();

                if (!string.IsNullOrEmpty(jwt))
                {
                    HttpContext.Session.SetString("JWT", jwt);    
                    
                    return RedirectToPage("/Dashboard");
                }
            }

            return Page();
        }
    }
}
