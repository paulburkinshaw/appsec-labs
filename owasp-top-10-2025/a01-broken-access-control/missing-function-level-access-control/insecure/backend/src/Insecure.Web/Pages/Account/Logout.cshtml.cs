using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Caching.Memory;

namespace Insecure.Web.Pages.Acount
{
    public class LogoutModel : PageModel
    {
        private readonly IMemoryCache _memoryCache;

        public LogoutModel(IMemoryCache memoryCache)
        {
            _memoryCache = memoryCache;
        }

        public void OnGet()
        {
            HttpContext.SignOutAsync().GetAwaiter().GetResult();
            _memoryCache.Remove($"jwt:{User.Identity.Name}");
            Response.Redirect("/Account/Login");
        }
    }
}
