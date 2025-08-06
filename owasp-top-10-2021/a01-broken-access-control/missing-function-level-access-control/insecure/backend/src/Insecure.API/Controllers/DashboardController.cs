using Insecure.API.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Insecure.API.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class DashboardController : ControllerBase
    {
        private readonly ILogger<DashboardController> _logger;

        public DashboardController(ILogger<DashboardController> logger)
        {
            _logger = logger;
        }

        [Authorize]
        [HttpGet("/admin/dashboard")]
        public Dashboard GetAdminDashboard()
        {
            return new Dashboard
            {
                WorkItems = [
                "Admin Work Item 1",
                "Admin Work Item 2",
                "Admin Work Item 3"
                ]
            };
        }

        [Authorize]
        [HttpGet("/user/dashboard")]
        public Dashboard Get()
        {
            return new Dashboard
            {
                WorkItems = [
                "Work Item 1",
                "Work Item 2",
                "Work Item 3"
                ]
            };
        }

        [HttpGet("/test/dashboard")]
        public Dashboard GetTest()
        {
            return new Dashboard
            {
                WorkItems = [
                "Test Item 1",
                "Test Item 2",
                "Test Item 3"
                ]
            };
        }
    }
}
