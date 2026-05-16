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
        [HttpGet("/user/dashboard")]
        public Dashboard Get()
        {
            // In a real application, work items would be fetched from a database or another service.
            var workItems = new List<WorkItem>
                {
                new WorkItem("Schedule follow up meeting with Alan",
                    "Schedule a follow-up meeting with Alan to discuss the project requirements.",
                    "<b>Important: complete this asap</b>",
                    DateTime.Now.AddDays(3)),

                    new WorkItem("Accept Tony's meeting invite",
                    "Respond to Tony's meeting invite email.",
                    "User notes 2",
                    DateTime.Now.AddDays(1)),

                    new WorkItem("Create draft report for Sales team",
                    "Prepare and send the draft report to the Sales team for review.",
                    "User notes 3",
                    DateTime.Now.AddDays(10))
                };

            return new Dashboard
            {
                WorkItems = workItems
            };
        }
    }
}
