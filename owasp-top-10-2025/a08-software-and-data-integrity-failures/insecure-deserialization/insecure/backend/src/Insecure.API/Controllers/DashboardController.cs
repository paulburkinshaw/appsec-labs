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
        [HttpPost("/user/dashboard")]
        public Dashboard Get(DashboardSortSettings dashboardSortSettings)
        {
            // In a real application, work items would be fetched from a database or another service.
            var workItems = new List<WorkItem>
                {
                new WorkItem("Schedule follow up meeting with Alan",
                    "Schedule a follow-up meeting with Alan to discuss the project requirements.",
                    DateTime.Now.AddDays(3)),

                    new WorkItem("Accept Tony's meeting invite",
                    "Respond to Tony's meeting invite email.",
                    DateTime.Now.AddDays(1)),
               
                    new WorkItem("Create draft report for Sales team",
                    "Prepare and send the draft report to the Sales team for review.",
                    DateTime.Now.AddDays(10))
                };

            var query = workItems.AsQueryable();

            query = dashboardSortSettings.WorkItemsSortBy switch
            {
                WorkItemsSortBy.Title => dashboardSortSettings.WorkItemsSortOrder == WorkItemsSortOrder.Ascending
                                                ? query.OrderBy(x => x.Title)
                                                : query.OrderByDescending(x => x.Title),

                WorkItemsSortBy.DateCreated => dashboardSortSettings.WorkItemsSortOrder == WorkItemsSortOrder.Ascending
                                                ? query.OrderBy(x => x.DateCreated)
                                                : query.OrderByDescending(x => x.DateCreated),

                WorkItemsSortBy.DueDate => dashboardSortSettings.WorkItemsSortOrder == WorkItemsSortOrder.Ascending
                                                ? query.OrderBy(x => x.DueDate)
                                                : query.OrderByDescending(x => x.DueDate),

                _ => query
            };

            var workItemsOrdered = query.ToList();

            return new Dashboard
            {
                WorkItems = workItemsOrdered
            };
        }
    }
}
