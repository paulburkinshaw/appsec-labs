using Insecure.API.Models;
using Microsoft.AspNetCore.Mvc;

namespace Insecure.Web.Models
{
    public class ViewModel
    {
        public string? Username { get; set; }

        public IList<WorkItem>? WorkItems { get; set; }
      
        public DashboardSortSettings? DashboardSortSettings { get; set; }
    }
}
