using Secure.API.Models;

namespace Secure.Web.Models
{
    public class ViewModel
    {
        public string? Username { get; set; }

        public IList<WorkItem>? WorkItems { get; set; }
      
        public DashboardSortSettings? DashboardSortSettings { get; set; }
    }
}
