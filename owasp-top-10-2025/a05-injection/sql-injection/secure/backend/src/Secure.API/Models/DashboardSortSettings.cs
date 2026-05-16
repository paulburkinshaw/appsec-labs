namespace Secure.API.Models
{
    public enum WorkItemsSortOrder
    {
        Ascending,
        Descending
    }

    public enum WorkItemsSortBy
    {
        DateCreated,
        DueDate,
        Title
    }

    public class DashboardSortSettings
    {
        public WorkItemsSortBy WorkItemsSortBy { get; set; }
        public WorkItemsSortOrder WorkItemsSortOrder { get; set; }
    }
}
