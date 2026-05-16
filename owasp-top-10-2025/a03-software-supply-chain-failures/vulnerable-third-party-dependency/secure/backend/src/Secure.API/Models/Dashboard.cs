using System.Globalization;

namespace Secure.API.Models
{
    public class Dashboard
    {
        public IList<WorkItem>? WorkItems { get; set; }
    }

    public class WorkItem
    {
        public string Title { get; set; }
        public string Description { get; set; }
        public DateTime DateCreated { get; set; }
        public DateTime DueDate { get; set; }
        public WorkItem(string title, string description, DateTime dueDate)
        {
            Title = title;
            Description = description;
            DueDate = dueDate;
            DateCreated = DateTime.Now;          
        }
        public override string ToString()
        {
            return $"{Title} - {Description} (Due: {DueDate.ToString("d", CultureInfo.InvariantCulture)})";
        }
    }
}
