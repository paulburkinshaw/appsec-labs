using System.Globalization;

namespace Insecure.API.Models;

public class Dashboard
{
    public IList<WorkItem>? WorkItems { get; set; }
}

public class WorkItem
{
    public string Title { get; set; }
    public string Description { get; set; }
    public string Notes { get; set; }   // new
    public DateTime DateCreated { get; set; }
    public DateTime DueDate { get; set; }
    public WorkItem(string title, string description, string notes, DateTime dueDate)
    {
        Title = title;
        Description = description;
        Notes = notes;
        DueDate = dueDate;
        DateCreated = DateTime.Now;
    }
    public override string ToString()
    {
        return $"{Title} - {Description} (Due: {DueDate.ToString("d", CultureInfo.InvariantCulture)})";
    }
}
