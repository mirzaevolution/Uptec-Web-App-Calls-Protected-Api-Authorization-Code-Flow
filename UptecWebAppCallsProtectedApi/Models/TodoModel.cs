namespace UptecWebAppCallsProtectedApi.Models
{
    public class TodoModel
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string Title { get; set; }
        public string Description { get; set; }
    }
}
