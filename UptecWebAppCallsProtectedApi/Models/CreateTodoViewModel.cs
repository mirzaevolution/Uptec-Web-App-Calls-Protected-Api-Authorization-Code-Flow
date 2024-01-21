using System.ComponentModel.DataAnnotations;

namespace UptecWebAppCallsProtectedApi.Models
{
    public class CreateTodoViewModel
    {
        [Required]
        [MinLength(3)]
        [MaxLength(100)]
        public string Title { get; set; }
        public string Description { get; set; }
    }
}