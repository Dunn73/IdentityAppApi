using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;

namespace Api.Models;

public class User : IdentityUser
{
    [Required]
    public string FirstName {get; set;}
    [Required]
    public string LastName {get; set;}
    public DateTime DateCreated {get; set;} = DateTime.UtcNow;
}