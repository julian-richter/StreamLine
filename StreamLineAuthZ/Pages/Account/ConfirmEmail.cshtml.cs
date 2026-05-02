using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using StreamLineAuthZ.Data;

namespace StreamLineAuthZ.Pages.Account;

public class ConfirmEmailModel(UserManager<ApplicationUser> userManager) : BasePageModel
{
    public bool Succeeded { get; private set; }

    public async Task<IActionResult> OnGetAsync(string? userId, string? token)
    {
        if (userId is null || token is null)
            return RedirectToPage("/Account/Login");

        var user = await userManager.FindByIdAsync(userId);
        if (user is null)
        {
            Succeeded = false;
            return Page();
        }

        var result = await userManager.ConfirmEmailAsync(user, token);
        Succeeded = result.Succeeded;
        return Page();
    }
}