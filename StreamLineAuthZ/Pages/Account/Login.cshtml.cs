using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using StreamLineAuthZ.Data;

namespace StreamLineAuthZ.Pages.Account;

public class LoginModel(SignInManager<ApplicationUser> signInManager) : BasePageModel
{
    [BindProperty]
    public InputModel Input { get; set; } = new();

    public class InputModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; } = string.Empty;
    }

    public void OnGet() { }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid)
            return Page();

        var result = await signInManager.PasswordSignInAsync(
            userName          : Input.Email,
            password          : Input.Password,
            isPersistent      : false,
            lockoutOnFailure  : true);

        if (result.Succeeded)
            return Redirect(SafeReturnUrl());

        if (result.IsLockedOut)
        {
            ModelState.AddModelError(string.Empty, "Account locked out. Please try again later.");
            return Page();
        }

        ModelState.AddModelError(string.Empty, "Invalid email or password.");
        return Page();
    }
}