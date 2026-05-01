using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using StreamLineAuthZ.Data;

namespace StreamLineAuthZ.Pages.Account;

public class LoginModel(SignInManager<ApplicationUser> signInManager) : PageModel
{
    [BindProperty]
    public InputModel Input { get; set; } = new();

    // SupportsGet lets the returnUrl query-string parameter bind automatically when the
    // Identity cookie challenge redirects here (GET /Account/Login?ReturnUrl=...).
    // The hidden field in the form then carries it through the POST.
    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

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

    // LocalRedirect() rejects absolute URLs, but OpenIddict sets the ReturnUrl to the full
    // /connect/authorize URL (same host). We allow absolute redirects back to our own host only.
    private string SafeReturnUrl()
    {
        if (string.IsNullOrEmpty(ReturnUrl))
            return "/";
        if (Url.IsLocalUrl(ReturnUrl))
            return ReturnUrl;
        if (Uri.TryCreate(ReturnUrl, UriKind.Absolute, out var uri) &&
            uri.Host.Equals(HttpContext.Request.Host.Host, StringComparison.OrdinalIgnoreCase))
            return ReturnUrl;
        return "/";
    }

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