using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace StreamLineAuthZ.Pages;

public abstract class BasePageModel : PageModel
{
    // SupportsGet lets the ReturnUrl query-string parameter bind automatically when the
    // Identity cookie challenge redirects to a page (GET /Account/Login?ReturnUrl=...).
    // The hidden field in forms then carries it through the POST.
    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    // LocalRedirect() rejects absolute URLs, but OpenIddict sets the ReturnUrl to the full
    // /connect/authorize URL (same host). We allow absolute redirects back to our own host only.
    protected string SafeReturnUrl()
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
}
