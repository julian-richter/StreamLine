using System.Collections.Immutable;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using OpenIddict.Abstractions;
using StreamLineAuthZ.Data;
using StreamLineAuthZ.Endpoints.Auth;

namespace StreamLineAuthZ.Pages.Account;

[Authorize]
public class ConsentModel(
    UserManager<ApplicationUser> userManager,
    IOpenIddictApplicationManager applicationManager,
    IOpenIddictAuthorizationManager authorizationManager) : BasePageModel
{
    public string ClientName { get; private set; } = string.Empty;
    public IReadOnlyList<string> RequestedScopes { get; private set; } = [];

    public async Task<IActionResult> OnGetAsync()
    {
        if (string.IsNullOrEmpty(ReturnUrl))
            return Redirect("/");

        var (clientId, scopes) = ParseAuthorizeUrl(ReturnUrl);

        var application = clientId is null ? null : await applicationManager.FindByClientIdAsync(clientId);
        ClientName = application is null
            ? clientId ?? "Unknown application"
            : await applicationManager.GetDisplayNameAsync(application) ?? clientId ?? "Unknown application";

        RequestedScopes = scopes;
        return Page();
    }

    public async Task<IActionResult> OnPostAllowAsync()
    {
        var safeUrl = SafeReturnUrl();
        var (clientId, scopes) = ParseAuthorizeUrl(safeUrl);

        if (clientId is null)
            return Redirect("/");

        var user = await userManager.GetUserAsync(User)
            ?? throw new InvalidOperationException("Authenticated user could not be retrieved.");
        var userId = await userManager.GetUserIdAsync(user);

        var application = await applicationManager.FindByClientIdAsync(clientId)
            ?? throw new InvalidOperationException($"Client '{clientId}' was not found.");
        var applicationId = await applicationManager.GetIdAsync(application)
            ?? throw new InvalidOperationException("Application ID could not be retrieved.");

        var scopeArray = scopes.ToImmutableArray();
        var principal = AuthorizeEndpoint.BuildPrincipal(user, userId, scopeArray);

        await authorizationManager.CreateAsync(
            principal : principal,
            subject   : userId,
            client    : applicationId,
            type      : OpenIddictConstants.AuthorizationTypes.Permanent,
            scopes    : scopeArray);

        return Redirect(safeUrl);
    }

    public async Task<IActionResult> OnPostDenyAsync()
    {
        var safeUrl = SafeReturnUrl();
        var query = ParseQueryString(safeUrl);

        var clientId = query.TryGetValue("client_id", out var cid) ? cid.ToString() : null;
        var redirectUri = query.TryGetValue("redirect_uri", out var ru) ? ru.ToString() : null;
        var state = query.TryGetValue("state", out var st) ? st.ToString() : null;

        if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(redirectUri))
            return Redirect("/");

        // Validate redirect_uri against the registered URIs for this client before
        // trusting it. Without this check, a crafted consent URL could redirect the
        // user to an arbitrary destination with the access_denied error attached.
        var application = await applicationManager.FindByClientIdAsync(clientId);
        if (application is null)
            return Redirect("/");

        var registeredUris = await applicationManager.GetRedirectUrisAsync(application);
        if (!registeredUris.Contains(redirectUri, StringComparer.Ordinal))
            return Redirect("/");

        var errorParams = new Dictionary<string, string?> { ["error"] = "access_denied" };
        if (!string.IsNullOrEmpty(state))
            errorParams["state"] = state;

        return Redirect(QueryHelpers.AddQueryString(redirectUri, errorParams));
    }

    internal static string GetScopeDisplayName(string scope) => scope switch
    {
        OpenIddictConstants.Scopes.OpenId         => "Sign you in (required)",
        OpenIddictConstants.Scopes.Profile        => "Your name and profile information",
        OpenIddictConstants.Scopes.Email          => "Your email address",
        OpenIddictConstants.Scopes.OfflineAccess  => "Keep you signed in with refresh tokens",
        "api"                                      => "Access StreamLine on your behalf",
        _                                          => scope
    };

    private static (string? clientId, IReadOnlyList<string> scopes) ParseAuthorizeUrl(string url)
    {
        var query = ParseQueryString(url);
        var clientId = query.TryGetValue("client_id", out var cid) ? cid.ToString() : null;
        var scopeStr = query.TryGetValue("scope", out var s) ? s.ToString() : string.Empty;
        var scopes = scopeStr.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        return (clientId, scopes);
    }

    private static Dictionary<string, Microsoft.Extensions.Primitives.StringValues> ParseQueryString(string url)
    {
        var qIndex = url.IndexOf('?');
        var qs = qIndex >= 0 ? url[(qIndex + 1)..] : string.Empty;
        return QueryHelpers.ParseQuery(qs);
    }
}