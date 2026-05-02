using System.Collections.Immutable;
using System.Security.Claims;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using StreamLineAuthZ.Data;

namespace StreamLineAuthZ.Endpoints.Auth;

// Handles the authorization endpoint — the entry point for the Authorization Code + PKCE flow.
//
// Flow:
//   1. Client redirects the browser to GET /connect/authorize?...
//   2. OpenIddict validates the request parameters (client_id, redirect_uri, PKCE, etc.)
//   3. This handler runs. If the user has no Identity cookie -> redirect to login page.
//   4. After login the browser comes back here with a valid cookie.
//   5. We locate or create a permanent authorization (consent record) for this user + client.
//   6. Results.SignIn tells OpenIddict to issue the authorization code and redirect to redirect_uri.
//
// Authorization Code grant — RFC 6749 §4.1: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1
// PKCE — RFC 7636: https://datatracker.ietf.org/doc/html/rfc7636
public sealed class AuthorizeEndpoint : IEndpoint
{
    public void MapEndpoint(IEndpointRouteBuilder app)
    {
        // The OIDC spec allows both GET and POST for the authorization endpoint.
        // GET is the normal browser redirect; POST is used when the request URL would exceed
        // browser URL length limits (rare but required by spec).
        // RFC 6749 §3.1: https://datatracker.ietf.org/doc/html/rfc6749#section-3.1
        var group = app.MapGroup("/connect").WithTags("Authorization Server").AllowAnonymous();
        group.MapGet("/authorize", Authorize);
        group.MapPost("/authorize", Authorize);
    }

    private static async Task<IResult> Authorize(
        HttpContext httpCtx,
        UserManager<ApplicationUser> userManager,
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictAuthorizationManager authorizationManager)
    {
        // OpenIddict stashes its validated request here after running the server pipeline.
        // Null means we're somehow outside of that pipeline, should never happen in practice.
        var request = httpCtx.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        // Try to read the existing Identity cookie. This is how we know whether the user
        // has already authenticated in this browser session.
        var result = await httpCtx.AuthenticateAsync(IdentityConstants.ApplicationScheme);

        if (result is not { Succeeded: true })
        {
            // No valid cookie -> redirect to the login page. Challenge will send the browser
            // to /Account/Login?ReturnUrl=<this full URL>, and after successful login
            // Identity redirects back here so we can continue the flow.
            return Results.Challenge(
                new AuthenticationProperties { RedirectUri = httpCtx.Request.GetEncodedUrl() },
                [IdentityConstants.ApplicationScheme]);
        }

        // Cookie present — resolve the full ApplicationUser from the cookie's principal.
        var user = await userManager.GetUserAsync(result.Principal)
            ?? throw new InvalidOperationException("The authenticated user could not be retrieved.");

        var userId = await userManager.GetUserIdAsync(user);
        var scopes = request.GetScopes();

        var application = await applicationManager.FindByClientIdAsync(request.ClientId!)
            ?? throw new InvalidOperationException($"Client '{request.ClientId}' was not found.");
        var applicationId = await applicationManager.GetIdAsync(application)
            ?? throw new InvalidOperationException("The application identifier could not be retrieved.");

        // Look for an existing, valid permanent authorization for this user + client + requested scopes.
        // If one exists we reuse it — the user has already consented and we don't want to keep
        // creating new authorization records on every login.
        var authorization = await authorizationManager.FindAsync(
            subject : userId,
            client  : applicationId,
            status  : OpenIddictConstants.Statuses.Valid,
            type    : OpenIddictConstants.AuthorizationTypes.Permanent,
            scopes  : scopes).FirstOrDefaultAsync();

        var principal = BuildPrincipal(user, userId, scopes);

        // No prior consent record — create one automatically. Because streamline-client is a
        // first-party app (our own SvelteKit frontend) we skip the consent screen entirely and
        // approve on behalf of the user. This is the "programmatic consent" pattern.
        // To show a real consent UI, return a consent page view here instead.
        authorization ??= await authorizationManager.CreateAsync(
            principal : principal,
            subject   : userId,
            client    : applicationId,
            type      : OpenIddictConstants.AuthorizationTypes.Permanent,
            scopes    : scopes);

        // Attach the authorization ID so OpenIddict can link the issued tokens back to this
        // consent record and revoke them all together if needed.
        principal.SetAuthorizationId(await authorizationManager.GetIdAsync(authorization!));

        // SignIn tells OpenIddict to serialize the principal into an authorization code,
        // store it, and redirect the browser back to the client's redirect_uri with ?code=...
        return Results.SignIn(principal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private static ClaimsPrincipal BuildPrincipal(ApplicationUser user, string userId, ImmutableArray<string> scopes)
    {
        var identity = new ClaimsIdentity(
            authenticationType : OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            nameType           : OpenIddictConstants.Claims.Name,
            roleType           : OpenIddictConstants.Claims.Role);

        identity.SetClaim(OpenIddictConstants.Claims.Subject,          userId);
        identity.SetClaim(OpenIddictConstants.Claims.Email,            user.Email);
        identity.SetClaim(OpenIddictConstants.Claims.Name,             user.UserName);
        identity.SetClaim(OpenIddictConstants.Claims.PreferredUsername, user.UserName);

        var principal = new ClaimsPrincipal(identity);

        // IMPORTANT: SetScopes must run before SetDestinations. The destinations lambda
        // calls principal.HasScope(), which reads the scope claims written here.
        principal.SetScopes(scopes);
        identity.SetDestinations(claim => ClaimsHelper.GetDestinations(claim, principal));

        return principal;
    }
}