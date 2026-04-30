using Microsoft.AspNetCore.Identity;
using OpenIddict.Server.AspNetCore;
using StreamLineAuthZ.Data;

namespace StreamLineAuthZ.Endpoints.Auth;

// Handles the OpenID Connect end-session endpoint (RP-Initiated Logout).
//
// Flow:
//   1. Client redirects the browser to GET /connect/logout?id_token_hint=...&post_logout_redirect_uri=...
//   2. OpenIddict validates the request (verifies the id_token_hint, checks post_logout_redirect_uri).
//   3. This handler signs the user out of the Identity cookie scheme (clears the server-side session).
//   4. Results.SignOut with the OpenIddict scheme tells OpenIddict to revoke the tokens and
//      redirect the browser to post_logout_redirect_uri (or "/" if none was specified / validated).
//
// RP-Initiated Logout 1.0: https://openid.net/specs/openid-connect-rpinitiated-1_0.html
public sealed class LogoutEndpoint : IEndpoint
{
    public void MapEndpoint(IEndpointRouteBuilder app)
    {
        // The spec allows both GET (browser redirect) and POST (form submission).
        // We handle both identically — no confirmation page needed for a first-party app.
        var group = app.MapGroup("/connect").WithTags("Authorization Server").AllowAnonymous();
        group.MapGet("/logout", Logout);
        group.MapPost("/logout", Logout);
    }

    private static async Task<IResult> Logout(SignInManager<ApplicationUser> signInManager)
    {
        // Clear the Identity cookie. Without this, the browser would still have a valid
        // session cookie and logging back in would succeed without a password prompt.
        await signInManager.SignOutAsync();

        // Trigger OpenIddict's end-session completion. This revokes any active tokens
        // tied to the current authorization and redirects to post_logout_redirect_uri.
        return Results.SignOut(authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
    }
}