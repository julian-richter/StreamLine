using System.Security.Claims;
using Microsoft.AspNetCore;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;

namespace StreamLineAuthZ.Endpoints.Auth;

// This is the token endpoint, the one place in our auth server that actually hands out tokens.
// Everything funnels through here. Lets rather not mess this up.
//
// We're implementing the OAuth 2.0 Client Credentials grant, which is the flow for
// machine-to-machine auth (no user involved, no browser, no consent screen).
//
// Client Credentials grant specifically lives in Section 4.4:
//   https://datatracker.ietf.org/doc/html/rfc6749#section-4.4
public sealed class TokenEndpoint : IEndpoint
{
    public void MapEndpoint(IEndpointRouteBuilder app)
    {
        // The `/connect/token` path is NOT arbitrary. It follows the OAuth 2.0 Authorization
        // Server Metadata specification (RFC 8414), which defines a standard discovery document
        // at `/.well-known/oauth-authorization-server`. That document points clients to this
        // exact path so they know where to ask for tokens without hardcoding anything.
        //
        // RFC 8414 (Authorization Server Metadata):
        //   https://datatracker.ietf.org/doc/html/rfc8414
        //
        // OpenIddict registers its own middleware that intercepts requests to this route BEFORE
        // our handler runs. It validates the client_id, client_secret, and grant_type for us.
        // By the time our code runs, the client is already authenticated. Huge deal.
        var group = app.MapGroup("/connect").WithTags("Authorization Server");

        // AllowAnonymous here does NOT mean "skip security", it means "don't require the
        // caller to already have a bearer token to hit this endpoint." That would be circular.
        // OpenIddict's own middleware is doing the heavy lifting for request validation.
        group.MapPost("/token", ExchangeToken)
            .WithName("ExchangeToken")
            .WithSummary("Exchange client credentials for an access token.")
            .WithDescription("Issues an access token using OAuth 2.0 client credentials flow.")
            .AllowAnonymous();
    }

    private static IResult ExchangeToken(HttpContext httpCtx)
    {
        // OpenIddict stashes the parsed token request on the HttpContext after its middleware
        // validates it. We grab it here. If this is null, something is deeply wrong with our
        // middleware pipeline, OpenIddict probably isn't registered or isn't running.
        //
        // OpenIddict server integration docs:
        //   https://documentation.openiddict.com/guides/getting-started/creating-your-own-server-instance
        var request = httpCtx.GetOpenIddictServerRequest()
                      ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        // OAuth 2.0 defines multiple grant types (authorization_code, refresh_token, password, etc.).
        // We only support `client_credentials` here. If someone sends a different grant_type,
        // we bail hard. Don't let unsupported flows silently succeed, that's how ppl silently impl bugs
        // that show up at 3am on a Saturday.
        //
        // Grant types overview — RFC 6749 Section 1.3:
        //   https://datatracker.ietf.org/doc/html/rfc6749#section-1.3
        if (!request.IsClientCredentialsGrantType())
        {
            throw new InvalidOperationException("The specified grant type is not supported.");
        }

        // By this point OpenIddict has already:
        //   1. Parsed and validated the request body (grant_type, client_id, client_secret, scope)
        //   2. Looked up the application in the database
        //   3. Verified the client_secret matches what's stored
        //   4. Confirmed the requested scopes are allowed for this client
        //
        // We now build a ClaimsIdentity which is a bag of claims that describes WHO this token
        // represents. For client credentials, "who" is the client application itself, not a user.
        //
        // The authenticationType MUST match the OpenIddict scheme. This is what tells ASP.NET Core
        // which authentication handler will sign and serialize this identity into a token.
        var identity = new ClaimsIdentity(authenticationType: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

        // The `sub` (subject) claim is THE canonical identifier in any OAuth/OIDC token.
        // It uniquely identifies the principal the token was issued for.
        // For client credentials, the subject is the client_id, there's no user, so the
        // client IS the subject.
        //
        // JWT `sub` claim — RFC 7519 Section 4.1.2:
        //   https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2
        identity.SetClaim(OpenIddictConstants.Claims.Subject, request.ClientId ?? throw new InvalidOperationException("Client Identifier missing."));

        // The `name` claim is a human-readable display name for the principal.
        // Again, since there's no user here, we're using client_id as the name too.
        // TODO: resolve a friendly name from our application registry.
        //
        // OpenID Connect Standard Claims:
        //   https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        identity.SetClaim(OpenIddictConstants.Claims.Name, request.ClientId ?? throw new InvalidOperationException("Client identifier is missing."));

        // This is OpenIddict-specific and it's critically important, we MUST tell OpenIddict
        // which destination each claim should go to, or claims will be silently dropped.
        //
        // Destinations:
        //   - AccessToken  → the opaque or JWT token the client will use to call APIs
        //   - IdentityToken → the id_token returned in OIDC flows (not used here)
        //
        // The `_` fallback with an empty array means "drop everything else" aka don't leak
        // unintended claims into tokens. Principle of least privilege applies to token contents too.
        //
        // OpenIddict claim destinations docs:
        //   https://documentation.openiddict.com/configuration/claim-destinations
        identity.SetDestinations(static claim => claim.Type switch
        {
            OpenIddictConstants.Claims.Name    => [OpenIddictConstants.Destinations.AccessToken],
            OpenIddictConstants.Claims.Subject => [OpenIddictConstants.Destinations.AccessToken],
            _                                  => [] // intentionally empty because unknown claims go nowhere
        });

        // ClaimsPrincipal wraps one or more ClaimsIdentity objects. ASP.NET Core's auth system
        // always works with a ClaimsPrincipal, not a raw identity, same as when a user logs in.
        var principal = new ClaimsPrincipal(identity);

        // Attach the scopes the client actually requested (and that OpenIddict already validated).
        // Scopes in the token tell resource servers (your APIs) what this token is allowed to do.
        // If you don't set them here they won't appear in the token.
        //
        // OAuth 2.0 Scopes — RFC 6749 Section 3.3:
        //   https://datatracker.ietf.org/doc/html/rfc6749#section-3.3
        principal.SetScopes(request.GetScopes());

        // Results.SignIn tells ASP.NET Core to run the SignIn flow for the given authentication
        // scheme. OpenIddict intercepts this, serializes the ClaimsPrincipal into a signed JWT
        // (or reference token, depending on config), and writes the token response JSON to the
        // HTTP response body.
        //
        // The response will look like:
        //   { "access_token": "...", "token_type": "Bearer", "expires_in": 3600 }
        //
        // OAuth 2.0 Access Token Response — RFC 6749 Section 5.1:
        //   https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
        return Results.SignIn(
            principal,
            authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }
}