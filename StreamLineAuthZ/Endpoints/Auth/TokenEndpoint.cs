using System.Security.Claims;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using StreamLineAuthZ.Data;

namespace StreamLineAuthZ.Endpoints.Auth;

// The token endpoint — every OAuth 2.0 token issued by this server comes through here.
//
// Three grant types are handled (in order of appearance in the method body):
//   1. client_credentials — M2M auth, no user involved. The client is the principal.
//   2. authorization_code — Browser flow. Exchanges a short-lived code for tokens after login.
//   3. refresh_token      — Renews an expired access token without repeating the login flow.
//
// OpenIddict's middleware validates the incoming request (client auth, grant type allowlist,
// PKCE, etc.) before our handler ever runs. By the time ExchangeToken is called, the request
// is already authenticated at the protocol level.
//
// RFC 6749 §4.4 (client_credentials):  https://datatracker.ietf.org/doc/html/rfc6749#section-4.4
// RFC 6749 §4.1 (authorization_code):  https://datatracker.ietf.org/doc/html/rfc6749#section-4.1
// RFC 6749 §6   (refresh_token):       https://datatracker.ietf.org/doc/html/rfc6749#section-6
public sealed class TokenEndpoint : IEndpoint
{
    public void MapEndpoint(IEndpointRouteBuilder app)
    {
        // /connect/token is not arbitrary — it follows RFC 8414 (Authorization Server Metadata),
        // which publishes this path in /.well-known/openid-configuration so clients can discover
        // it without hardcoding. RFC 8414: https://datatracker.ietf.org/doc/html/rfc8414
        var group = app.MapGroup("/connect").WithTags("Authorization Server");

        // AllowAnonymous means "don't require an existing bearer token to call this endpoint" —
        // that would be circular. OpenIddict handles client authentication before our handler runs.
        group.MapPost("/token", ExchangeToken)
            .WithName("ExchangeToken")
            .WithSummary("Exchange credentials for an access token.")
            .WithDescription("""
                Issues an OAuth 2.0 access token. The request body must be `application/x-www-form-urlencoded`.

                **Supported grant types**

                | `grant_type` | Required fields | Use case |
                |---|---|---|
                | `client_credentials` | `client_id`, `client_secret` (or HTTP Basic) | M2M / service-to-service |
                | `authorization_code` | `code`, `redirect_uri`, `code_verifier` (PKCE) | Browser-based / interactive |
                | `refresh_token` | `refresh_token` | Renew an expired access token |

                **Client authentication**

                Confidential clients may authenticate either via form body (`client_id` + `client_secret`) or via
                HTTP Basic authentication (`Authorization: Basic base64(client_id:client_secret)`). Public clients
                must use PKCE and do not send a secret.

                **Scopes**

                Request scopes via the `scope` field (space-separated). The granted scopes may be a subset of
                what was requested. Available scopes: `api`, `openid`, `profile`.
                """)
            .Accepts<TokenRequestDto>("application/x-www-form-urlencoded")
            .Produces<TokenResponseDto>()
            .Produces<OAuthErrorResponseDto>(StatusCodes.Status400BadRequest, "application/json")
            .Produces<OAuthErrorResponseDto>(StatusCodes.Status401Unauthorized, "application/json")
            .AllowAnonymous();
    }

    private static async Task<IResult> ExchangeToken(
        HttpContext httpCtx,
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager)
    {
        // OpenIddict stashes the parsed and validated token request on the HttpContext.
        // If this is null, OpenIddict's middleware is not in the pipeline — misconfiguration.
        var request = httpCtx.GetOpenIddictServerRequest()
                      ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        // ── Client Credentials ────────────────────────────────────────────────────────────
        // Machine-to-machine flow: the client authenticates with its own credentials,
        // no user involved. Used by backend services calling the StreamLine API directly.
        // RFC 6749 §4.4: https://datatracker.ietf.org/doc/html/rfc6749#section-4.4
        if (request.IsClientCredentialsGrantType())
        {
            // For client credentials the client IS the principal — no user record to look up.
            // The authenticationType MUST match the OpenIddict scheme so ASP.NET Core routes
            // the SignIn result back through OpenIddict's token serialization pipeline.
            var identity = new ClaimsIdentity(authenticationType: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            // sub — canonical principal identifier (JWT §4.1.2): https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2
            identity.SetClaim(OpenIddictConstants.Claims.Subject, request.ClientId
                ?? throw new InvalidOperationException("Client identifier is missing."));

            // name — human-readable display name.
            // TODO: resolve the registered DisplayName from the application registry instead of echoing client_id.
            identity.SetClaim(OpenIddictConstants.Claims.Name, request.ClientId
                ?? throw new InvalidOperationException("Client identifier is missing."));

            // OpenIddict requires explicit destination routing for every claim. Claims without a
            // destination are silently dropped — intentional to prevent accidental token leakage.
            // Docs: https://documentation.openiddict.com/configuration/claim-destinations
            identity.SetDestinations(static claim => claim.Type switch
            {
                OpenIddictConstants.Claims.Name    => [OpenIddictConstants.Destinations.AccessToken],
                OpenIddictConstants.Claims.Subject => [OpenIddictConstants.Destinations.AccessToken],
                _                                  => []
            });

            var principal = new ClaimsPrincipal(identity);

            // Attach only the scopes OpenIddict already validated. Without this, scope claims
            // won't appear in the token and resource servers can't enforce them.
            // OAuth 2.0 scopes — RFC 6749 §3.3: https://datatracker.ietf.org/doc/html/rfc6749#section-3.3
            principal.SetScopes(request.GetScopes());

            // SignIn triggers OpenIddict's response writer: serializes the principal into a signed
            // JWT and writes the token response (access_token, token_type, expires_in, scope).
            // OAuth 2.0 token response — RFC 6749 §5.1: https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
            return Results.SignIn(principal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        // ── Authorization Code / Refresh Token ───────────────────────────────────────────
        // User-facing flows. OpenIddict has already validated the code or refresh token.
        // The principal stored during the /connect/authorize step is recovered via Authenticate.
        // RFC 6749 §4.1: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1
        // RFC 6749 §6:   https://datatracker.ietf.org/doc/html/rfc6749#section-6
        if (request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType())
        {
            // This Authenticate call retrieves the principal that was sealed inside the auth
            // code or refresh token by OpenIddict. It does NOT make a network call.
            var result = await httpCtx.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            var principal = result.Principal
                ?? throw new InvalidOperationException("The authenticated principal cannot be retrieved.");

            var userId = principal.GetClaim(OpenIddictConstants.Claims.Subject)
                ?? throw new InvalidOperationException("The subject claim is missing from the token principal.");

            // Confirm the user still exists. If someone was deleted after the auth code was
            // issued we must reject rather than issue a token for a ghost account.
            var user = await userManager.FindByIdAsync(userId);
            if (user is null)
            {
                return Results.Forbid(
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error]            = OpenIddictConstants.Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The token is no longer valid."
                    }),
                    authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
            }

            // Confirm the user is still allowed to sign in (not locked out, not disabled, etc.).
            if (!await signInManager.CanSignInAsync(user))
            {
                return Results.Forbid(
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error]            = OpenIddictConstants.Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The user is no longer allowed to sign in."
                    }),
                    authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
            }

            // Re-apply destination routing. The principal already carries the right claims
            // from the authorize step; we just ensure each claim knows which token(s) it goes into.
            foreach (var claim in principal.Claims)
                claim.SetDestinations(ClaimsHelper.GetDestinations(claim, principal));

            return Results.SignIn(principal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        throw new InvalidOperationException("The specified grant type is not supported.");
    }
}