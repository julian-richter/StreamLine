using OpenIddict.Abstractions;

namespace StreamLineAuthZ.Data.OpenIddict;

public static class ClientSeeder
{
    public static async Task SeedAsync(
        IOpenIddictApplicationManager applicationManager,
        CancellationToken cancellationToken = default)
    {
        await SeedWebClientAsync(applicationManager, cancellationToken);
        await SeedMachineClientAsync(applicationManager, cancellationToken);
    }

    // Machine-to-machine (M2M) confidential client using the Client Credentials flow.
    // Used by backend services or daemons that need to call the StreamLine API directly,
    // with no user involved. The secret is hashed by OpenIddict before storage — never stored in plaintext.
    //
    // Client Credentials grant — RFC 6749 Section 4.4: https://datatracker.ietf.org/doc/html/rfc6749#section-4.4
    // Confidential clients — RFC 6749 Section 2.1: https://datatracker.ietf.org/doc/html/rfc6749#section-2.1
    private static async Task SeedMachineClientAsync(
        IOpenIddictApplicationManager applicationManager,
        CancellationToken cancellationToken)
    {
        const string clientId = "streamline-m2m";

        if (await applicationManager.FindByClientIdAsync(clientId, cancellationToken) is not null)
            return;

        await applicationManager.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            // TODO: replace with a value from our secrets manager before shipping to production.
            // In dev, Aspire can inject this via environment variables or user secrets.
            ClientSecret = "m2m-dev-secret",
            DisplayName = "StreamLine M2M Service Client",
            ClientType = OpenIddictConstants.ClientTypes.Confidential,
            Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
                OpenIddictConstants.Permissions.Prefixes.Scope + "api"
            }
        }, cancellationToken);
    }

    // Browser-based SvelteKit frontend using Authorization Code + PKCE.
    private static async Task SeedWebClientAsync(
        IOpenIddictApplicationManager applicationManager,
        CancellationToken cancellationToken)
    {
        const string clientId = "streamline-client";

        // Idempotent guard: safe to call on every startup without duplicating data.
        if (await applicationManager.FindByClientIdAsync(clientId, cancellationToken) is not null)
        {
            return;
        }

        // This registers a PUBLIC client using the Authorization Code + PKCE flow.
        // That's the correct flow for a browser-based SvelteKit app, it runs on the user's
        // machine and cannot safely store a client_secret, so we use PKCE instead.
        //
        // NOTE: AllowAuthorizationCodeFlow() must be enabled in ServiceCollectionExtensions.cs
        //
        // Public vs confidential clients — RFC 6749 Section 2.1: https://datatracker.ietf.org/doc/html/rfc6749#section-2.1
        // Authorization Code flow — RFC 6749 Section 4.1: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1
        // PKCE — RFC 7636: https://datatracker.ietf.org/doc/html/rfc7636
        await applicationManager.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            DisplayName = "StreamLine SvelteKit Client",

            // Explicit consent means the user sees a "grant access" screen before the token
            // is issued. For a first-party app you'd use ConsentTypes.Implicit to skip the screen.
            // OpenID Connect consent: https://openid.net/specs/openid-connect-core-1_0.html#Consent
            ConsentType = OpenIddictConstants.ConsentTypes.Explicit,

            // After a successful login the auth server redirects the user back to this URI
            // with the authorization code. Must be an exact match — no wildcards.
            // RFC 6749 Section 3.1.2: https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2
            RedirectUris =
            {
                new Uri("http://localhost:5173/callback")
            },

            // After logout the user is sent here. Lock these down in production.
            PostLogoutRedirectUris =
            {
                new Uri("http://localhost:5173/")
            },

            // OpenIddict is deny-by-default — every capability a client needs must be explicitly
            // granted here or requests for it will be rejected before your code ever runs.
            Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Authorization, // can hit /connect/authorize
                OpenIddictConstants.Permissions.Endpoints.Token,          // can hit /connect/token
                OpenIddictConstants.Permissions.Endpoints.EndSession,     // can hit /connect/logout

                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode, // can use auth code flow
                OpenIddictConstants.Permissions.ResponseTypes.Code,           // can request response_type=code

                // Scopes this client is allowed to request. The "api" scope was seeded by ScopeSeeder.
                OpenIddictConstants.Permissions.Prefixes.Scope + OpenIddictConstants.Scopes.OpenId,
                OpenIddictConstants.Permissions.Prefixes.Scope + OpenIddictConstants.Scopes.Profile,
                OpenIddictConstants.Permissions.Prefixes.Scope + "api"
            },

            // Enforces PKCE for this client. Without it, a stolen auth code could be exchanged
            // for a token by any party. With PKCE, only the original requester can complete the flow.
            // RFC 7636: https://datatracker.ietf.org/doc/html/rfc7636
            Requirements =
            {
                OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange
            }
        }, cancellationToken);
    }
}