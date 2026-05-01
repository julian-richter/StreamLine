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

        var descriptor = new OpenIddictApplicationDescriptor
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
        };

        var existing = await applicationManager.FindByClientIdAsync(clientId, cancellationToken);
        if (existing is null)
            await applicationManager.CreateAsync(descriptor, cancellationToken);
        else
            await applicationManager.UpdateAsync(existing, descriptor, cancellationToken);
    }

    // Browser-based SvelteKit frontend using Authorization Code + PKCE.
    private static async Task SeedWebClientAsync(
        IOpenIddictApplicationManager applicationManager,
        CancellationToken cancellationToken)
    {
        const string clientId = "streamline-client";

        // This registers a PUBLIC client using the Authorization Code + PKCE flow.
        // That's the correct flow for a browser-based SvelteKit app — it runs on the user's
        // machine and cannot safely store a client_secret, so we use PKCE instead.
        //
        // Public vs confidential clients — RFC 6749 Section 2.1: https://datatracker.ietf.org/doc/html/rfc6749#section-2.1
        // Authorization Code flow — RFC 6749 Section 4.1: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1
        // PKCE — RFC 7636: https://datatracker.ietf.org/doc/html/rfc7636
        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            DisplayName = "StreamLine Client",
            ClientType = OpenIddictConstants.ClientTypes.Public,

            // Explicit requires that a permanent authorization record exist before OpenIddict
            // will issue tokens. We satisfy this programmatically in AuthorizeEndpoint — the
            // first login auto-creates the record without showing a consent UI, because this is
            // a first-party app. ConsentTypes.Implicit would skip the authorization record entirely.
            // OpenID Connect consent: https://openid.net/specs/openid-connect-core-1_0.html#Consent
            ConsentType = OpenIddictConstants.ConsentTypes.Explicit,

            // After a successful login the auth server redirects the user back to this URI
            // with the authorization code. Must be an exact match — no wildcards.
            // RFC 6749 Section 3.1.2: https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2
            RedirectUris =
            {
                new Uri("http://localhost:5173/callback"),
                // Postman's OAuth2 helper redirect — allows "Get New Access Token" in the collection.
                new Uri("https://oauth.pstmn.io/v1/callback")
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
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken,      // can exchange refresh tokens
                OpenIddictConstants.Permissions.ResponseTypes.Code,           // can request response_type=code

                // Scopes this client is allowed to request.
                // offline_access is the OIDC scope that signals the server to issue a refresh token alongside
                // the access token. Defined in OpenID Connect Core §11:
                // https://openid.net/specs/openid-connect-core-1_0.html#OfflineAccess
                OpenIddictConstants.Permissions.Prefixes.Scope + OpenIddictConstants.Scopes.OpenId,
                OpenIddictConstants.Permissions.Prefixes.Scope + OpenIddictConstants.Scopes.Profile,
                OpenIddictConstants.Permissions.Prefixes.Scope + OpenIddictConstants.Scopes.Email,
                OpenIddictConstants.Permissions.Prefixes.Scope + OpenIddictConstants.Scopes.OfflineAccess,
                OpenIddictConstants.Permissions.Prefixes.Scope + "api"
            },

            // Enforces PKCE for this client. Without it, a stolen auth code could be exchanged
            // for a token by any party. With PKCE, only the original requester can complete the flow.
            // RFC 7636: https://datatracker.ietf.org/doc/html/rfc7636
            Requirements =
            {
                OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange
            }
        };

        var existing = await applicationManager.FindByClientIdAsync(clientId, cancellationToken);
        if (existing is null)
            await applicationManager.CreateAsync(descriptor, cancellationToken);
        else
            await applicationManager.UpdateAsync(existing, descriptor, cancellationToken);
    }
}