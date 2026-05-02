using OpenIddict.Abstractions;

namespace StreamLineAuthZ.Data.OpenIddict;

public static class ClientSeeder
{
    public static async Task SeedAsync(
        IOpenIddictApplicationManager applicationManager,
        IConfiguration configuration,
        IWebHostEnvironment environment,
        CancellationToken cancellationToken = default)
    {
        await SeedWebClientAsync(applicationManager, configuration, environment, cancellationToken);
        await SeedMachineClientAsync(applicationManager, configuration, environment, cancellationToken);
    }

    // Machine-to-machine (M2M) confidential client using the Client Credentials flow.
    // Used by backend services or daemons that need to call the StreamLine API directly,
    // with no user involved. The secret is hashed by OpenIddict before storage — never stored in plaintext.
    //
    // Client Credentials grant — RFC 6749 Section 4.4: https://datatracker.ietf.org/doc/html/rfc6749#section-4.4
    // Confidential clients — RFC 6749 Section 2.1: https://datatracker.ietf.org/doc/html/rfc6749#section-2.1
    private static async Task SeedMachineClientAsync(
        IOpenIddictApplicationManager applicationManager,
        IConfiguration configuration,
        IWebHostEnvironment environment,
        CancellationToken cancellationToken)
    {
        const string clientId = "streamline-m2m";

        // Read from config; fall back to a dev-only placeholder in development.
        // In production the app will refuse to start if this is not set.
        // Generate and store via:  openssl rand -base64 32
        // Set as:  OpenIddict__M2MClientSecret=<value>
        var clientSecret = configuration["OpenIddict:M2MClientSecret"];
        if (clientSecret is null)
        {
            if (!environment.IsDevelopment())
                throw new InvalidOperationException(
                    "OpenIddict:M2MClientSecret is not configured. " +
                    "Set it as the OpenIddict__M2MClientSecret environment variable.");

            clientSecret = "m2m-dev-secret";
        }

        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            ClientSecret = clientSecret,
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
        IConfiguration configuration,
        IWebHostEnvironment environment,
        CancellationToken cancellationToken)
    {
        const string clientId = "streamline-client";

        var (redirectUris, postLogoutUris) = ResolveWebClientUris(configuration, environment);

        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            DisplayName = "StreamLine Client",
            ClientType = OpenIddictConstants.ClientTypes.Public,
            ConsentType = OpenIddictConstants.ConsentTypes.Explicit,

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

        descriptor.RedirectUris.UnionWith(redirectUris);
        descriptor.PostLogoutRedirectUris.UnionWith(postLogoutUris);

        var existing = await applicationManager.FindByClientIdAsync(clientId, cancellationToken);
        if (existing is null)
            await applicationManager.CreateAsync(descriptor, cancellationToken);
        else
            await applicationManager.UpdateAsync(existing, descriptor, cancellationToken);
    }

    private static (IEnumerable<Uri> redirectUris, IEnumerable<Uri> postLogoutUris) ResolveWebClientUris(
        IConfiguration configuration,
        IWebHostEnvironment environment)
    {
        if (environment.IsDevelopment())
        {
            return (
                [
                    new Uri("http://localhost:5173/callback"),
                    new Uri("https://oauth.pstmn.io/v1/callback")
                ],
                [new Uri("http://localhost:5173/")]
            );
        }

        // Production URIs must be set explicitly via environment variables:
        //   OpenIddict__WebClientRedirectUris__0=https://app.example.com/callback
        //   OpenIddict__WebClientPostLogoutRedirectUris__0=https://app.example.com/
        var redirectUris = configuration
            .GetSection("OpenIddict:WebClientRedirectUris")
            .Get<string[]>();

        var postLogoutUris = configuration
            .GetSection("OpenIddict:WebClientPostLogoutRedirectUris")
            .Get<string[]>();

        if (redirectUris is not { Length: > 0 })
            throw new InvalidOperationException(
                "OpenIddict:WebClientRedirectUris is not configured. " +
                "Set OpenIddict__WebClientRedirectUris__0 (and optionally __1, __2, …).");

        if (postLogoutUris is not { Length: > 0 })
            throw new InvalidOperationException(
                "OpenIddict:WebClientPostLogoutRedirectUris is not configured. " +
                "Set OpenIddict__WebClientPostLogoutRedirectUris__0 (and optionally __1, __2, …).");

        return (
            redirectUris.Select(u => new Uri(u)),
            postLogoutUris.Select(u => new Uri(u))
        );
    }
}