using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.StackExchangeRedis;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi;
using StackExchange.Redis;
using StreamLineAuthZ.Data;
using StreamLineAuthZ.Endpoints;

namespace StreamLineAuthZ.Extensions;

public static class ServiceCollectionExtensions
{
    // This extension method is the wiring hub for the entire application.
    // Everything that needs to be registered with the DI container lives here.
    // Keeps Program.cs from becoming a 300-line monster that nobody wants to read.
    public static IServiceCollection AddApplicationServices(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        // Registers the OpenAPI document generator. This is the built-in
        // Microsoft.AspNetCore.OpenApi package. Generates the spec at /openapi/v1.json.
        // Docs: https://learn.microsoft.com/en-us/aspnet/core/fundamentals/openapi/aspnetcore-openapi
        services.AddOpenApi(options =>
        {
            // Add the Authorization header to the token endpoint's OpenAPI operation.
            // Done here (not via the deprecated WithOpenApi on the endpoint) because .NET 10
            // replaced per-endpoint WithOpenApi(Func<>) with document-level operation transformers.
            // https://aka.ms/aspnet/deprecate/002
            options.AddOperationTransformer((operation, context, _) =>
            {
                if (context.Description.RelativePath == "connect/token" &&
                    string.Equals(context.Description.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
                {
                    (operation.Parameters ??= []).Add(new OpenApiParameter
                    {
                        Name = "Authorization",
                        In = ParameterLocation.Header,
                        Required = false,
                        Description = "HTTP Basic client authentication: `Basic base64(client_id:client_secret)`. " +
                                      "Alternative to supplying `client_id` and `client_secret` in the request body.",
                        Schema = new OpenApiSchema { Type = JsonSchemaType.String }
                    });
                }

                return Task.CompletedTask;
            });
        });

        // Scans the assembly for all types implementing IEndpoint and registers them.
        // This is our custom convention: see Endpoints/IEndpoint.cs and the endpoint
        // registration extensions. New endpoint class? Drop it in and let the machine cook.
        services.AddEndpoints();

        // CORS (Cross-Origin Resource Sharing) controls which browser origins can call our API.
        // Browsers enforce this; non-browser clients like curl, Postman, or backend services don't care.
        //
        // WARNING: AllowAnyOrigin + AllowAnyHeader + AllowAnyMethod is a wide-open dev policy.
        // Fine for local development. Absolutely not the move for production unless chaos is the goal.
        // TODO: lock this down before shipping. At minimum, restrict origins to your known frontend domain(s).
        //
        // MDN CORS explainer: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
        // RFC 6454 (The Web Origin Concept): https://datatracker.ietf.org/doc/html/rfc6454
        services.AddCors(options =>
        {
            options.AddPolicy("default", policy =>
            {
                policy
                    .AllowAnyOrigin()
                    .AllowAnyHeader()
                    .AllowAnyMethod();
            });
        });

        // When this app sits behind a reverse proxy (nginx, Traefik, AWS ALB, etc.),
        // the proxy terminates TLS and forwards the original client IP and protocol via headers.
        // Without this, HttpContext.Connection.RemoteIpAddress would be the proxy's IP,
        // and HttpContext.Request.Scheme could be wrong.
        //
        // X-Forwarded-For   -> the real client IP address
        // X-Forwarded-Proto -> the original scheme the client used (http or https)
        //
        // This matters for OAuth redirect URIs, issuer URLs, and audit logs.
        // RFC 7239 (Forwarded HTTP Extension): https://datatracker.ietf.org/doc/html/rfc7239
        // ASP.NET Core proxy docs: https://learn.microsoft.com/en-us/aspnet/core/host-and-deploy/proxy-load-balancer
        services.Configure<ForwardedHeadersOptions>(options =>
        {
            options.ForwardedHeaders =
                ForwardedHeaders.XForwardedFor |
                ForwardedHeaders.XForwardedProto;
        });

        // Register EF Core with the Npgsql (PostgreSQL) provider.
        // The connection string comes from configuration: appsettings, environment variables,
        // Aspire-injected config, or a secrets manager.
        //
        // We throw immediately if it's missing. Fail fast > mysterious runtime garbage later.
        //
        // UseOpenIddict() tells EF Core to include OpenIddict's entity model
        // (Applications, Tokens, Authorizations, Scopes) in this DbContext.
        // Without this, OpenIddict has nowhere to persist anything.
        //
        // Npgsql EF Core provider: https://www.npgsql.org/efcore/
        // OpenIddict EF Core integration: https://documentation.openiddict.com/integrations/entity-framework-core
        services.AddDbContext<ApplicationDbContext>(options =>
        {
            var connectionString = configuration.GetConnectionString("appdb")
                                   ?? throw new InvalidOperationException("Connection string `appdb` was not found");

            options.UseNpgsql(connectionString);
            options.UseOpenIddict();
        });

        // ASP.NET Core Identity — user store, password hashing, sign-in manager, lockout, etc.
        //
        // AddDefaultTokenProviders() registers the token providers Identity uses for email
        // confirmation and password-reset flows (not to be confused with OAuth tokens — those
        // are OpenIddict's domain).
        //
        // We do NOT call AddDefaultUI() here: that would scaffold Razor Pages Identity UI
        // into the project, but we're building our own login pages to keep full control.
        //
        // Identity docs: https://learn.microsoft.com/en-us/aspnet/core/security/authentication/identity
        services.AddIdentity<ApplicationUser, IdentityRole>(options =>
            {
                // Dev-friendly password policy — tighten before production.
                options.Password.RequireDigit           = false;
                options.Password.RequireLowercase       = false;
                options.Password.RequireUppercase       = false;
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequiredLength         = 8;

                // Require unique emails so we can use email as the login identifier.
                options.User.RequireUniqueEmail = true;
            })
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddDefaultTokenProviders();

        // Register ASP.NET Core authentication services.
        // IMPORTANT: do NOT set the OpenIddict server handler as the default scheme.
        // OpenIddict handles protocol endpoints like /connect/token, but it cannot be used
        // as the app-wide default authentication handler. That path leads directly to startup explosions.
        //
        // Identity's AddIdentity() call above already configures cookie authentication as the
        // default scheme, which is exactly what we need: the login page sets a cookie, the
        // /connect/authorize endpoint reads it to authenticate the user, then OpenIddict issues
        // the auth code. The two systems work together, not against each other.
        //
        // ASP.NET Core authentication overview:
        // https://learn.microsoft.com/en-us/aspnet/core/security/authentication/
        services.AddAuthentication();

        // Registers authorization services.
        // The token endpoint itself is usually anonymous, because that's where clients obtain tokens,
        // but protected APIs that consume those tokens will rely on this.
        //
        // ASP.NET Core authorization docs:
        // https://learn.microsoft.com/en-us/aspnet/core/security/authorization/introduction
        services.AddAuthorization();

        // Data Protection — persist encryption keys to Redis so they survive process restarts.
        //
        // Without this, ASP.NET Core generates a new key ring every time the process starts.
        // Any Identity cookies or anti-forgery tokens signed with the old keys become invalid,
        // which means active browser sessions are silently killed on every redeploy.
        //
        // SetApplicationName pins the key ring to a fixed name. If the name ever changes,
        // all previously issued cookies and tokens are immediately invalidated — treat it
        // like a primary key, not a display name.
        //
        // The key repository is configured via AddOptions so that IConnectionMultiplexer
        // resolves from DI at first use rather than at service-registration time. This keeps
        // ServiceCollectionExtensions free of direct Redis construction and plays nicely with
        // Aspire's builder.AddRedisClient("redis") registration in Program.cs.
        //
        // ASP.NET Core Data Protection docs:
        //   https://learn.microsoft.com/en-us/aspnet/core/security/data-protection/introduction
        services.AddDataProtection()
            .SetApplicationName("StreamLineAuthZ");

        services.AddOptions<KeyManagementOptions>()
            .Configure<IConnectionMultiplexer>((opts, redis) =>
                opts.XmlRepository = new RedisXmlRepository(() => redis.GetDatabase(), "StreamLine-DataProtection-Keys"));

        // Razor Pages powers the login page at /Account/Login.
        // We use a Razor Page instead of an inline HTML response to get tag helpers,
        // model binding, anti-forgery tokens, and validation summaries without boilerplate.
        services.AddRazorPages();

        services.AddOpenIddict()
            // Core wires up OpenIddict's managers and stores.
            // This is the engine room: applications, scopes, tokens, authorizations, the whole show.
            // We tell it to use EF Core backed by our ApplicationDbContext for persistence.
            //
            // OpenIddict architecture overview:
            // https://documentation.openiddict.com/guides/getting-started/creating-your-own-server-instance
            .AddCore(options =>
            {
                options.UseEntityFrameworkCore()
                    .UseDbContext<ApplicationDbContext>();
            })

            // Server wires up the actual OAuth/OpenID Connect endpoints and token issuing behavior.
            .AddServer(options =>
            {
                // Tells OpenIddict which URLs to intercept for each protocol endpoint.
                // These are published in the discovery document (/.well-known/openid-configuration)
                // so clients can find them without hardcoding. Must match the routes we register
                // in our endpoint classes.
                //
                // OAuth 2.0 endpoints — RFC 6749 Section 3:
                // https://datatracker.ietf.org/doc/html/rfc6749#section-3
                options.SetTokenEndpointUris("/connect/token");
                options.SetAuthorizationEndpointUris("/connect/authorize");
                options.SetEndSessionEndpointUris("/connect/logout");

                // Enables the Client Credentials grant type.
                // OpenIddict is grant-type opt-in by default. If you don't explicitly allow a flow,
                // requests for it get rejected before they ever hit your handler. Beautiful. Ruthless. Correct.
                //
                // Client Credentials grant — RFC 6749 Section 4.4:
                // https://datatracker.ietf.org/doc/html/rfc6749#section-4.4
                options.AllowClientCredentialsFlow();

                // Enables the Authorization Code grant type — the correct flow for browser-based apps.
                // The browser never sees the access token directly; instead it gets a short-lived code
                // that the server exchanges for a token. Combined with PKCE (enforced per-client in
                // the seeder via Requirements.Features.ProofKeyForCodeExchange), this is the gold standard
                // for interactive user-facing flows in 2024+.
                //
                // Authorization Code grant — RFC 6749 Section 4.1:
                // https://datatracker.ietf.org/doc/html/rfc6749#section-4.1
                options.AllowAuthorizationCodeFlow();

                // Enables the Refresh Token grant type.
                // After an access token expires, the client can exchange its refresh token for a new
                // access token without sending the user through the login flow again. The refresh token
                // is longer-lived and must be stored securely by the client.
                //
                // Refresh Token grant — RFC 6749 Section 6:
                // https://datatracker.ietf.org/doc/html/rfc6749#section-6
                options.AllowRefreshTokenFlow();

                // Development-only signing and encryption certificates.
                // Great for local work. Garbage for production.
                //
                // In production, replace these with real certificates from a certificate store,
                // .pfx file, HSM, or secrets manager.
                //
                // Signing cert  -> proves integrity
                // Encryption cert -> protects confidential payloads
                //
                // OpenIddict certificate configuration:
                // https://documentation.openiddict.com/configuration/encryption-and-signing-credentials
                options.AddDevelopmentEncryptionCertificate();
                options.AddDevelopmentSigningCertificate();

                // This enables ASP.NET Core passthrough mode for the token endpoint.
                //
                // By default, OpenIddict can handle token requests entirely by itself.
                // With passthrough enabled, OpenIddict still validates the incoming request first,
                // then lets the request continue into our Minimal API endpoint so we can build
                // the claims principal ourselves.
                //
                // Without this line: our token endpoint handler never runs.
                // With this line: we get full control after protocol validation. Absolute cinema.
                //
                // OpenIddict passthrough mode docs:
                // https://documentation.openiddict.com/guides/getting-started/creating-your-own-server-instance
                options.UseAspNetCore()
                    .EnableTokenEndpointPassthrough()
                    .EnableAuthorizationEndpointPassthrough()
                    .EnableEndSessionEndpointPassthrough();
            });

        return services;
    }
}