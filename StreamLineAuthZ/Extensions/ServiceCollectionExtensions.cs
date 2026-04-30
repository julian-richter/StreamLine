using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.EntityFrameworkCore;
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
        services.AddOpenApi();

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

        // Register ASP.NET Core authentication services.
        // IMPORTANT: do NOT set the OpenIddict server handler as the default scheme.
        // OpenIddict handles protocol endpoints like /connect/token, but it cannot be used
        // as the app-wide default authentication handler. That path leads directly to startup explosions.
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
                // Tells OpenIddict which URL to intercept as the token endpoint.
                // Must match the route registered in our token endpoint mapping.
                // This is what gets published in the discovery document so clients can find it.
                //
                // OAuth 2.0 token endpoint — RFC 6749 Section 3.2:
                // https://datatracker.ietf.org/doc/html/rfc6749#section-3.2
                options.SetTokenEndpointUris("/connect/token");

                // Enables the Client Credentials grant type.
                // OpenIddict is grant-type opt-in by default. If you don't explicitly allow a flow,
                // requests for it get rejected before they ever hit your handler. Beautiful. Ruthless. Correct.
                //
                // Client Credentials grant — RFC 6749 Section 4.4:
                // https://datatracker.ietf.org/doc/html/rfc6749#section-4.4
                options.AllowClientCredentialsFlow();

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
                // https://documentation.openiddict.com/guides/getting-started/creating-your-own-server-instance#passthrough-mode
                options.UseAspNetCore()
                    .EnableTokenEndpointPassthrough();
            });

        return services;
    }
}