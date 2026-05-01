using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.StackExchangeRedis;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi;
using OpenIddict.Abstractions;
using OpenIddict.Validation.AspNetCore;
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
        IConfiguration configuration,
        IWebHostEnvironment environment)
    {
        services.AddOpenApi(options =>
        {
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

        services.AddEndpoints();

        // CORS — open to any origin in development, locked to configured origins in production.
        // Browsers enforce this; non-browser clients (curl, Postman, backends) are unaffected.
        //
        // In production set Cors:AllowedOrigins in app config (appsettings, env vars, secrets manager).
        // MDN CORS explainer: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
        services.AddCors(options =>
        {
            options.AddPolicy("default", policy =>
            {
                if (environment.IsDevelopment())
                {
                    policy.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod();
                }
                else
                {
                    var origins = configuration.GetSection("Cors:AllowedOrigins").Get<string[]>()
                        ?? throw new InvalidOperationException(
                            "Cors:AllowedOrigins must be configured for production. " +
                            "Set it in appsettings.Production.json or as an environment variable.");
                    policy.WithOrigins(origins).AllowAnyHeader().AllowAnyMethod();
                }
            });
        });

        services.Configure<ForwardedHeadersOptions>(options =>
        {
            options.ForwardedHeaders =
                ForwardedHeaders.XForwardedFor |
                ForwardedHeaders.XForwardedProto;
        });

        services.AddDbContext<ApplicationDbContext>(options =>
        {
            var connectionString = configuration.GetConnectionString("appdb")
                                   ?? throw new InvalidOperationException("Connection string `appdb` was not found");

            options.UseNpgsql(connectionString);
            options.UseOpenIddict();
        });

        services.AddIdentity<ApplicationUser, IdentityRole>(options =>
            {
                if (environment.IsDevelopment())
                {
                    // Relaxed for local development — easy to test with short passwords.
                    options.Password.RequireDigit           = false;
                    options.Password.RequireLowercase       = false;
                    options.Password.RequireUppercase       = false;
                    options.Password.RequireNonAlphanumeric = false;
                    options.Password.RequiredLength         = 8;
                }
                else
                {
                    // Production defaults — ASP.NET Core Identity ships with these values;
                    // raising the length to 12 is the only change we make on top.
                    options.Password.RequireDigit           = true;
                    options.Password.RequireLowercase       = true;
                    options.Password.RequireUppercase       = true;
                    options.Password.RequireNonAlphanumeric = true;
                    options.Password.RequiredLength         = 12;
                }

                options.User.RequireUniqueEmail = true;
            })
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddDefaultTokenProviders();

        services.AddAuthentication();

        // Authorization — "api" policy requires a valid bearer token issued by this server.
        // API endpoints call .RequireAuthorization("api") to use it.
        // The explicit scheme prevents the cookie authentication handler (used for the login
        // page) from running on bearer-token endpoints and vice versa.
        services.AddAuthorizationBuilder()
            .AddPolicy("api", policy =>
            {
                policy.AddAuthenticationSchemes(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);
                policy.RequireAuthenticatedUser();
            });

        services.AddDataProtection()
            .SetApplicationName("StreamLineAuthZ");

        services.AddOptions<KeyManagementOptions>()
            .Configure<IConnectionMultiplexer>((opts, redis) =>
                opts.XmlRepository = new RedisXmlRepository(() => redis.GetDatabase(), "StreamLine-DataProtection-Keys"));

        services.AddRazorPages();

        services.AddOpenIddict()
            .AddCore(options =>
            {
                options.UseEntityFrameworkCore()
                    .UseDbContext<ApplicationDbContext>();
            })

            .AddServer(options =>
            {
                options.SetTokenEndpointUris("/connect/token");
                options.SetAuthorizationEndpointUris("/connect/authorize");
                options.SetEndSessionEndpointUris("/connect/logout");

                options.RegisterScopes(
                    OpenIddictConstants.Scopes.OpenId,
                    OpenIddictConstants.Scopes.Profile,
                    OpenIddictConstants.Scopes.Email,
                    OpenIddictConstants.Scopes.OfflineAccess,
                    "api");

                options.AllowClientCredentialsFlow();
                options.AllowAuthorizationCodeFlow();
                options.AllowRefreshTokenFlow();

                if (environment.IsDevelopment())
                {
                    // Self-signed ephemeral certificates — valid for local development only.
                    // They change on every restart, which breaks tokens issued before the restart.
                    // Fine for dev; catastrophic for production.
                    options.AddDevelopmentEncryptionCertificate();
                    options.AddDevelopmentSigningCertificate();
                }
                else
                {
                    // Production: load real certificates from a certificate store, .pfx file,
                    // Azure Key Vault, or a secrets manager. The dev certificates above MUST NOT
                    // be used in production — they are not trusted by any client and change on restart.
                    //
                    // Example (X.509 from file):
                    //   options.AddEncryptionCertificate(certificate);
                    //   options.AddSigningCertificate(certificate);
                    //
                    // See: https://documentation.openiddict.com/configuration/encryption-and-signing-credentials
                    throw new InvalidOperationException(
                        "Production signing and encryption certificates are not configured. " +
                        "See ServiceCollectionExtensions.cs for instructions.");
                }

                options.UseAspNetCore()
                    .EnableTokenEndpointPassthrough()
                    .EnableAuthorizationEndpointPassthrough()
                    .EnableEndSessionEndpointPassthrough();
            })

            // Validates bearer tokens on protected API endpoints within this same application.
            // UseLocalServer() reads the signing keys and issuer from the OpenIddict server above —
            // no remote discovery call needed because the auth server and resource server are the same process.
            //
            // OpenIddict validation docs:
            // https://documentation.openiddict.com/guides/getting-started/creating-your-own-server-instance
            .AddValidation(options =>
            {
                options.UseLocalServer();
                options.UseAspNetCore();
            });

        return services;
    }
}