using Scalar.AspNetCore;
using StreamLineAuthZ.Data.OpenIddict;
using StreamLineAuthZ.Endpoints;

namespace StreamLineAuthZ.Extensions;

public static class WebApplicationExtensions
{
    // This is the HTTP request pipeline. Every request to this server runs through this
    // chain of middleware in the exact order you see below. ORDER IS NOT OPTIONAL.
    // Swapping two lines here can silently break auth, CORS, or HTTPS in ways that are
    // extremely annoying to debug. Read the ASP.NET Core middleware ordering docs and then
    // read them again.
    //
    // ASP.NET Core middleware pipeline overview:
    //   https://learn.microsoft.com/en-us/aspnet/core/fundamentals/middleware/
    // Recommended middleware ordering (bookmark this):
    //   https://learn.microsoft.com/en-us/aspnet/core/fundamentals/middleware/#middleware-order
    public static async Task<WebApplication> UseApplicationPipelineAsync(this WebApplication app)
    {
        // MUST be first. If this runs after anything that reads the request (like HTTPS redirect
        // or auth), those middlewares will see the proxy's IP and "http" scheme instead of the
        // real client values. ForwardedHeaders rewrites HttpContext so everything downstream
        // sees the correct RemoteIpAddress and Request.Scheme.
        //
        // This only takes effect because we called services.Configure<ForwardedHeadersOptions>
        // in ServiceCollectionExtensions.cs. The two calls are a pair — one registers the config,
        // this one activates it.
        //
        // ASP.NET Core reverse proxy docs:
        //   https://learn.microsoft.com/en-us/aspnet/core/host-and-deploy/proxy-load-balancer
        app.UseForwardedHeaders();

        // Maps ASP.NET Core's built-in health check and liveness endpoints.
        // These are used by container orchestrators (Kubernetes, Docker, AWS ECS) to determine
        // whether this instance is alive and ready to receive traffic.
        // Registered early so they respond even if the rest of the pipeline has issues.
        //
        // Health checks docs:
        //   https://learn.microsoft.com/en-us/aspnet/core/host-and-deploy/health-checks
        app.MapDefaultEndpoints();

        // Only expose the API explorer in development. We do NOT want Scalar
        // shipping to production, it advertises our entire API surface to the world
        // and is a free recon tool for anyone who finds it.
        //
        // MapOpenApi() serves the raw OpenAPI JSON spec at /openapi/v1.json.
        // MapScalarApiReference() serves the Scalar UI
        // that reads from that spec and gives us a clean interactive API browser.
        //
        // Scalar docs: https://scalar.com/
        // ASP.NET Core OpenAPI docs: https://learn.microsoft.com/en-us/aspnet/core/fundamentals/openapi/aspnetcore-openapi
        if (app.Environment.IsDevelopment())
        {
            app.MapOpenApi();
            app.MapScalarApiReference();
        }

        // Redirects all plain HTTP requests to HTTPS. Comes after ForwardedHeaders so the
        // redirect check sees the correct scheme that was rewritten above, not the proxy's
        // internal "http". If you put this before ForwardedHeaders, every proxied request
        // would get redirected in an infinite loop.
        //
        // HSTS (a related concept worth knowing which tells browsers to always use HTTPS for this domain):
        //   https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
        app.UseHttpsRedirection();

        // Applies the "default" CORS policy we defined in ServiceCollectionExtensions.cs.
        // CORS middleware MUST come before UseAuthentication and UseAuthorization.
        // Why: browsers send a preflight OPTIONS request before the real request. If auth
        // middleware runs first and rejects the OPTIONS request (because it has no token),
        // the browser never gets the CORS headers back and the actual request is blocked.
        //
        // CORS preflight explained:
        //   https://developer.mozilla.org/en-US/docs/Glossary/Preflight_request
        app.UseCors("default");

        // Runs the authentication middleware. This reads the incoming request, looks for a
        // bearer token (or cookie, or whatever scheme is configured), validates it, and if
        // valid, populates HttpContext.User with the caller's ClaimsPrincipal.
        //
        // If there's no token or the token is invalid, HttpContext.User is an anonymous
        // (unauthenticated) principal. Authentication does NOT reject the request, that's
        // authorization's job. These two are separate on purpose.
        //
        // Authentication vs Authorization (read this if you're confused about the difference):
        //   https://learn.microsoft.com/en-us/aspnet/core/security/authentication/
        app.UseAuthentication();

        // Runs the authorization middleware. Checks whether the now-identified HttpContext.User
        // has permission to access the requested endpoint. This MUST come after UseAuthentication
        // because it needs a populated HttpContext.User to make any decisions.
        //
        // If you flip these two, [Authorize] attributes will always see an anonymous user
        // and reject every request. Classic ASP.NET Core beginner trap.
        //
        // Authorization docs:
        //   https://learn.microsoft.com/en-us/aspnet/core/security/authorization/introduction
        app.UseAuthorization();

        // Scans the assembly for all IEndpoint implementations and calls MapEndpoint on each.
        // This is our custom convention that replaces registering every route manually in Program.cs.
        // At this point in the pipeline the request has been authenticated and authorized,
        // so endpoint handlers can safely read HttpContext.User.
        app.MapEndpoints();
        app.MapRazorPages();

        await OpenIddictSeeder.SeedAsync(app.Services);

        return app;
    }
}