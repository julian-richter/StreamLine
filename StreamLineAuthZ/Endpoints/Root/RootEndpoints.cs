using Scalar.AspNetCore;

namespace StreamLineAuthZ.Endpoints.Root;

public class RootEndpoints : IEndpoint
{
    public void MapEndpoint(IEndpointRouteBuilder app)
    {
        var env = app.ServiceProvider.GetRequiredService<IWebHostEnvironment>();
        var target = env.IsDevelopment() ? "/scalar/v1" : "/Account/Login";

        app.MapGet("/", () => Results.Redirect(target))
            .ExcludeFromDescription()
            .ExcludeFromApiReference();
    }
}