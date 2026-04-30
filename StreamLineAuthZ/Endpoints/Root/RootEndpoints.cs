using Scalar.AspNetCore;

namespace StreamLineAuthZ.Endpoints.Root;

public class RootEndpoints : IEndpoint
{
    public void MapEndpoint(IEndpointRouteBuilder app)
    {
        app.MapGet("/", () => Results.Redirect("/scalar/v1"))
            .ExcludeFromDescription()
            .ExcludeFromApiReference();
    }
}