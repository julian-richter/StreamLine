using Scalar.AspNetCore;
using StreamLineAuthZ.Endpoints;

namespace StreamLineAuthZ.Extensions;

public static class WebApplicationExtensions
{
    public static WebApplication UseApplicationPipeline(this WebApplication app)
    {
        app.MapDefaultEndpoints();

        if (app.Environment.IsDevelopment())
        {
            app.MapOpenApi();
            app.MapScalarApiReference();
        }

        app.UseHttpsRedirection();
        app.MapEndpoints();

        return app;
    }
}