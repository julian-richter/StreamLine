using StreamLineAuthZ.Endpoints;

namespace StreamLineAuthZ.Extensions;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddApplicationServices(this IServiceCollection services)
    {
        // this is the wiring hub meant to keep Program.cs clean
        services.AddOpenApi();
        services.AddEndpoints();

        return services;
    }
}