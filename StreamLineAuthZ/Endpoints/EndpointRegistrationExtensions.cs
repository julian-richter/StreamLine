using System.Reflection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace StreamLineAuthZ.Endpoints;

public static class EndpointRegistrationExtensions
{
    public static IServiceCollection AddEndpoints(this IServiceCollection services)
    {
        var endpointServiceDescriptors = Assembly.GetExecutingAssembly()
            .DefinedTypes
            .Where(type => type is { IsAbstract: false, IsInterface: false } &&
                           typeof(IEndpoint).IsAssignableFrom(type))
            .Select(type => ServiceDescriptor.Transient(typeof(IEndpoint), type))
            .ToArray();

        services.TryAddEnumerable(endpointServiceDescriptors);

        return services;
    }

    public static WebApplication MapEndpoints(this WebApplication app)
    {
        var endpoints = app.Services.GetRequiredService<IEnumerable<IEndpoint>>();

        foreach (var endpoint in endpoints)
        {
            // Every endpoint file registers itself
            endpoint.MapEndpoint(app);
        }

        return app;
    }
}