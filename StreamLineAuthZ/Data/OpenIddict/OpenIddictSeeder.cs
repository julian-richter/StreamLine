using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;

namespace StreamLineAuthZ.Data.OpenIddict;

public static class OpenIddictSeeder
{
    public static async Task SeedAsync(IServiceProvider services, CancellationToken cancellationToken = default)
    {
        // CreateAsyncScope carves out a fresh DI scope. Never resolve scoped services
        // (like DbContext) from the root IServiceProvider — that's a lifetime leak.
        // https://learn.microsoft.com/en-us/dotnet/core/extensions/dependency-injection-guidelines#scoped-service-as-singleton
        await using var scope = services.CreateAsyncScope();

        var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        var applicationManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var scopeManager = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();

        // Apply pending EF Core migrations before seeding — the OpenIddict tables must exist first.
        // Safe to call on every startup; it's a no-op if the schema is already up to date.
        await dbContext.Database.MigrateAsync(cancellationToken);

        // Scopes before clients — ClientSeeder references the "api" scope by name,
        // so it must already exist when CreateAsync runs.
        await ScopeSeeder.SeedAsync(scopeManager, cancellationToken);
        await ClientSeeder.SeedAsync(applicationManager, cancellationToken);
    }
}