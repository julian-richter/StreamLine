using OpenIddict.Abstractions;

namespace StreamLineAuthZ.Data.OpenIddict;

public static class ScopeSeeder
{
    public static async Task SeedAsync(
        IOpenIddictScopeManager scopeManager,
        CancellationToken cancellationToken = default)
    {
        const string scopeName = "api";

        var descriptor = new OpenIddictScopeDescriptor
        {
            Name = scopeName,         // what clients request:  scope=api
            DisplayName = "StreamLine API",
            Resources =
            {
                // The audience value OpenIddict stamps into the `aud` claim of any token
                // that includes this scope. Resource servers validate this to confirm the
                // token was actually intended for them.
                // JWT `aud` claim — RFC 7519 Section 4.1.3: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
                "streamline-api"
            }
        };

        var existing = await scopeManager.FindByNameAsync(scopeName, cancellationToken);
        if (existing is null)
            await scopeManager.CreateAsync(descriptor, cancellationToken);
        else
            await scopeManager.UpdateAsync(existing, descriptor, cancellationToken);
    }
}