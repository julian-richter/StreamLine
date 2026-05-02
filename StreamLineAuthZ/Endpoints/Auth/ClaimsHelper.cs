using System.Security.Claims;
using OpenIddict.Abstractions;

namespace StreamLineAuthZ.Endpoints.Auth;

internal static class ClaimsHelper
{
    // Shared claim → destination routing used by both the authorize and token endpoints.
    // Claims without a destination are dropped by OpenIddict before the token is serialized,
    // so every claim must be mapped here — silence means the claim never reaches the client.
    //
    // Claim destinations — https://documentation.openiddict.com/configuration/claim-destinations
    internal static IEnumerable<string> GetDestinations(Claim claim, ClaimsPrincipal principal)
        => claim.Type switch
        {
            // name / preferred_username land in both tokens when the profile scope was granted.
            OpenIddictConstants.Claims.Name or OpenIddictConstants.Claims.PreferredUsername
                when principal.HasScope(OpenIddictConstants.Scopes.Profile)
                => [OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken],

            // email lands in both tokens when the email scope was granted.
            OpenIddictConstants.Claims.Email
                when principal.HasScope(OpenIddictConstants.Scopes.Email)
                => [OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken],

            // sub always appears in both tokens, it's the canonical principal identifier.
            OpenIddictConstants.Claims.Subject
                => [OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken],

            // Unknown claims are excluded from all tokens. Only claims explicitly mapped above
            // are emitted — this prevents Identity internals (SecurityStamp, etc.) leaking out.
            _ => []
        };
}