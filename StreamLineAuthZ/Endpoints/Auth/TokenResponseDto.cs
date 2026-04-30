using System.ComponentModel;
using System.Text.Json.Serialization;

namespace StreamLineAuthZ.Endpoints.Auth;

// RFC 6749 Section 5.1 — Successful Response
// https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
public sealed record TokenResponseDto
{
    [JsonPropertyName("access_token")]
    [Description("The issued JWT access token. Pass this as a Bearer token in the Authorization header of API requests.")]
    public required string AccessToken { get; init; }

    [JsonPropertyName("token_type")]
    [Description("Always 'Bearer'. Use as the scheme prefix in the Authorization header.")]
    public required string TokenType { get; init; }

    [JsonPropertyName("expires_in")]
    [Description("Lifetime of the access token in seconds from the time of issuance.")]
    public required int ExpiresIn { get; init; }

    [JsonPropertyName("scope")]
    [Description("Space-separated list of scopes actually granted. May be a subset of what was requested.")]
    public string? Scope { get; init; }

    [JsonPropertyName("refresh_token")]
    [Description("Issued when the refresh_token scope was included and the client is eligible. Exchange this for a new access token when the current one expires.")]
    public string? RefreshToken { get; init; }

    [JsonPropertyName("id_token")]
    [Description("OIDC ID token. Only present when the openid scope was requested and granted.")]
    public string? IdToken { get; init; }
}