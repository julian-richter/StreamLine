using System.ComponentModel;
using System.Text.Json.Serialization;

namespace StreamLineAuthZ.Endpoints.Auth;

// Exists purely for OpenAPI schema generation. The actual request is parsed by OpenIddict's
// middleware before our handler runs — we never bind this DTO manually.
public sealed record TokenRequestDto
{
    [JsonPropertyName("grant_type")]
    [Description("The OAuth 2.0 grant type. Supported values: client_credentials, authorization_code, refresh_token.")]
    public required string GrantType { get; init; }

    [JsonPropertyName("client_id")]
    [Description("Client identifier. Required unless the client authenticates via HTTP Basic (Authorization header).")]
    public string? ClientId { get; init; }

    [JsonPropertyName("client_secret")]
    [Description("Client secret. Required for confidential clients that authenticate via the request body instead of HTTP Basic.")]
    public string? ClientSecret { get; init; }

    [JsonPropertyName("scope")]
    [Description("Space-separated list of requested scopes, e.g. 'api' or 'openid profile api'.")]
    public string? Scope { get; init; }

    [JsonPropertyName("code")]
    [Description("Authorization code received from /connect/authorize. Required for the authorization_code grant.")]
    public string? Code { get; init; }

    [JsonPropertyName("redirect_uri")]
    [Description("Must exactly match the redirect_uri used in the /connect/authorize request. Required for the authorization_code grant.")]
    public string? RedirectUri { get; init; }

    [JsonPropertyName("code_verifier")]
    [Description("PKCE code verifier. Required for public clients and any client registered with PKCE enforcement.")]
    public string? CodeVerifier { get; init; }

    [JsonPropertyName("refresh_token")]
    [Description("Refresh token to exchange for a new access token. Required for the refresh_token grant.")]
    public string? RefreshToken { get; init; }
}