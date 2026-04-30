using System.ComponentModel;
using System.Text.Json.Serialization;

namespace StreamLineAuthZ.Endpoints.Auth;

// RFC 6749 Section 5.2 — Error Response
// https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
//
// Common error codes returned by the token endpoint:
//   invalid_request       — missing or malformed parameter
//   invalid_client        — client authentication failed (bad client_id or secret)
//   invalid_grant         — code/refresh token is invalid, expired, or already used
//   unauthorized_client   — client is not allowed to use this grant type
//   unsupported_grant_type — grant_type is not supported by this server
//   invalid_scope         — requested scope is invalid or not allowed for this client
public sealed record OAuthErrorResponseDto
{
    [JsonPropertyName("error")]
    [Description("OAuth 2.0 error code. Common values: invalid_request, invalid_client, invalid_grant, unauthorized_client, unsupported_grant_type, invalid_scope.")]
    public required string Error { get; init; }

    [JsonPropertyName("error_description")]
    [Description("Human-readable description of the error. Useful for debugging; do not display to end users.")]
    public string? ErrorDescription { get; init; }

    [JsonPropertyName("error_uri")]
    [Description("URI of a page with more information about the error.")]
    public string? ErrorUri { get; init; }
}