namespace StreamLineAuthZ.Infrastructure.Email;

public sealed class SmtpSettings
{
    public string? Host { get; init; }
    public int Port { get; init; } = 587;
    public string? Username { get; init; }
    public string? Password { get; init; }
    public string? FromAddress { get; init; }
    public string FromName { get; init; } = "StreamLine";

    public bool IsConfigured =>
        !string.IsNullOrEmpty(Host) &&
        !string.IsNullOrEmpty(Username) &&
        !string.IsNullOrEmpty(Password) &&
        !string.IsNullOrEmpty(FromAddress);
}