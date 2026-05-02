using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using MimeKit;
using StreamLineAuthZ.Data;

namespace StreamLineAuthZ.Infrastructure.Email;

public sealed class SmtpEmailSender(
    IOptions<SmtpSettings> options,
    IWebHostEnvironment env,
    ILogger<SmtpEmailSender> logger) : IEmailSender<ApplicationUser>
{
    private readonly SmtpSettings _settings = options.Value;

    public Task SendConfirmationLinkAsync(ApplicationUser user, string email, string confirmationLink)
        => SendAsync(email, "Confirm your StreamLine account",
            $"""
             <p>Thanks for signing up. Please confirm your email address to activate your account.</p>
             <p><a href="{confirmationLink}">Confirm my account</a></p>
             <p>If you did not create this account you can safely ignore this email.</p>
             """);

    public Task SendPasswordResetLinkAsync(ApplicationUser user, string email, string resetLink)
        => SendAsync(email, "Reset your StreamLine password",
            $"""
             <p>Click the link below to reset your password. This link expires in one hour.</p>
             <p><a href="{resetLink}">Reset my password</a></p>
             <p>If you did not request this, ignore this email.</p>
             """);

    public Task SendPasswordResetCodeAsync(ApplicationUser user, string email, string resetCode)
        => SendAsync(email, "Reset your StreamLine password",
            $"<p>Your password reset code is: <strong>{resetCode}</strong></p>");

    private async Task SendAsync(string to, string subject, string html)
    {
        if (!_settings.IsConfigured)
        {
            if (!env.IsDevelopment())
                throw new InvalidOperationException(
                    "Email is not configured. Set Email__Host, Email__Username, Email__Password, " +
                    "and Email__FromAddress in the environment.");

            logger.LogInformation("[DEV EMAIL] To: {To} | Subject: {Subject} | Body: {Body}",
                to, subject, html);
            return;
        }

        var message = new MimeMessage();
        message.From.Add(new MailboxAddress(_settings.FromName, _settings.FromAddress!));
        message.To.Add(MailboxAddress.Parse(to));
        message.Subject = subject;
        message.Body = new TextPart("html") { Text = html };

        using var client = new SmtpClient();
        await client.ConnectAsync(_settings.Host!, _settings.Port, SecureSocketOptions.StartTls);
        await client.AuthenticateAsync(_settings.Username!, _settings.Password!);
        await client.SendAsync(message);
        await client.DisconnectAsync(true);
    }
}