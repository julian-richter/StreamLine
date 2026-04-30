using Microsoft.AspNetCore.Identity;

namespace StreamLineAuthZ.Data.OpenIddict;

public static class UserSeeder
{
    public static async Task SeedAsync(
        UserManager<ApplicationUser> userManager,
        CancellationToken cancellationToken = default)
    {
        await SeedDevUserAsync(userManager, cancellationToken);
    }

    // Development-only user for testing the Authorization Code flow locally.
    // NEVER seed hardcoded credentials in production — provision real users through
    // a registration flow or an admin tool.
    private static async Task SeedDevUserAsync(
        UserManager<ApplicationUser> userManager,
        CancellationToken cancellationToken)
    {
        const string email = "dev@streamline.local";

        if (await userManager.FindByEmailAsync(email) is not null)
            return;

        var user = new ApplicationUser
        {
            UserName = email,
            Email    = email,
            EmailConfirmed = true
        };

        var result = await userManager.CreateAsync(user, password: "DevPassword1!");

        if (!result.Succeeded)
        {
            var errors = string.Join(", ", result.Errors.Select(e => e.Description));
            throw new InvalidOperationException($"Failed to seed dev user '{email}': {errors}");
        }
    }
}