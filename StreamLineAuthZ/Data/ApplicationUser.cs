using Microsoft.AspNetCore.Identity;

namespace StreamLineAuthZ.Data;

// Extending IdentityUser gives us the full ASP.NET Core Identity feature set:
// password hashing, lockout, two-factor, email/phone confirmation, claims, roles, tokens.
//
// Keep this class lean — add only columns that belong to the auth server's own user record.
// Application-specific profile data (display name, avatar, preferences) lives in the
// downstream resource API's own database, not here. This server only cares about identity.
//
// IdentityUser already provides: Id, UserName, Email, PasswordHash, SecurityStamp,
// ConcurrencyStamp, PhoneNumber, TwoFactorEnabled, LockoutEnd, LockoutEnabled, AccessFailedCount.
public sealed class ApplicationUser : IdentityUser
{
}