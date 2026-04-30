using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace StreamLineAuthZ.Data;

// Single DbContext that owns three table groups in one database and one migration history:
//   1. ASP.NET Core Identity  — AspNetUsers, AspNetRoles, AspNetUserClaims, etc.
//   2. OpenIddict             — OpenIddictApplications, Tokens, Authorizations, Scopes
//   3. Future app tables      — anything else we add over time
//
// IdentityDbContext<ApplicationUser> sets up the Identity schema.
// UseOpenIddict() tells EF Core to include OpenIddict's entity model alongside it.
//
// EF Core DbContext docs:
//   https://learn.microsoft.com/en-us/ef/core/dbcontext-configuration/
// Identity with EF Core:
//   https://learn.microsoft.com/en-us/aspnet/core/security/authentication/identity
public sealed class ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
    : IdentityDbContext<ApplicationUser>(options)
{
    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        base.OnConfiguring(optionsBuilder);
        // OpenIddict EF Core integration:
        //   https://documentation.openiddict.com/integrations/entity-framework-core
        optionsBuilder.UseOpenIddict();
    }
}