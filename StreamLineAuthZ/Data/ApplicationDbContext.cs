using Microsoft.EntityFrameworkCore;

namespace StreamLineAuthZ.Data;

// The single DbContext for this application. It owns both our own tables (when we add them)
// and OpenIddict's tables (Applications, Tokens, Authorizations, Scopes).
// Keeping them in one context means one database, one migration history, one connection pool.
//
// `sealed` means nobody can subclass this. Good. DbContext inheritance hierarchies are a trap.
//
// EF Core DbContext docs:
//   https://learn.microsoft.com/en-us/ef/core/dbcontext-configuration/
public sealed class ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : DbContext(options)
{ 
    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        base.OnConfiguring(optionsBuilder);
        // OpenIddict EF Core integration:
        //   https://documentation.openiddict.com/integrations/entity-framework-core
        optionsBuilder.UseOpenIddict();
    }
}