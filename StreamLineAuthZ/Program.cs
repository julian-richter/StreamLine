using Azure.Identity;
using StreamLineAuthZ.Extensions;

var builder = WebApplication.CreateBuilder(args);

// When AzureKeyVaultUri is set the app loads secrets from Key Vault using Managed Identity.
// In Azure Container Apps assign a user-assigned or system-assigned identity and grant it
// the "Key Vault Secrets User" role on the vault. Locally, DefaultAzureCredential falls
// back to the Azure CLI / Visual Studio credential so no extra config is needed.
if (builder.Configuration["AzureKeyVaultUri"] is { } keyVaultUri)
    builder.Configuration.AddAzureKeyVault(new Uri(keyVaultUri), new DefaultAzureCredential());

builder.AddServiceDefaults();
builder.AddRedisClient("redis");
builder.Services.AddApplicationServices(builder.Configuration, builder.Environment);
var app = builder.Build();
await app.UseApplicationPipelineAsync();

app.Run();