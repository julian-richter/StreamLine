using StreamLineAuthZ.Extensions;

var builder = WebApplication.CreateBuilder(args);

builder.AddServiceDefaults();
builder.Services.AddApplicationServices(builder.Configuration);
var app = builder.Build();
await app.UseApplicationPipelineAsync();

app.Run();