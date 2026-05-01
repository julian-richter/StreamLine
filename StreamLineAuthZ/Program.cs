using StreamLineAuthZ.Extensions;

var builder = WebApplication.CreateBuilder(args);

builder.AddServiceDefaults();
builder.AddRedisClient("redis");
builder.Services.AddApplicationServices(builder.Configuration, builder.Environment);
var app = builder.Build();
await app.UseApplicationPipelineAsync();

app.Run();