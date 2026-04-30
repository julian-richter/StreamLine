using StreamLineAuthZ.Extensions;

var builder = WebApplication.CreateBuilder(args);

builder.AddServiceDefaults();
builder.Services.AddApplicationServices();
var app = builder.Build();
app.UseApplicationPipeline();

app.Run();