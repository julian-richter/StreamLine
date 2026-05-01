using GrpcManagementService.Services;

var builder = WebApplication.CreateBuilder(args);

builder.AddServiceDefaults();
builder.Services.AddGrpc();

var app = builder.Build();

app.MapDefaultEndpoints();
app.MapGrpcService<GreeterService>();
app.MapGet("/", () => "StreamLine gRPC Management Service — use a gRPC client to call endpoints.");

app.Run();