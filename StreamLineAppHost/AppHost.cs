var builder = DistributedApplication.CreateBuilder(args);

var postgres = builder.AddPostgres("postgres")
    .WithDataVolume();

var appDb = postgres.AddDatabase("appdb");

var redis = builder.AddRedis("redis")
    .WithDataVolume()
    .WithRedisInsight();

var authzService = builder.AddProject<Projects.StreamLineAuthZ>("authz")
    .WithExternalHttpEndpoints()
    .WithReference(appDb)
    .WithReference(redis)
    .WaitFor(appDb)
    .WaitFor(redis);

// gRPC bridge between the management frontend and the auth server.
// Not externally exposed — only the SvelteKit server-side calls it.
var grpcManagement = builder.AddProject<Projects.GrpcManagementService>("grpc-management")
    .WithReference(appDb)
    .WithReference(authzService)
    .WaitFor(appDb)
    .WaitFor(authzService);

// SvelteKit admin frontend (adapter-node, Vite dev server in development).
// WithReference injects GRPC_MANAGEMENT_HTTP / GRPC_MANAGEMENT_HTTPS env vars
// so the SvelteKit server-side knows where to reach the gRPC service.
builder.AddViteApp("management", "../apps/management")
    .WithPnpm()
    .WithReference(grpcManagement)
    .WaitFor(grpcManagement)
    .WithExternalHttpEndpoints();

builder.Build().Run();