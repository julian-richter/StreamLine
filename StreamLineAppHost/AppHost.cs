var builder = DistributedApplication.CreateBuilder(args);

var postgres = builder.AddPostgres("postgres")
    .WithDataVolume();

var appDb = postgres.AddDatabase("appdb");

var redis = builder.AddRedis("redis")
    .WithDataVolume()
    .WithRedisInsight();

builder.AddProject<Projects.StreamLineAuthZ>("authz")
    .WithExternalHttpEndpoints()
    .WithReference(appDb)
    .WithReference(redis)
    .WaitFor(appDb)
    .WaitFor(redis);

builder.Build().Run();