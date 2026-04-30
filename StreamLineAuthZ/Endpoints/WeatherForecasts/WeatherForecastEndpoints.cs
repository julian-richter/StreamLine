namespace StreamLineAuthZ.Endpoints.WeatherForecasts;

public sealed class WeatherForecastEndpoints : IEndpoint
{
    private static readonly string[] Summaries =
    [
        "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Balmy", "Hot", "Sweltering", "Scorching"
    ];

    public void MapEndpoint(IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/weatherforecasts")
            .WithTags("Weather Forecasts");

        group.MapGet("/", GetWeatherForecasts)
            .WithName("GetWeatherForecasts")
            .WithSummary("Get a 5-day weather forecast.")
            .WithDescription("Returns five sample weather forecast entries. Development scaffolding — not part of the auth server contract.")
            .Produces<WeatherForecastDto[]>(StatusCodes.Status200OK);
    }

    private static WeatherForecastDto[] GetWeatherForecasts() =>
        Enumerable.Range(1, 5)
            .Select(index => new WeatherForecastDto(
                DateOnly.FromDateTime(DateTime.UtcNow.AddDays(index)),
                Random.Shared.Next(-20, 55),
                Summaries[Random.Shared.Next(Summaries.Length)]))
            .ToArray();
}