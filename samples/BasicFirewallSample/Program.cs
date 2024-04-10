var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();

// Add the reverse proxy capability to the server
builder.Services.AddReverseProxy()
    // Initialise the reverse proxy from the "ReverseProxy" section of configuration
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    // Add the firewall capability to the reverse proxy
    .AddFirewall()
    // Initialise the firewall from the "ReverseProxy" section of configuration
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));

var app = builder.Build();

// Register the reverse proxy routes
app.MapReverseProxy(config =>
{
    // Register the firewall middleware
    config.UseFirewall();
});

app.Run();
