using Microsoft.AspNetCore.Server.Kestrel.Https;
using Mitm.Net;

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.UseKestrel(options =>
{
    options.ListenAnyIP(8080, options =>
    {
        options
            .ProcessProxyConnects()
            .RelayConnectionsL4(remote => remote.Host != "httpbin.org");

        options.UseHttps(new HttpsConnectionAdapterOptions
        {
            ServerCertificateSelector = (_, serverName) => MitmCertificateStore.GetCertificate(serverName ?? "localhost")
        });
    });
});

builder.Services.AddHttpForwarder();

var app = builder.Build();

// The idea is that you can intercept requests as regular ASP.NET HTTP requests and work with all the usual features.
app.MapGet("/get", async context =>
{
    await context.Response.WriteAsync($"This is totally httpbin. Origin: {context.Connection.RemoteIpAddress}");
});

// Fallback: proxy everything else to the origin
app.MapForwarder("/{**catch-all}", "https://httpbin.org");

app.Run();