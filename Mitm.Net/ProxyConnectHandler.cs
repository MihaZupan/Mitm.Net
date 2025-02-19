using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using System.Buffers;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO.Pipelines;
using System.Net.Sockets;
using System.Text;

namespace Mitm.Net;

internal static class ProxyConnectHandler
{
    private const string ConnectionIdPrefix = "Mitm.Net";
    private static readonly ConcurrentDictionary<string, (string Host, int Port)> s_connections = new(StringComparer.Ordinal);
    private static ulong s_connectionCounter;

    public static IConnectionBuilder ProcessProxyConnects(this ListenOptions options) =>
        options.Use(next => connection => HandleProxyConnectAsync(next, connection));

    public static IConnectionBuilder RelayConnectionsL4(this IConnectionBuilder builder, Predicate<(string Host, int Port)> shouldRelay) =>
        builder.Use(next =>
        {
            var stoppingCts = new CancellationTokenSource();
            builder.ApplicationServices.GetRequiredService<IHostApplicationLifetime>().ApplicationStopping.Register(() => stoppingCts.Cancel());

            return connection =>
            {
                var remote = connection.GetProxyConnectRemoteHost();

                if (shouldRelay(remote))
                {
                    return RelayAsync(connection, remote.Host, remote.Port, stoppingCts.Token);
                }

                return next(connection);
            };
        });

    private static async Task HandleProxyConnectAsync(ConnectionDelegate next, ConnectionContext connection)
    {
        string? remoteHost;
        int remotePort;

        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

            string? remote = await TryParseConnectRequestAsync(connection, cts.Token);
            if (remote is null)
            {
                await connection.DisposeAsync();
                return;
            }

            int colonIndex = remote.IndexOf(':');
            remoteHost = colonIndex < 0 ? remote : remote[..colonIndex];
            remotePort = colonIndex < 0 ? 443 : ushort.Parse(remote[(colonIndex + 1)..]);

            //Console.WriteLine($"Remote: {remoteHost}:{remotePort}");

            await connection.Transport.Output.WriteAsync("HTTP/1.1 200 Connection established\r\nProxy-Agent: Mitm.Net\r\n\r\n"u8.ToArray(), cts.Token);
        }
        catch
        {
            await connection.DisposeAsync();
            return;
        }

        string connectionId = $"{ConnectionIdPrefix} {Interlocked.Increment(ref s_connectionCounter)}";
        connection.ConnectionId = connectionId;

        s_connections.TryAdd(connectionId, (remoteHost, remotePort));
        try
        {
            await next(connection);
        }
        finally
        {
            s_connections.TryRemove(connectionId, out _);
        }
    }

    private static async Task RelayAsync(ConnectionContext source, string host, int port, CancellationToken stoppingCt)
    {
        await using var _ = source;

        using var remoteSocket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await remoteSocket.ConnectAsync(host, port);
        }
        catch
        {
            return;
        }

        using var remoteStream = new NetworkStream(remoteSocket, ownsSocket: true);

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(source.ConnectionClosed, stoppingCt);

        Task one = source.Transport.Input.CopyToAsync(remoteStream, cts.Token);
        Task two = remoteStream.CopyToAsync(source.Transport.Output, cts.Token);

        Task first = await Task.WhenAny(one, two);
        if (first.IsCompletedSuccessfully)
        {
            if (first == one)
            {
                remoteSocket.Shutdown(SocketShutdown.Send);
            }
            else
            {
                await source.Transport.Output.CompleteAsync();
            }
        }
        else
        {
            cts.Cancel();
        }

        await one.ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);
        await two.ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);
    }

    private static async Task<string?> TryParseConnectRequestAsync(ConnectionContext connection, CancellationToken cancellationToken)
    {
        var input = connection.Transport.Input;

        while (true)
        {
            ReadResult result = await input.ReadAsync(cancellationToken);

            if (result.IsCanceled || result.IsCompleted)
            {
                return null;
            }

            if (TryParseHeaders(result.Buffer, out ReadOnlySequence<byte> advanceTo, out string? remoteHost))
            {
                input.AdvanceTo(advanceTo.Start);
                return remoteHost;
            }

            if (result.Buffer.Length > 64 * 1024)
            {
                return null;
            }

            input.AdvanceTo(result.Buffer.Start, result.Buffer.End);
        }

        static bool TryParseHeaders(in ReadOnlySequence<byte> buffer, out ReadOnlySequence<byte> advanceTo, out string? remoteHost)
        {
            var reader = new SequenceReader<byte>(buffer);

            if (reader.TryReadTo(out ReadOnlySequence<byte> headers, "\r\n\r\n"u8, advancePastDelimiter: true))
            {
                advanceTo = reader.UnreadSequence;

                var lines = Encoding.UTF8.GetString(headers).ReplaceLineEndings("\n").Split('\n');
                remoteHost = null;

                if (lines.Length >= 2 && lines[0].StartsWith("CONNECT ", StringComparison.OrdinalIgnoreCase))
                {
                    foreach (string line in lines)
                    {
                        if (line.StartsWith("Host:", StringComparison.OrdinalIgnoreCase))
                        {
                            remoteHost = line.AsSpan(5).Trim().ToString();
                            break;
                        }
                    }
                }

                return true;
            }

            advanceTo = default;
            remoteHost = null;
            return false;
        }
    }

    public static (string Host, int Port) GetProxyConnectRemoteHost(this ConnectionContext connection) =>
        GetProxyConnectRemoteHost(connection.ConnectionId);

    public static (string Host, int Port) GetProxyConnectRemoteHost(this HttpContext httpContext) =>
        GetProxyConnectRemoteHost(httpContext.Connection.Id);

    private static (string Host, int Port) GetProxyConnectRemoteHost(string connectionId)
    {
        if (s_connections.TryGetValue(connectionId, out var remote))
        {
            return remote;
        }

        if (!connectionId.StartsWith(ConnectionIdPrefix, StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"Connection '{connectionId}' was not handled by {nameof(ProxyConnectHandler)}.");
        }

        throw new UnreachableException($"Connection '{connectionId}' not found.");
    }
}
