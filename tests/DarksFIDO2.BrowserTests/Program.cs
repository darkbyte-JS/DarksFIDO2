using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Microsoft.Playwright;

int port = ReserveLoopbackPort();
string origin = $"http://localhost:{port}";
using var listener = new HttpListener();
listener.Prefixes.Add(origin + "/");
listener.Start();
using var serverCancellation = new CancellationTokenSource();
Task server = ServeAsync(listener, serverCancellation.Token);

using IPlaywright playwright = await Playwright.CreateAsync();
await using IBrowser browser = await playwright.Chromium.LaunchAsync(new BrowserTypeLaunchOptions
{
    Channel = "msedge",
    Headless = true
});
IBrowserContext context = await browser.NewContextAsync();
IPage page = await context.NewPageAsync();
ICDPSession cdp = await context.NewCDPSessionAsync(page);
string? authenticatorId = null;

try
{
    await cdp.SendAsync("WebAuthn.enable", new Dictionary<string, object> { ["enableUI"] = false });
    JsonElement? added = await cdp.SendAsync("WebAuthn.addVirtualAuthenticator", new Dictionary<string, object>
    {
        ["options"] = new Dictionary<string, object>
        {
            ["protocol"] = "ctap2",
            ["transport"] = "internal",
            ["hasResidentKey"] = true,
            ["hasUserVerification"] = true,
            ["isUserVerified"] = true,
            ["automaticPresenceSimulation"] = true
        }
    });
    authenticatorId = added?.GetProperty("authenticatorId").GetString()
        ?? throw new InvalidOperationException("Chromium did not create the virtual authenticator.");

    await page.GotoAsync(origin, new PageGotoOptions { WaitUntil = WaitUntilState.DOMContentLoaded });
    JsonElement? ceremony = await page.EvaluateAsync<JsonElement>("runWebAuthnCeremony()");
    if (ceremony is null ||
        ceremony.Value.GetProperty("createdType").GetString() != "public-key" ||
        ceremony.Value.GetProperty("assertedType").GetString() != "public-key" ||
        ceremony.Value.GetProperty("credentialId").GetString() is not { Length: > 20 })
        throw new InvalidOperationException("The browser did not complete a create/get WebAuthn ceremony.");

    JsonElement? credentials = await cdp.SendAsync("WebAuthn.getCredentials", new Dictionary<string, object>
    {
        ["authenticatorId"] = authenticatorId
    });
    if (credentials is null || credentials.Value.GetProperty("credentials").GetArrayLength() != 1)
        throw new InvalidOperationException("The virtual authenticator did not retain exactly one credential.");

    Console.WriteLine("PASS  Browser WebAuthn create/get ceremony with required user verification");
    return 0;
}
finally
{
    if (authenticatorId is not null)
    {
        try
        {
            await cdp.SendAsync("WebAuthn.removeVirtualAuthenticator", new Dictionary<string, object>
            {
                ["authenticatorId"] = authenticatorId
            });
        }
        catch { }
    }
    try { await cdp.SendAsync("WebAuthn.disable"); } catch { }
    serverCancellation.Cancel();
    listener.Stop();
    try { await server; } catch (OperationCanceledException) { }
}

static int ReserveLoopbackPort()
{
    var socket = new TcpListener(IPAddress.Loopback, 0);
    socket.Start();
    int port = ((IPEndPoint)socket.LocalEndpoint).Port;
    socket.Stop();
    return port;
}

static async Task ServeAsync(HttpListener listener, CancellationToken cancellationToken)
{
    const string html = """
        <!doctype html>
        <html lang="en">
        <meta charset="utf-8">
        <title>DarksFIDO2 WebAuthn integration test</title>
        <script>
        window.runWebAuthnCeremony = async () => {
          const challenge = crypto.getRandomValues(new Uint8Array(32));
          const userId = crypto.getRandomValues(new Uint8Array(16));
          const created = await navigator.credentials.create({
            publicKey: {
              challenge,
              rp: { id: "localhost", name: "DarksFIDO2 browser test" },
              user: { id: userId, name: "browser-test", displayName: "Browser test" },
              pubKeyCredParams: [{ type: "public-key", alg: -7 }],
              authenticatorSelection: {
                authenticatorAttachment: "platform",
                residentKey: "required",
                userVerification: "required"
              },
              timeout: 10000,
              attestation: "none"
            }
          });
          const asserted = await navigator.credentials.get({
            publicKey: {
              challenge: crypto.getRandomValues(new Uint8Array(32)),
              rpId: "localhost",
              allowCredentials: [{ type: "public-key", id: created.rawId }],
              userVerification: "required",
              timeout: 10000
            }
          });
          const id = btoa(String.fromCharCode(...new Uint8Array(created.rawId)))
            .replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
          return { createdType: created.type, assertedType: asserted.type, credentialId: id };
        };
        </script>
        """;
    byte[] body = Encoding.UTF8.GetBytes(html);
    while (!cancellationToken.IsCancellationRequested)
    {
        HttpListenerContext context;
        try { context = await listener.GetContextAsync().WaitAsync(cancellationToken); }
        catch (HttpListenerException) when (cancellationToken.IsCancellationRequested) { break; }
        context.Response.StatusCode = 200;
        context.Response.ContentType = "text/html; charset=utf-8";
        context.Response.ContentLength64 = body.Length;
        await context.Response.OutputStream.WriteAsync(body, cancellationToken);
        context.Response.Close();
    }
}
