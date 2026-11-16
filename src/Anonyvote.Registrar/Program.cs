using System.Security.Cryptography;
using Anonyvote.Core;
using Anonyvote.Core.Storage;
using Anonyvote.Crypto;

// ---------------------------------------------------------------------------
// REGISTRAR — phase 1. Exchanges census codes for anonymous credentials.
//
// This service knows WHO registers (it holds the census) but cannot know WHICH credential it
// hands out: all it ever sees is the blinded message. And it knows nothing at all about the
// votes, which go to another service, another database and preferably another machine.
//
// Configuration (appsettings.json, environment variables or --key=value):
//   Anonyvote:Election    path to election.json
//   Anonyvote:PrivateKey  path to registrar-private.pem
//   Anonyvote:Database    path to the census SQLite file
//   Anonyvote:SourceUrl   where this deployment's source can be obtained (AGPL s.13)
// ---------------------------------------------------------------------------

// ContentRoot next to the executable, so the web client is served the same way from any
// working directory, which is how system services start.
var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = args,
    ContentRootPath = AppContext.BaseDirectory
});

var config = builder.Configuration.GetSection("Anonyvote");
var election = ElectionManifest.Load(PathOf(config, "Election", "election.json"));
var signingKey = KeyFiles.LoadPrivate(PathOf(config, "PrivateKey", "registrar-private.pem"));
var databasePath = config["Database"] ?? "registrar.db";
var sourceUrl = config["SourceUrl"];

builder.Services.AddSingleton(election);
builder.Services.AddSingleton(signingKey);
builder.Services.AddSingleton(_ => RegistrarStore.Open(databasePath));

var app = builder.Build();

app.UseDefaultFiles();
app.UseStaticFiles();

app.MapGet("/api/election", (ElectionManifest e, RegistrarStore store) =>
    new ElectionInfo(e.Id, e.Name, e.Candidates, e.MaxChoices,
        e.RegistrarPublicKeyPem, e.ElectionPublicKeyPem, store.Phase, sourceUrl));

app.MapPost("/api/register", (RegisterRequest request, RSA key, RegistrarStore store) =>
{
    if (store.Phase != ElectionPhase.Registration)
        return Results.BadRequest(new ErrorResponse(
            $"registration is not open (current phase: {store.Phase})"));

    if (!VotingCode.LooksValid(request.Code))
        return Results.BadRequest(new ErrorResponse("the code is not in the expected format"));

    byte[] blinded;
    try
    {
        blinded = Convert.FromBase64String(request.BlindedMessage);
    }
    catch (FormatException)
    {
        return Results.BadRequest(new ErrorResponse("badly encoded blinded message"));
    }

    if (blinded.Length != key.KeySize / 8)
        return Results.BadRequest(new ErrorResponse("blinded message of incorrect length"));

    // The code is spent first and only then signed. The other way round, a failure between the
    // two steps would leave a live code with a credential already issued, which is a double
    // vote. That is why every input check happens BEFORE this line.
    if (!store.TryConsumeCode(VotingCode.Hash(request.Code)))
        return Results.BadRequest(new ErrorResponse("invalid or already used code"));

    var blindSignature = BlindRsa.BlindSign(key, blinded);
    return Results.Ok(new RegisterResponse(Convert.ToBase64String(blindSignature)));
});

app.Run();

static string PathOf(IConfiguration config, string key, string fallback)
{
    var path = config[key] ?? fallback;
    if (!File.Exists(path))
        throw new FileNotFoundException($"cannot find {key} at \"{path}\"");
    return path;
}
