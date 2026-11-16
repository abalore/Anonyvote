using System.Threading.RateLimiting;
using Anonyvote.Core;
using Anonyvote.Core.Storage;
using Anonyvote.Crypto;

// ---------------------------------------------------------------------------
// BALLOT BOX — phase 2. Receives encrypted ballots from anonymous credentials.
//
// This service does NOT know who votes: there is no session, no account, no authentication
// header. Neither does it record IP addresses: doing so would destroy the system's main
// guarantee, because it would allow cross-referencing who asked for a credential with who
// cast a vote.
//
// Configuration (appsettings.json, environment variables or --key=value):
//   Anonyvote:Election            path to election.json
//   Anonyvote:Database            path to the board's SQLite file
//   Anonyvote:RateLimit:PerSecond requests per second allowed (0 = no limit)
//   Anonyvote:RateLimit:Queue     how many wait in line before rejection starts
//   Anonyvote:Results             path to the published results.json, once it exists
//   Anonyvote:SourceUrl           where this deployment's source can be obtained (AGPL s.13)
// ---------------------------------------------------------------------------

// ContentRoot next to the executable, so the web client is served the same way from any
// working directory, which is how system services start.
var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = args,
    ContentRootPath = AppContext.BaseDirectory
});

var config = builder.Configuration.GetSection("Anonyvote");
var electionPath = config["Election"] ?? "election.json";
if (!File.Exists(electionPath))
    throw new FileNotFoundException($"cannot find election.json at \"{electionPath}\"");

var election = ElectionManifest.Load(electionPath);
var registrarKey = KeyFiles.FromPublicPem(election.RegistrarPublicKeyPem);
var electionKey = KeyFiles.FromPublicPem(election.ElectionPublicKeyPem);
var databasePath = config["Database"] ?? "ballotbox.db";
var resultsPath = config["Results"];
var sourceUrl = config["SourceUrl"];

builder.Services.AddSingleton(election);
builder.Services.AddSingleton(_ => BallotBoxStore.Open(databasePath, election.Id));

// A ballot is a few hundred bytes; any larger body is junk or an attack.
builder.WebHost.ConfigureKestrel(options => options.Limits.MaxRequestBodySize = 16 * 1024);

// ---------------------------------------------------------------------------
// Rate limiting.
//
// The limit is GLOBAL, not per IP address, and that is a decision rather than an oversight:
// limiting per IP would mean keeping a map of live addresses inside the ballot box, which is
// exactly the data this service must not hold. What it buys is a bound on the total work an
// attacker can cause (signature verifications and writes), not an inability to try. Blocking
// one specific abuser is the job of whatever proxy or firewall sits in front, where the IPs
// are already visible anyway.
// ---------------------------------------------------------------------------
var perSecond = config.GetValue("RateLimit:PerSecond", 500);
var queued = config.GetValue("RateLimit:Queue", 200);

if (perSecond > 0)
{
    builder.Services.AddRateLimiter(options =>
    {
        options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(_ =>
            RateLimitPartition.GetFixedWindowLimiter("ballotbox", _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = perSecond,
                Window = TimeSpan.FromSeconds(1),
                QueueLimit = queued,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst
            }));

        options.OnRejected = async (context, cancellation) =>
        {
            context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
            context.HttpContext.Response.Headers.RetryAfter = "1";
            await context.HttpContext.Response.WriteAsJsonAsync(
                new ErrorResponse("the ballot box is saturated; try again in a few seconds"),
                cancellation);
        };
    });
}

var app = builder.Build();

if (perSecond > 0) app.UseRateLimiter();

app.UseDefaultFiles();
app.UseStaticFiles();

app.MapGet("/api/election", (ElectionManifest e, BallotBoxStore store) =>
    new ElectionInfo(e.Id, e.Name, e.Candidates, e.MaxChoices,
        e.RegistrarPublicKeyPem, e.ElectionPublicKeyPem, store.Phase, sourceUrl));

app.MapPost("/api/cast", (CastRequest request, BallotBoxStore store) =>
{
    if (store.Phase != ElectionPhase.Voting)
        return Results.BadRequest(new ErrorResponse(
            $"voting is not open (current phase: {store.Phase})"));

    byte[] message, signature, ciphertext;
    try
    {
        message = Convert.FromBase64String(request.Message);
        signature = Convert.FromBase64String(request.Signature);
        ciphertext = Convert.FromBase64String(request.Ciphertext);
    }
    catch (FormatException)
    {
        return Results.BadRequest(new ErrorResponse("badly encoded request"));
    }

    // Fixed lengths: no ballot can be told apart from another by its size, and requests that
    // do not even have the right shape are discarded without spending any cryptography.
    const int MessageLength = BlindRsa.RandomPrefixLength + 32;
    if (message.Length != MessageLength)
        return Results.BadRequest(new ErrorResponse($"the message must be {MessageLength} bytes long"));
    if (signature.Length != registrarKey.KeySize / 8)
        return Results.BadRequest(new ErrorResponse("signature of incorrect length"));
    if (ciphertext.Length != electionKey.KeySize / 8)
        return Results.BadRequest(new ErrorResponse("encrypted ballot of incorrect length"));

    // The only eligibility check that exists here: that the registrar signed the credential.
    // Who obtained it is, by design, impossible to know.
    if (!BlindRsa.Verify(registrarKey, message, signature))
        return Results.BadRequest(new ErrorResponse("invalid credential"));

    var outcome = store.Append(
        Nullifier.ComputeHex(message), request.Message, request.Signature, request.Ciphertext);

    if (outcome.Rejection == CastRejection.AlreadyVoted)
        return Results.Conflict(new ErrorResponse("this credential has already voted"));

    return Results.Ok(new CastResponse(outcome.Index, outcome.EntryHash, outcome.Head));
});

// The board is public throughout the vote: every voter checks that their ballot is in it. It
// stays unreadable until the election key is published.
app.MapGet("/api/board", (BallotBoxStore store, long from = 0, int limit = 500) =>
{
    var head = store.Head();
    return new BoardPage(head.Count, head.Head, store.Page(from, Math.Clamp(limit, 1, 2000)));
});

app.MapGet("/api/board/head", (BallotBoxStore store) => store.Head());

// The published results, served as-is. The ballot box does no counting and holds no private
// key: it hands over the file the organiser published and the results page recomputes the
// whole thing in the reader's browser. That is the point — the count must not depend on
// whoever runs this service.
app.MapGet("/api/results", () =>
    resultsPath is not null && File.Exists(resultsPath)
        ? Results.File(resultsPath, "application/json")
        : Results.NotFound(new ErrorResponse("the results have not been published yet")));

app.Run();
