using System.Net;
using System.Net.Http.Json;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using Anonyvote.Core;
using Anonyvote.Crypto;

// ---------------------------------------------------------------------------
// SIMULATOR — synthetic voter.
//
// It does exactly what the browser will do, but by the thousand and against the real services
// over HTTP. It serves as the acceptance test and, along the way, as a second client
// implementation to check the browser's against.
// ---------------------------------------------------------------------------

const string Usage = """
    anonyvote-simulator register --registrar URL --codes FILE --out credentials.json
    anonyvote-simulator vote     --ballotbox URL --credentials credentials.json --out expected.json [--seed N]
    anonyvote-simulator attacks  --phase registration|voting --registrar URL --ballotbox URL
                                 --codes FILE --credentials credentials.json
    anonyvote-simulator flood    --ballotbox URL --count N
    """;

CultureInfo.DefaultThreadCurrentCulture = CultureInfo.InvariantCulture;

if (args.Length == 0) { Console.WriteLine(Usage); return 0; }

var options = Options(args.Skip(1));
using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };

try
{
    return args[0].ToLowerInvariant() switch
    {
        "register" => await Register(),
        "vote" => await Vote(),
        "attacks" => await Attacks(),
        "flood" => await Flood(),
        _ => Fail($"unknown command: {args[0]}\n{Usage}")
    };
}
catch (Exception ex)
{
    return Fail(ex.Message);
}

// --- Phase 1: exchange codes for credentials -------------------------------

async Task<int> Register()
{
    var baseUrl = options["registrar"].TrimEnd('/');
    var codes = File.ReadAllLines(options["codes"]).Where(l => l.Trim().Length > 0).ToList();
    var election = await Election(baseUrl);
    using var registrarKey = KeyFiles.FromPublicPem(election.RegistrarPublicKeyPem);

    var credentials = new List<Credential>(codes.Count);
    var stopwatch = System.Diagnostics.Stopwatch.StartNew();

    foreach (var code in codes)
    {
        // This is exactly what happens inside the voter's browser.
        var prepared = BlindRsa.Prepare(RandomNumberGenerator.GetBytes(32));
        var blinded = BlindRsa.Blind(registrarKey, prepared);

        var response = await http.PostAsJsonAsync($"{baseUrl}/api/register",
            new RegisterRequest(code, Convert.ToBase64String(blinded.Blinded)));

        if (!response.IsSuccessStatusCode)
            return Fail($"registration refused for one code: {await response.Content.ReadAsStringAsync()}");

        var body = await response.Content.ReadFromJsonAsync<RegisterResponse>()
                   ?? throw new InvalidDataException("empty response");

        var signature = BlindRsa.Finalize(registrarKey, prepared,
            Convert.FromBase64String(body.BlindSignature), blinded.Inverse);

        credentials.Add(new Credential(
            Convert.ToBase64String(prepared), Convert.ToBase64String(signature)));
    }

    File.WriteAllText(options["out"], JsonSerializer.Serialize(credentials));
    Console.WriteLine($"{credentials.Count} credentials obtained in {stopwatch.Elapsed.TotalSeconds:F1} s " +
                      $"({credentials.Count / Math.Max(0.001, stopwatch.Elapsed.TotalSeconds):F0}/s)");
    return 0;
}

// --- Phase 2: vote ----------------------------------------------------------

async Task<int> Vote()
{
    var baseUrl = options["ballotbox"].TrimEnd('/');
    var credentials = JsonSerializer.Deserialize<List<Credential>>(
        File.ReadAllText(options["credentials"]))!;
    var election = await Election(baseUrl);
    using var electionKey = KeyFiles.FromPublicPem(election.ElectionPublicKeyPem);

    var random = new Random(int.TryParse(options.GetValueOrDefault("seed"), out var s) ? s : 42);
    var expected = election.Candidates.ToDictionary(c => c.Id, _ => 0);
    int blank = 0;
    var receipts = new List<string>();
    var stopwatch = System.Diagnostics.Stopwatch.StartNew();

    foreach (var credential in credentials)
    {
        var choices = PickAtRandom(random, election, out var isBlank);
        var ballot = new Ballot(choices);

        var response = await http.PostAsJsonAsync($"{baseUrl}/api/cast", new CastRequest(
            credential.Message, credential.Signature,
            Convert.ToBase64String(BallotCipher.Encrypt(ballot, electionKey))));

        if (!response.IsSuccessStatusCode)
            return Fail($"vote refused: {await response.Content.ReadAsStringAsync()}");

        var receipt = await response.Content.ReadFromJsonAsync<CastResponse>()!;
        receipts.Add(receipt!.EntryHash);

        if (isBlank) blank++;
        else foreach (var id in choices) expected[id]++;
    }

    File.WriteAllText(options["out"], JsonSerializer.Serialize(new
    {
        tally = expected,
        blank,
        ballots = credentials.Count,
        receipt = receipts[^1]
    }, new JsonSerializerOptions { WriteIndented = true }));

    Console.WriteLine($"{credentials.Count} votes cast in {stopwatch.Elapsed.TotalSeconds:F1} s " +
                      $"({credentials.Count / Math.Max(0.001, stopwatch.Elapsed.TotalSeconds):F0}/s)");
    return 0;
}

// --- Fraud attempts the system must reject ----------------------------------

async Task<int> Attacks()
{
    var phase = options.GetValueOrDefault("phase", "voting").ToLowerInvariant();
    var registrar = options["registrar"].TrimEnd('/');
    var ballotBox = options["ballotbox"].TrimEnd('/');
    var election = await Election(ballotBox);
    using var registrarKey = KeyFiles.FromPublicPem(election.RegistrarPublicKeyPem);
    using var electionKey = KeyFiles.FromPublicPem(election.ElectionPublicKeyPem);

    var spentCode = File.ReadAllLines(options["codes"]).First(l => l.Trim().Length > 0);
    var credentials = JsonSerializer.Deserialize<List<Credential>>(
        File.ReadAllText(options["credentials"]))!;

    var failures = new List<string>();
    byte[] Encrypt(params int[] c) => BallotCipher.Encrypt(new Ballot(c), electionKey);

    // 1. Reuse a census code that has already been exchanged. Only meaningful during
    //    registration: afterwards the registrar rejects on phase, not on a spent code.
    if (phase == "registration")
    {
        var prepared = BlindRsa.Prepare(RandomNumberGenerator.GetBytes(32));
        var blinded = BlindRsa.Blind(registrarKey, prepared);
        await Expect("already used code", failures, HttpStatusCode.BadRequest,
            () => http.PostAsJsonAsync($"{registrar}/api/register",
                new RegisterRequest(spentCode, Convert.ToBase64String(blinded.Blinded))));

        return Report(failures);
    }

    // 2. Vote twice with the same credential.
    var used = credentials[0];
    await Expect("already spent credential", failures, HttpStatusCode.Conflict,
        () => http.PostAsJsonAsync($"{ballotBox}/api/cast",
            new CastRequest(used.Message, used.Signature, Convert.ToBase64String(Encrypt(1)))));

    // 3. A credential with a tampered signature.
    var brokenSignature = Convert.FromBase64String(used.Signature);
    brokenSignature[^1] ^= 0x01;
    var freshMessage = BlindRsa.Prepare(RandomNumberGenerator.GetBytes(32));
    await Expect("tampered signature", failures, HttpStatusCode.BadRequest,
        () => http.PostAsJsonAsync($"{ballotBox}/api/cast", new CastRequest(
            Convert.ToBase64String(freshMessage), Convert.ToBase64String(brokenSignature),
            Convert.ToBase64String(Encrypt(1)))));

    // 4. A credential minted without going through the registrar.
    using var forgedKey = RSA.Create(registrarKey.KeySize);
    var forgedPrepared = BlindRsa.Prepare(RandomNumberGenerator.GetBytes(32));
    var forgedBlinded = BlindRsa.Blind(forgedKey, forgedPrepared);
    var forgedSignature = BlindRsa.Finalize(forgedKey, forgedPrepared,
        BlindRsa.BlindSign(forgedKey, forgedBlinded.Blinded), forgedBlinded.Inverse);
    await Expect("credential from another key", failures, HttpStatusCode.BadRequest,
        () => http.PostAsJsonAsync($"{ballotBox}/api/cast", new CastRequest(
            Convert.ToBase64String(forgedPrepared), Convert.ToBase64String(forgedSignature),
            Convert.ToBase64String(Encrypt(2)))));

    return Report(failures);
}

async Task Expect(string name, List<string> failures, HttpStatusCode expected,
                  Func<Task<HttpResponseMessage>> request)
{
    var response = await request();
    if (response.StatusCode == expected)
        Console.WriteLine($"  correctly rejected: {name} ({(int)response.StatusCode})");
    else
        failures.Add($"{name}: expected {(int)expected} and got {(int)response.StatusCode}");
}

static int Report(List<string> failures)
{
    if (failures.Count == 0)
    {
        Console.WriteLine("  every fraud attempt was rejected.");
        return 0;
    }

    foreach (var failure in failures) Console.Error.WriteLine($"  - {failure}");
    return Fail($"{failures.Count} attack(s) were NOT rejected as expected");
}

// --- The ballot box's rate limiting ----------------------------------------

async Task<int> Flood()
{
    var ballotBox = options["ballotbox"].TrimEnd('/');
    var howMany = int.TryParse(options.GetValueOrDefault("count"), out var n) ? n : 40;

    // Requests with the right shape but useless content: what matters is that the ballot box
    // cuts them off BEFORE spending a signature verification on each one.
    var junk = new CastRequest(
        Convert.ToBase64String(new byte[64]),
        Convert.ToBase64String(new byte[256]),
        Convert.ToBase64String(new byte[256]));

    var responses = await Task.WhenAll(Enumerable.Range(0, howMany).Select(async _ =>
    {
        try { return (int)(await http.PostAsJsonAsync($"{ballotBox}/api/cast", junk)).StatusCode; }
        catch (HttpRequestException) { return 0; }
    }));

    var limited = responses.Count(c => c == 429);
    var served = responses.Count(c => c is not (429 or 0));

    Console.WriteLine($"  {howMany} requests at once -> {limited} rejected with 429, {served} served");

    if (limited == 0)
        return Fail("the ballot box served an entire flood without limiting anything");
    if (served == 0)
        return Fail("the ballot box rejected absolutely everything: the limit is set too low");

    return 0;
}

// --- Helpers ----------------------------------------------------------------

async Task<ElectionInfo> Election(string baseUrl) =>
    await http.GetFromJsonAsync<ElectionInfo>($"{baseUrl}/api/election")
    ?? throw new InvalidDataException("could not read the election");

static int[] PickAtRandom(Random random, ElectionInfo election, out bool isBlank)
{
    // 5 % blank, the rest between 1 and MaxChoices options: closer to a real vote than
    // everybody always ticking the maximum.
    if (random.NextDouble() < 0.05) { isBlank = true; return []; }

    isBlank = false;
    int howMany = random.Next(1, election.MaxChoices + 1);
    return election.Candidates.OrderBy(_ => random.Next()).Take(howMany).Select(c => c.Id).ToArray();
}

static Dictionary<string, string> Options(IEnumerable<string> args)
{
    var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    string? key = null;
    foreach (var arg in args)
    {
        if (arg.StartsWith("--", StringComparison.Ordinal)) key = arg[2..];
        else if (key is not null) { result[key] = arg; key = null; }
    }
    return result;
}

static int Fail(string message) { Console.Error.WriteLine($"error: {message}"); return 1; }

internal sealed record Credential(string Message, string Signature);
