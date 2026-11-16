using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Anonyvote.Admin;
using Anonyvote.Core;
using Anonyvote.Core.Storage;

// Numbers are printed the same way whatever locale the operator's machine has.
CultureInfo.DefaultThreadCurrentCulture = CultureInfo.InvariantCulture;

const string Usage = """
anonyvote-admin — the election organiser's tool

  init      --dir DIR --name "NAME" --candidates FILE [--max-choices 3] [--key-size 2048] [--id ID]
            [--trustees N --threshold K]
            Generates the keys and the public manifest of the election. With --trustees, the
            election's private key is NOT stored whole: it is split into N shares, K of which
            will be needed to open the ballot box.

  codes     --db REGISTRAR.db --count N [--out FILE]
            Generates N single-use codes. They are printed ONCE: the database only keeps
            their hashes. Hand them out off-band.

  phase     --db FILE.db --election ELECTION.json [--set registration|voting|closed] [--kind ballotbox|registrar]
            Shows or changes the phase. It has to be done on each service separately.

  publish   --ballotbox-db BALLOTBOX.db --election ELECTION.json
            (--key election-private.pem | --share share1.json --share share2.json ...)
            [--registrar-db REGISTRAR.db | --issued N --census M] --out results.json
            Publishes the whole board and the election's private key, so that anyone can
            count the votes for themselves.

Usual order:
  init  ->  codes  ->  phase --set registration  ->  (hand-out and registration)
        ->  phase --set voting (on both services)  ->  (voting)
        ->  phase --set closed  ->  publish
""";

try
{
    return args.Length == 0 ? Print(Usage) : args[0].ToLowerInvariant() switch
    {
        "init" => Init(new Args(args.Skip(1))),
        "codes" => Codes(new Args(args.Skip(1))),
        "phase" => Phase(new Args(args.Skip(1))),
        "publish" => Publish(new Args(args.Skip(1))),
        "-h" or "--help" or "help" => Print(Usage),
        var other => Fail($"unknown command: {other}\n\n{Usage}")
    };
}
catch (Exception ex)
{
    return Fail(ex.Message);
}

static int Print(string text) { Console.WriteLine(text); return 0; }
static int Fail(string text) { Console.Error.WriteLine($"error: {text}"); return 1; }

static int Init(Args a)
{
    var dir = a.Require("dir");
    var name = a.Require("name");
    var maxChoices = a.GetInt("max-choices", 3);
    var keySize = a.GetInt("key-size", 2048);

    var candidates = ReadCandidates(a.Require("candidates"));
    if (candidates.Count < 2)
        throw new ArgumentException("at least two candidates are required");
    if (maxChoices < 1 || maxChoices > candidates.Count)
        throw new ArgumentException($"--max-choices must be between 1 and {candidates.Count}");

    Directory.CreateDirectory(dir);
    var manifestPath = Path.Combine(dir, "election.json");
    if (File.Exists(manifestPath))
        throw new InvalidOperationException($"{manifestPath} already exists; an election is never overwritten");

    var id = a.Get("id") ?? $"{Slug(name)}-{Convert.ToHexString(RandomNumberGenerator.GetBytes(4)).ToLowerInvariant()}";

    Console.WriteLine($"Generating {keySize}-bit RSA keys...");
    using var registrarKey = RSA.Create(keySize);
    using var electionKey = RSA.Create(keySize);

    var registrarPem = Path.Combine(dir, "registrar-private.pem");
    KeyFiles.SavePrivate(registrarKey, registrarPem);

    var trustees = a.GetInt("trustees", 0);
    var threshold = a.GetInt("threshold", 0);
    KeyCustody? custody = null;
    string electionKeyLine;

    if (trustees > 0 || threshold > 0)
    {
        if (trustees < 1 || threshold < 1)
            throw new ArgumentException("--trustees and --threshold go together");
        if (threshold > trustees)
            throw new ArgumentException($"the threshold ({threshold}) cannot exceed the number of trustees ({trustees})");
        if (threshold == 1)
            Console.Error.WriteLine(
                "warning: with --threshold 1 every single share opens the ballot box on its own; custody is not actually split.");

        custody = new KeyCustody(threshold, trustees);
        electionKeyLine = SplitKey(dir, electionKey, id, threshold, trustees);
    }
    else
    {
        var electionPem = Path.Combine(dir, "election-private.pem");
        KeyFiles.SavePrivate(electionKey, electionPem);
        electionKeyLine = $"election key  {electionPem}         <- SECRET: held by the organiser until closing";
    }

    var election = new ElectionManifest(
        id, name, candidates, maxChoices,
        KeyFiles.PublicPem(registrarKey),
        KeyFiles.PublicPem(electionKey),
        custody);
    File.WriteAllText(manifestPath, election.ToJson());

    Console.WriteLine($"""

        Election "{name}" created.
          id            {id}
          candidates    {candidates.Count} (up to {maxChoices} are chosen)
          manifest      {manifestPath}          <- public: goes to both services and to verifiers
          signing key   {registrarPem}      <- SECRET: the Registrar only
          {electionKeyLine}

        If the signing key leaks, anyone can mint credentials and vote as many times as they
        like. Store it accordingly.
        """);
    return 0;
}

/// <summary>
/// Splits the election's private key into shares and stores the whole key nowhere: from this
/// point on, the threshold must be gathered to have it again.
/// </summary>
static string SplitKey(string dir, RSA electionKey, string id, int threshold, int trustees)
{
    var pkcs8 = electionKey.ExportPkcs8PrivateKey();
    try
    {
        var shares = Shamir.Split(pkcs8, trustees, threshold);

        for (int i = 0; i < shares.Count; i++)
        {
            var path = Path.Combine(dir, $"share-{i + 1}.json");
            var share = new KeyShare(id, i + 1, threshold, trustees,
                                     Convert.ToBase64String(shares[i]));
            File.WriteAllText(path, share.ToJson());
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }

        // Check before throwing the key away: if the shares do not reconstruct it, better to
        // find out now than on counting day.
        var probe = Shamir.Combine(
            Enumerable.Range(0, threshold).Select(i => (i + 1, shares[i])).ToList());
        if (!probe.SequenceEqual(pkcs8))
            throw new CryptographicException("the generated shares do not reconstruct the key");

        return $"election key  {trustees} shares in {dir}/share-N.json\n" +
               $"          <- SECRET: one per trustee, kept apart. {threshold} of them are needed\n" +
               $"             to open the ballot box; the whole key no longer exists anywhere.";
    }
    finally
    {
        CryptographicOperations.ZeroMemory(pkcs8);
    }
}

static int Codes(Args a)
{
    var count = a.RequireInt("count");
    if (count < 1) throw new ArgumentException("--count must be at least 1");

    using var store = RegistrarStore.Open(a.Require("db"));
    if (store.Phase is not (ElectionPhase.Setup or ElectionPhase.Registration))
        throw new InvalidOperationException($"the phase is {store.Phase}: the census can no longer be extended");

    var codes = new List<string>(count);
    var hashes = new List<string>(count);
    while (codes.Count < count)
    {
        var code = VotingCode.Generate();
        var hash = VotingCode.Hash(code);
        if (hashes.Contains(hash)) continue;
        codes.Add(code);
        hashes.Add(hash);
    }

    var added = store.AddCodeHashes(hashes);

    var output = a.Get("out");
    if (output is null)
    {
        foreach (var code in codes) Console.WriteLine(code);
    }
    else
    {
        File.WriteAllText(output, string.Join('\n', codes) + "\n");
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(output, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        Console.WriteLine($"{added} codes written to {output}");
    }

    Console.Error.WriteLine($"""

        Census: {store.CensusSize()} codes in total.
        These codes CANNOT be recovered: the database only keeps their hashes.
        """);
    return 0;
}

static int Phase(Args a)
{
    var path = a.Require("db");
    var election = ElectionManifest.Load(a.Require("election"));
    var wanted = a.Get("set");

    if (IsBallotBox(path, a.Get("kind")))
    {
        using var ballotBox = BallotBoxStore.Open(path, election.Id);
        if (wanted is not null) ballotBox.Phase = Parse(wanted);
        Console.WriteLine($"ballot box  {path}: phase {ballotBox.Phase}, {ballotBox.Head().Count} votes on the board");
    }
    else
    {
        using var registrar = RegistrarStore.Open(path);
        if (wanted is not null) registrar.Phase = Parse(wanted);
        Console.WriteLine($"registrar   {path}: phase {registrar.Phase}, " +
                          $"{registrar.IssuedCount()}/{registrar.CensusSize()} credentials issued");
    }
    return 0;

    static ElectionPhase Parse(string value) =>
        Enum.TryParse<ElectionPhase>(value, ignoreCase: true, out var phase)
            ? phase
            : throw new ArgumentException($"unknown phase: {value} (setup|registration|voting|closed)");
}

static int Publish(Args a)
{
    var election = ElectionManifest.Load(a.Require("election"));
    var output = a.Require("out");

    using var ballotBox = BallotBoxStore.Open(a.Require("ballotbox-db"), election.Id);
    if (ballotBox.Phase != ElectionPhase.Closed)
        throw new InvalidOperationException(
            $"the ballot box is in phase {ballotBox.Phase}: close it before publishing (phase --set closed)");

    long issued, census;
    if (a.Get("registrar-db") is string registrarPath)
    {
        using var registrar = RegistrarStore.Open(registrarPath);
        issued = registrar.IssuedCount();
        census = registrar.CensusSize();
    }
    else
    {
        issued = a.RequireInt("issued");
        census = a.RequireInt("census");
    }

    var privateKey = ResolvePrivateKey(a, election);
    var board = ballotBox.All();
    var published = new PublishedElection(election, census, issued, privateKey, board);
    File.WriteAllText(output, published.ToJson());

    var turnout = census == 0 ? 0 : 100.0 * board.Count / census;
    Console.WriteLine($"""
        Published to {output}
          census              {census} codes generated
          credentials issued  {issued}
          votes               {board.Count}  ({turnout:F1} % turnout)
          chain head          {ballotBox.Head().Head}

        Anyone can count the votes with:  anonyvote-verify {output}
        """);
    return 0;
}

/// <summary>
/// Obtains the election's private key, from a PEM file or by gathering shares, and checks it
/// really is the counterpart of the manifest's public key. Without that check, an organiser
/// could publish any old key and make the count unreadable.
/// </summary>
static string ResolvePrivateKey(Args a, ElectionManifest election)
{
    var sharePaths = a.GetAll("share");
    string pem;

    if (sharePaths.Count > 0)
    {
        var shares = sharePaths.Select(KeyShare.Load).ToList();

        foreach (var share in shares)
            if (share.ElectionId != election.Id)
                throw new InvalidOperationException(
                    $"share {share.Index} belongs to another election ({share.ElectionId})");

        var threshold = shares[0].Threshold;
        if (shares.Any(s => s.Threshold != threshold))
            throw new InvalidOperationException("the shares declare different thresholds");
        if (shares.Count < threshold)
            throw new InvalidOperationException(
                $"{threshold} shares are needed and only {shares.Count} were given");

        var reconstructed = Shamir.Combine(shares.Select(s => (s.Index, s.Bytes)).ToList());

        using var key = RSA.Create();
        try
        {
            key.ImportPkcs8PrivateKey(reconstructed, out _);
        }
        catch (CryptographicException)
        {
            throw new InvalidOperationException(
                "the shares do not reconstruct a valid key: one of them is altered or belongs to another split");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(reconstructed);
        }

        pem = key.ExportPkcs8PrivateKeyPem();
        Console.WriteLine($"Election key reconstructed from {shares.Count} shares (threshold {threshold}).");
    }
    else
    {
        pem = File.ReadAllText(a.Require("key"));
    }

    using var check = KeyFiles.FromPrivatePem(pem);
    if (KeyFiles.PublicPem(check).Trim() != election.ElectionPublicKeyPem.Trim())
        throw new InvalidOperationException(
            "the private key obtained does NOT match the election's public key");

    return pem;
}

static bool IsBallotBox(string path, string? kind)
{
    if (kind is not null)
        return kind.ToLowerInvariant() switch
        {
            "ballotbox" or "ballot-box" => true,
            "registrar" => false,
            _ => throw new ArgumentException($"unknown --kind: {kind} (ballotbox|registrar)")
        };

    if (!File.Exists(path))
        throw new FileNotFoundException(
            $"{path} does not exist; if it has not been created yet, pass --kind ballotbox|registrar");

    using var db = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={path};Mode=ReadOnly");
    db.Open();
    using var cmd = db.CreateCommand();
    cmd.CommandText = "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'entries'";
    return cmd.ExecuteScalar() is not null;
}

static List<Candidate> ReadCandidates(string path)
{
    var candidates = new List<Candidate>();
    foreach (var line in File.ReadAllLines(path))
    {
        var name = line.Trim();
        if (name.Length == 0 || name.StartsWith('#')) continue;
        candidates.Add(new Candidate(candidates.Count + 1, name));
    }
    return candidates;
}

static string Slug(string text)
{
    var sb = new StringBuilder();
    foreach (var c in text.Normalize(NormalizationForm.FormD))
    {
        if (char.IsLetterOrDigit(c) && c < 128) sb.Append(char.ToLowerInvariant(c));
        else if (char.IsWhiteSpace(c) && sb.Length > 0 && sb[^1] != '-') sb.Append('-');
    }
    return sb.ToString().Trim('-') is { Length: > 0 } s ? s : "election";
}
