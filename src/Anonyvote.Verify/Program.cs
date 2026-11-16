using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using Anonyvote.Core;
using Anonyvote.Crypto;

// Numbers are printed the same way whatever locale the operator's machine has.
CultureInfo.DefaultThreadCurrentCulture = CultureInfo.InvariantCulture;

// ---------------------------------------------------------------------------
// VERIFIER — independent count.
//
// It talks to no service and trusts none: it works solely on the file published at closing
// time. Anyone can run it and get the same result; if that result disagrees with the one the
// organiser announces, the published file is its own evidence.
// ---------------------------------------------------------------------------

if (args.Length == 0 || args[0] is "-h" or "--help")
{
    Console.WriteLine("""
        anonyvote-verify RESULTS.json [--receipt ENTRY_HASH] [--json]

        Checks the hash chain, the signatures, the absence of double votes and the tally.
        With --receipt it also tells you whether your receipt is on the board.
        """);
    return 0;
}

var asJson = args.Contains("--json");
var published = PublishedElection.Load(args[0]);
var election = published.Election;
var board = published.Board;

using var registrarPublicKey = KeyFiles.FromPublicPem(election.RegistrarPublicKeyPem);
using var electionPrivateKey = KeyFiles.FromPrivatePem(published.ElectionPrivateKeyPem);

var custody = election.Custody is { } c
    ? $"split among {c.Trustees} trustees, threshold {c.Threshold}"
    : "in a single pair of hands (no threshold split)";

if (!asJson)
    Console.WriteLine($"""
        Election      {election.Name}  ({election.Id})
        Candidates    {election.Candidates.Count}, up to {election.MaxChoices} are chosen
        Census        {published.CensusSize} codes generated
        Credentials   {published.IssuedCredentials} issued
        Ballots       {board.Count}
        Election key  {custody}
        """);

var problems = new List<string>();

// 1. The published private key must be the election's: otherwise the count would be over
//    ballots other than the ones announced.
if (KeyFiles.PublicPem(electionPrivateKey).Trim() != election.ElectionPublicKeyPem.Trim())
    problems.Add("the published private key does NOT match the public key in the manifest");

// 2. Hash chain: any later alteration of an entry breaks it.
var hash = HashChain.GenesisHex(election.Id);
long expected = 0;
foreach (var entry in board)
{
    if (entry.Index != expected)
        problems.Add($"entry {expected}: the index jumps to {entry.Index}");

    hash = HashChain.NextHex(hash, entry.Index, entry.NullifierBytes,
                             entry.MessageBytes, entry.SignatureBytes, entry.CiphertextBytes);

    if (!hash.Equals(entry.Hash, StringComparison.OrdinalIgnoreCase))
    {
        problems.Add($"entry {entry.Index}: the hash chain does not match (tampered board)");
        hash = entry.Hash;   // carry on from where the board claims, so errors do not cascade
    }
    expected++;
}

// 3. Signatures and uniqueness: eligibility and one vote each, without knowing whose
//    credential is whose.
var nullifiers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
foreach (var entry in board)
{
    if (!BlindRsa.Verify(registrarPublicKey, entry.MessageBytes, entry.SignatureBytes))
        problems.Add($"entry {entry.Index}: credential not signed by the registrar");

    if (!Nullifier.ComputeHex(entry.MessageBytes).Equals(entry.Nullifier, StringComparison.OrdinalIgnoreCase))
        problems.Add($"entry {entry.Index}: the nullifier does not match the message");

    if (!nullifiers.Add(entry.Nullifier))
        problems.Add($"entry {entry.Index}: repeated credential (double vote)");
}

// 4. Census >= credentials >= votes. This is the chain of quantities that stops votes
//    appearing out of nowhere, and the reason the census is published.
if (board.Count > published.IssuedCredentials)
    problems.Add($"there are {board.Count} votes and only {published.IssuedCredentials} credentials issued");

if (published.IssuedCredentials > published.CensusSize)
    problems.Add($"{published.IssuedCredentials} credentials were issued against a census of " +
                 $"{published.CensusSize}: the registrar handed out more than it could");

// 5. The tally.
var tally = election.Candidates.ToDictionary(c => c.Id, _ => 0);
int blank = 0, spoilt = 0;
foreach (var entry in board)
{
    Ballot ballot;
    try
    {
        ballot = BallotCipher.Decrypt(entry.CiphertextBytes, electionPrivateKey);
    }
    catch (Exception)
    {
        spoilt++;
        continue;
    }

    if (ballot.Validate(election) is not null) { spoilt++; continue; }
    if (ballot.IsBlank) { blank++; continue; }

    foreach (var id in ballot.Choices) tally[id]++;
}

// Machine-readable output, for automated audits and for the simulation.
if (asJson)
{
    Console.WriteLine(JsonSerializer.Serialize(new
    {
        ok = problems.Count == 0,
        head = hash,
        ballots = board.Count,
        census = published.CensusSize,
        credentials = published.IssuedCredentials,
        custody = election.Custody,
        blank,
        spoilt,
        tally = tally.ToDictionary(kv => kv.Key.ToString(), kv => kv.Value),
        problems
    }, new JsonSerializerOptions { WriteIndented = true }));
    return problems.Count == 0 ? 0 : 1;
}

Console.WriteLine($"\nChain head  {hash}\n");

if (args.Length > 2 && args[1] == "--receipt")
{
    var receipt = args[2];
    var entry = board.FirstOrDefault(e => e.Hash.Equals(receipt, StringComparison.OrdinalIgnoreCase));
    Console.WriteLine(entry is null
        ? $"RECEIPT NOT FOUND: {receipt} is not on the board\n"
        : $"Receipt found: your ballot is number {entry.Index} on the board\n");
}

Console.WriteLine("TALLY");
Console.WriteLine(new string('-', 46));
foreach (var (candidate, votes) in election.Candidates
             .Select(c => (c, tally[c.Id]))
             .OrderByDescending(x => x.Item2).ThenBy(x => x.c.Name))
{
    var bar = new string('#', board.Count == 0 ? 0 : votes * 20 / Math.Max(1, board.Count));
    Console.WriteLine($"{candidate.Name,-24} {votes,6}  {bar}");
}
Console.WriteLine(new string('-', 46));
Console.WriteLine($"{"ballots",-24} {board.Count,6}");
Console.WriteLine($"{"blank",-24} {blank,6}");
if (spoilt > 0) Console.WriteLine($"{"spoilt",-24} {spoilt,6}");

var turnout = published.CensusSize == 0 ? 0 : 100.0 * board.Count / published.CensusSize;
Console.WriteLine($"{"turnout",-24} {turnout,5:F1} % of a census of {published.CensusSize}");

if (problems.Count == 0)
{
    Console.WriteLine("\nAll correct: chain intact, signatures valid, no double votes.");
    return 0;
}

Console.Error.WriteLine($"\n{problems.Count} PROBLEM(S) — this result cannot be trusted:");
foreach (var problem in problems.Take(50)) Console.Error.WriteLine($"  - {problem}");
if (problems.Count > 50) Console.Error.WriteLine($"  ... and {problems.Count - 50} more");
return 1;
