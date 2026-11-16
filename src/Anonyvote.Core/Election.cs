using System.Text.Json;
using System.Text.Json.Serialization;

namespace Anonyvote.Core;

/// <summary>Phase of the election. The phases are deliberately disjoint: the ballot box does
/// not open until registration has closed, and that is what makes it impossible to correlate
/// who registered with who voted by looking at timing.</summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum ElectionPhase
{
    /// <summary>Prepared but not open: neither registrations nor votes are accepted.</summary>
    Setup,
    /// <summary>Codes are exchanged for credentials. The ballot box rejects everything.</summary>
    Registration,
    /// <summary>Voting is open. The registrar rejects everything.</summary>
    Voting,
    /// <summary>Closed. No registration, no voting; what remains is publishing.</summary>
    Closed
}

public sealed record Candidate(int Id, string Name);

/// <summary>
/// How the election's private key is held: <paramref name="Threshold"/> of the
/// <paramref name="Trustees"/> shares are needed to reconstruct it. This goes in the public
/// manifest on purpose: a voter is entitled to know how many people it would take to decrypt
/// early.
/// </summary>
public sealed record KeyCustody(int Threshold, int Trustees);

/// <summary>
/// Public definition of the election. It is distributed as-is to voters and verifiers: it
/// contains no secrets.
/// </summary>
public sealed record ElectionManifest(
    string Id,
    string Name,
    IReadOnlyList<Candidate> Candidates,
    int MaxChoices,
    string RegistrarPublicKeyPem,
    string ElectionPublicKeyPem,
    KeyCustody? Custody = null)
{
    public static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public string ToJson() => JsonSerializer.Serialize(this, Json);

    public static ElectionManifest FromJson(string json) =>
        JsonSerializer.Deserialize<ElectionManifest>(json, Json)
        ?? throw new InvalidDataException("unreadable election manifest");

    public static ElectionManifest Load(string path) => FromJson(File.ReadAllText(path));
}
