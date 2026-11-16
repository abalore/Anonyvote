using System.Text.Json;
using System.Text.Json.Serialization;

namespace Anonyvote.Core;

/// <summary>
/// The package published at closing time: the manifest, the whole board, the size of the
/// census, how many credentials were issued and — this is the important part — the election's
/// private key.
///
/// The census size is published because without that figure there is no way to judge turnout,
/// nor to notice the registrar issuing credentials beyond it: a census that quietly grows is
/// the easiest fraud to hide.
///
/// Publishing the private key is deliberate: from that moment on, counting the votes requires
/// trusting nobody. Anyone can decrypt every ballot and count for themselves. Ballots carry no
/// identity, so once the box is closed there is nothing left to protect.
/// </summary>
public sealed record PublishedElection(
    ElectionManifest Election,
    long CensusSize,
    long IssuedCredentials,
    string ElectionPrivateKeyPem,
    IReadOnlyList<BoardEntry> Board)
{
    public static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public string ToJson() => JsonSerializer.Serialize(this, Json);

    public static PublishedElection Load(string path) =>
        JsonSerializer.Deserialize<PublishedElection>(File.ReadAllText(path), Json)
        ?? throw new InvalidDataException("unreadable results file");
}
