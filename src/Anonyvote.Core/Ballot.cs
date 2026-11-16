using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Anonyvote.Core;

/// <summary>
/// A ballot: up to <c>MaxChoices</c> candidates, unordered and without repeats. Blank ballots
/// (an empty list) and partial ballots (fewer choices than allowed) are both valid.
/// </summary>
public sealed record Ballot(IReadOnlyList<int> Choices)
{
    /// <summary>Deterministic encoding: sorted ids, so that two ballots with the same choices
    /// are byte-for-byte identical before encryption.</summary>
    public byte[] Encode() =>
        JsonSerializer.SerializeToUtf8Bytes(new { choices = Choices.Order().ToArray() });

    public static Ballot Decode(ReadOnlySpan<byte> bytes)
    {
        var doc = JsonSerializer.Deserialize<BallotDto>(bytes)
                  ?? throw new InvalidDataException("unreadable ballot");
        return new Ballot(doc.Choices ?? []);
    }

    private sealed record BallotDto([property: JsonPropertyName("choices")] int[]? Choices);

    /// <summary>Content validation. Returns null when the ballot is valid.</summary>
    public string? Validate(ElectionManifest election)
    {
        if (Choices.Count > election.MaxChoices)
            return $"the ballot carries {Choices.Count} choices and the maximum is {election.MaxChoices}";

        if (Choices.Distinct().Count() != Choices.Count)
            return "the ballot repeats a candidate";

        var valid = election.Candidates.Select(c => c.Id).ToHashSet();
        foreach (var id in Choices)
            if (!valid.Contains(id))
                return $"candidate {id} does not exist in this election";

        return null;
    }

    public bool IsBlank => Choices.Count == 0;
}

/// <summary>
/// Ballot encryption under the election's public key (RSA-OAEP-SHA256).
///
/// Its purpose is to keep the board public but unreadable while voting is open: without it
/// there would be partial results on display, which sway whoever has not voted yet. No nonce
/// is needed: OAEP is already randomized and the ciphertext is always the same size, so it
/// neither repeats nor leaks how long the vote is.
/// </summary>
public static class BallotCipher
{
    private static readonly RSAEncryptionPadding Padding = RSAEncryptionPadding.OaepSHA256;

    public static byte[] Encrypt(Ballot ballot, RSA electionPublicKey) =>
        electionPublicKey.Encrypt(ballot.Encode(), Padding);

    public static Ballot Decrypt(ReadOnlySpan<byte> ciphertext, RSA electionPrivateKey) =>
        Ballot.Decode(electionPrivateKey.Decrypt(ciphertext, Padding));
}
