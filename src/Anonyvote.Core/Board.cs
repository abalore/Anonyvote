using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Anonyvote.Core;

/// <summary>
/// One entry on the board. It deliberately carries NO timestamp: the index already gives the
/// order, and an exact time would be precisely the metadata that would help re-link voter and
/// vote if someone cross-referenced the two services' records.
/// </summary>
public sealed record BoardEntry(
    long Index,
    string Nullifier,
    string Message,
    string Signature,
    string Ciphertext,
    string Hash)
{
    public byte[] MessageBytes => Convert.FromBase64String(Message);
    public byte[] SignatureBytes => Convert.FromBase64String(Signature);
    public byte[] CiphertextBytes => Convert.FromBase64String(Ciphertext);
    public byte[] NullifierBytes => Convert.FromHexString(Nullifier);
}

/// <summary>
/// The board's hash chain. The format is deliberately plain: anyone must be able to
/// reimplement it in any language to audit the published result.
///
///   H0 = SHA256( "anonyvote-board-v1:" || electionId )
///   Hi = SHA256( Hi-1 || u64be(index) || lp(nullifier) || lp(message) || lp(signature) || lp(ciphertext) )
///
/// where lp(x) = u32be(length(x)) || x. The length prefix stops two different entries from
/// ever collapsing into the same byte sequence.
/// </summary>
public static class HashChain
{
    public const string Domain = "anonyvote-board-v1:";

    public static byte[] Genesis(string electionId) =>
        SHA256.HashData(Encoding.UTF8.GetBytes(Domain + electionId));

    public static string GenesisHex(string electionId) => Hex(Genesis(electionId));

    public static byte[] Next(
        ReadOnlySpan<byte> previousHash,
        long index,
        ReadOnlySpan<byte> nullifier,
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> signature,
        ReadOnlySpan<byte> ciphertext)
    {
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        sha.AppendData(previousHash);

        Span<byte> number = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(number, index);
        sha.AppendData(number);

        AppendWithLength(sha, nullifier);
        AppendWithLength(sha, message);
        AppendWithLength(sha, signature);
        AppendWithLength(sha, ciphertext);

        return sha.GetHashAndReset();
    }

    public static string NextHex(
        string previousHashHex,
        long index,
        ReadOnlySpan<byte> nullifier,
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> signature,
        ReadOnlySpan<byte> ciphertext) =>
        Hex(Next(Convert.FromHexString(previousHashHex), index, nullifier, message, signature, ciphertext));

    private static void AppendWithLength(IncrementalHash sha, ReadOnlySpan<byte> data)
    {
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(length, (uint)data.Length);
        sha.AppendData(length);
        sha.AppendData(data);
    }

    public static string Hex(ReadOnlySpan<byte> bytes) => Convert.ToHexString(bytes).ToLowerInvariant();
}
