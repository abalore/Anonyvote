using System.Security.Cryptography;

namespace Anonyvote.Core;

/// <summary>
/// Nullifier: a credential's unique identifier, derived from the signed message. It is what
/// lets the ballot box detect a double vote without knowing whose credential it is.
/// </summary>
public static class Nullifier
{
    public static byte[] Compute(ReadOnlySpan<byte> preparedMessage) => SHA256.HashData(preparedMessage);

    public static string ComputeHex(ReadOnlySpan<byte> preparedMessage) =>
        Convert.ToHexString(Compute(preparedMessage)).ToLowerInvariant();
}
