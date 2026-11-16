using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Anonyvote.Core;

/// <summary>
/// Shamir secret sharing over GF(256), byte by byte.
///
/// Its job is to keep the election's private key out of any single pair of hands: it is split
/// into N shares and K of them are needed to put it back together. With K-1 shares you do not
/// get an approximation or a hint — you get noise, and that is provable rather than an
/// assumption about how expensive it would be to break.
///
/// GF(256) (the AES field) is used because each byte of the secret is shared separately:
/// shares are exactly as long as the secret and no arbitrary-precision arithmetic is needed.
/// </summary>
public static class Shamir
{
    public const int MaxShares = 255;   // abscissas run 1..255; 0 is the secret itself

    // --- GF(256) arithmetic, polynomial 0x11b ---

    private static byte Multiply(byte a, byte b)
    {
        byte result = 0;
        for (int i = 0; i < 8; i++)
        {
            // No data-dependent branches: not worth leaving a side channel here.
            result ^= (byte)(-(b & 1) & a);
            byte high = (byte)(-((a >> 7) & 1) & 0x1b);
            a = (byte)((a << 1) ^ high);
            b >>= 1;
        }
        return result;
    }

    private static byte Power(byte baseValue, int exponent)
    {
        byte result = 1;
        for (int i = 0; i < exponent; i++) result = Multiply(result, baseValue);
        return result;
    }

    /// <summary>Multiplicative inverse: a^254 = a^-1 in GF(256).</summary>
    private static byte Inverse(byte a) =>
        a == 0 ? throw new DivideByZeroException("0 has no inverse in GF(256)") : Power(a, 254);

    // --- Splitting and reconstruction ---

    /// <summary>Splits a secret into <paramref name="shares"/> shares, of which
    /// <paramref name="threshold"/> suffice to reconstruct it.</summary>
    public static IReadOnlyList<byte[]> Split(ReadOnlySpan<byte> secret, int shares, int threshold)
    {
        if (threshold < 1 || threshold > shares)
            throw new ArgumentException($"the threshold must be between 1 and {shares}", nameof(threshold));
        if (shares is < 1 or > MaxShares)
            throw new ArgumentException($"the number of shares must be between 1 and {MaxShares}", nameof(shares));
        if (secret.Length == 0)
            throw new ArgumentException("the secret is empty", nameof(secret));

        var output = new byte[shares][];
        for (int i = 0; i < shares; i++) output[i] = new byte[secret.Length];

        // One random polynomial per byte, with that byte of the secret as the constant term.
        var coefficients = new byte[threshold];
        for (int position = 0; position < secret.Length; position++)
        {
            RandomNumberGenerator.Fill(coefficients.AsSpan(1));
            coefficients[0] = secret[position];

            for (int i = 0; i < shares; i++)
                output[i][position] = Evaluate(coefficients, (byte)(i + 1));
        }

        CryptographicOperations.ZeroMemory(coefficients);
        return output;
    }

    /// <summary>Reconstructs the secret by Lagrange interpolation at x = 0.</summary>
    public static byte[] Combine(IReadOnlyList<(int X, byte[] Y)> shares)
    {
        if (shares.Count == 0) throw new ArgumentException("no shares were given", nameof(shares));

        var length = shares[0].Y.Length;
        if (shares.Any(s => s.Y.Length != length))
            throw new ArgumentException("the shares differ in length: they are not of the same secret", nameof(shares));
        if (shares.Any(s => s.X is < 1 or > MaxShares))
            throw new ArgumentException("share index out of range", nameof(shares));
        if (shares.Select(s => s.X).Distinct().Count() != shares.Count)
            throw new ArgumentException("two shares carry the same index", nameof(shares));

        var secret = new byte[length];
        for (int position = 0; position < length; position++)
        {
            byte accumulated = 0;
            for (int i = 0; i < shares.Count; i++)
            {
                // Lagrange coefficient at 0: prod x_m / (x_m - x_i); subtraction is XOR in GF(2^n).
                byte numerator = 1, denominator = 1;
                for (int m = 0; m < shares.Count; m++)
                {
                    if (m == i) continue;
                    numerator = Multiply(numerator, (byte)shares[m].X);
                    denominator = Multiply(denominator, (byte)(shares[m].X ^ shares[i].X));
                }
                accumulated ^= Multiply(shares[i].Y[position], Multiply(numerator, Inverse(denominator)));
            }
            secret[position] = accumulated;
        }

        return secret;
    }

    private static byte Evaluate(byte[] coefficients, byte x)
    {
        // Horner, from the highest degree down.
        byte result = 0;
        for (int i = coefficients.Length - 1; i >= 0; i--)
            result = (byte)(Multiply(result, x) ^ coefficients[i]);
        return result;
    }
}

/// <summary>
/// One share of the election's private key, as handed to a trustee. On its own it is useless:
/// <see cref="Threshold"/> distinct shares are required.
/// </summary>
public sealed record KeyShare(
    string ElectionId,
    int Index,
    int Threshold,
    int Trustees,
    string Share)
{
    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public byte[] Bytes => Convert.FromBase64String(Share);

    public string ToJson() => JsonSerializer.Serialize(this, Json);

    public static KeyShare Load(string path) =>
        JsonSerializer.Deserialize<KeyShare>(File.ReadAllText(path), Json)
        ?? throw new InvalidDataException($"unreadable share: {path}");
}
