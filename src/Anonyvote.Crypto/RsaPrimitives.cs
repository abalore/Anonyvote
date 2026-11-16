using System.Numerics;
using System.Security.Cryptography;

namespace Anonyvote.Crypto;

/// <summary>Integer/octet-string conversions (RFC 8017 §4) and modular arithmetic.</summary>
internal static class RsaPrimitives
{
    /// <summary>OS2IP: big-endian octet string to non-negative integer.</summary>
    internal static BigInteger Os2Ip(ReadOnlySpan<byte> bytes) =>
        new(bytes, isUnsigned: true, isBigEndian: true);

    /// <summary>I2OSP: non-negative integer to fixed-length big-endian octet string.</summary>
    internal static byte[] I2Osp(BigInteger value, int length)
    {
        if (value.Sign < 0)
            throw new ArgumentOutOfRangeException(nameof(value), "I2OSP does not accept negative integers");

        var bytes = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        if (bytes.Length > length)
            throw new CryptographicException("integer does not fit in the requested length");
        if (bytes.Length == length)
            return bytes;

        var padded = new byte[length];
        bytes.CopyTo(padded.AsSpan(length - bytes.Length));
        return padded;
    }

    /// <summary>Modular inverse by the extended Euclidean algorithm. Throws if none exists.</summary>
    internal static BigInteger ModInverse(BigInteger a, BigInteger modulus)
    {
        var oldR = BigInteger.Remainder(a, modulus);
        if (oldR.Sign < 0) oldR += modulus;
        var r = modulus;
        BigInteger oldS = BigInteger.One, s = BigInteger.Zero;

        while (!r.IsZero)
        {
            var q = BigInteger.Divide(oldR, r);
            (oldR, r) = (r, oldR - q * r);
            (oldS, s) = (s, oldS - q * s);
        }

        if (!oldR.IsOne)
            throw new CryptographicException("no modular inverse exists");

        var result = BigInteger.Remainder(oldS, modulus);
        return result.Sign < 0 ? result + modulus : result;
    }

    /// <summary>Uniform random integer in [1, modulus-1] that is coprime with the modulus.</summary>
    internal static BigInteger RandomInvertible(BigInteger modulus, int byteLength)
    {
        var buffer = new byte[byteLength];
        while (true)
        {
            RandomNumberGenerator.Fill(buffer);
            var candidate = Os2Ip(buffer);
            if (candidate.IsZero || candidate >= modulus) continue;
            if (!BigInteger.GreatestCommonDivisor(candidate, modulus).IsOne) continue;
            return candidate;
        }
    }
}
