using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Anonyvote.Crypto;

/// <summary>
/// MGF1 and EMSA-PSS-ENCODE (RFC 8017 §B.2.1 and §9.1.1). The encoded message has to be built
/// by hand because .NET does not expose the raw RSA operation a blind signature needs.
/// VERIFICATION uses none of this: the resulting signature is an ordinary RSA-PSS signature
/// that .NET's own provider validates.
/// </summary>
internal static class Pss
{
    internal static int HashLength(HashAlgorithmName name) => name.Name switch
    {
        "SHA256" => 32,
        "SHA384" => 48,
        "SHA512" => 64,
        _ => throw new CryptographicException($"unsupported hash: {name.Name}")
    };

    private static void Hash(HashAlgorithmName name, ReadOnlySpan<byte> data, Span<byte> destination)
    {
        switch (name.Name)
        {
            case "SHA256": SHA256.HashData(data, destination); break;
            case "SHA384": SHA384.HashData(data, destination); break;
            case "SHA512": SHA512.HashData(data, destination); break;
            default: throw new CryptographicException($"unsupported hash: {name.Name}");
        }
    }

    /// <summary>MGF1: hash-based mask generation function.</summary>
    internal static byte[] Mgf1(ReadOnlySpan<byte> seed, int maskLength, HashAlgorithmName hashName)
    {
        if (maskLength < 0) throw new ArgumentOutOfRangeException(nameof(maskLength));

        int hLen = HashLength(hashName);
        var mask = new byte[maskLength];
        var block = new byte[seed.Length + 4];
        seed.CopyTo(block);
        Span<byte> digest = stackalloc byte[hLen];

        for (uint counter = 0, offset = 0; offset < maskLength; counter++)
        {
            BinaryPrimitives.WriteUInt32BigEndian(block.AsSpan(seed.Length), counter);
            Hash(hashName, block, digest);
            int take = Math.Min(hLen, maskLength - (int)offset);
            digest[..take].CopyTo(mask.AsSpan((int)offset));
            offset += (uint)take;
        }

        return mask;
    }

    /// <summary>
    /// EMSA-PSS-ENCODE. <paramref name="fixedSalt"/> is for test vectors only; in production
    /// the salt is generated at random.
    /// </summary>
    internal static byte[] Encode(
        ReadOnlySpan<byte> message,
        int emBits,
        int saltLength,
        HashAlgorithmName hashName,
        ReadOnlySpan<byte> fixedSalt = default)
    {
        int hLen = HashLength(hashName);
        int emLen = (emBits + 7) / 8;

        if (emLen < hLen + saltLength + 2)
            throw new CryptographicException("key too short for PSS with this salt length");

        Span<byte> mHash = stackalloc byte[hLen];
        Hash(hashName, message, mHash);

        byte[] salt;
        if (fixedSalt.IsEmpty)
        {
            salt = RandomNumberGenerator.GetBytes(saltLength);
        }
        else
        {
            if (fixedSalt.Length != saltLength)
                throw new ArgumentException("the fixed salt is not saltLength long", nameof(fixedSalt));
            salt = fixedSalt.ToArray();
        }

        // M' = (0x00 * 8) || mHash || salt   ->   H = Hash(M')
        var mPrime = new byte[8 + hLen + saltLength];
        mHash.CopyTo(mPrime.AsSpan(8));
        salt.CopyTo(mPrime.AsSpan(8 + hLen));
        Span<byte> h = stackalloc byte[hLen];
        Hash(hashName, mPrime, h);

        // DB = PS || 0x01 || salt, masked with MGF1(H)
        var db = new byte[emLen - hLen - 1];
        db[db.Length - saltLength - 1] = 0x01;
        salt.CopyTo(db.AsSpan(db.Length - saltLength));

        var dbMask = Mgf1(h, db.Length, hashName);
        for (int i = 0; i < db.Length; i++)
            db[i] ^= dbMask[i];

        // clear the leftmost 8*emLen - emBits bits
        int zeroBits = 8 * emLen - emBits;
        if (zeroBits > 0)
            db[0] &= (byte)(0xFF >> zeroBits);

        var em = new byte[emLen];
        db.CopyTo(em, 0);
        h.CopyTo(em.AsSpan(db.Length));
        em[emLen - 1] = 0xBC;
        return em;
    }
}
