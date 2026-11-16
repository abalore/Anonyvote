using System.Numerics;
using System.Security.Cryptography;
using static Anonyvote.Crypto.RsaPrimitives;

namespace Anonyvote.Crypto;

/// <summary>A blinded message ready to send to the signer, with the factor that unblinds it.</summary>
/// <param name="Blinded">The only thing the registrar ever sees.</param>
/// <param name="Inverse">The voter's secret: without it the blind signature is worthless.</param>
public sealed record BlindedMessage(byte[] Blinded, byte[] Inverse);

/// <summary>
/// RSA blind signatures as specified by RFC 9474, variant RSABSSA-SHA384-PSS-Randomized.
///
/// The property the whole of Anonyvote rests on: the signer produces a valid signature over a
/// message it CANNOT see, and later cannot link that signature to the request that produced
/// it. And because the output is a standard RSA-PSS signature, whoever verifies it needs none
/// of this code.
/// </summary>
public static class BlindRsa
{
    public static readonly HashAlgorithmName HashAlgorithm = HashAlgorithmName.SHA384;

    /// <summary>PSS salt length: equal to the hash size, which is what .NET assumes on verify.</summary>
    public const int SaltLength = 48;

    /// <summary>Random prefix of the Randomized variant (RFC 9474 §4.1).</summary>
    public const int RandomPrefixLength = 32;

    /// <summary>
    /// Prepare: prepends 32 random bytes to the message. The result is what gets signed and
    /// what is later verified, so it must be kept whole.
    /// </summary>
    public static byte[] Prepare(ReadOnlySpan<byte> message)
    {
        var prepared = new byte[RandomPrefixLength + message.Length];
        RandomNumberGenerator.Fill(prepared.AsSpan(0, RandomPrefixLength));
        message.CopyTo(prepared.AsSpan(RandomPrefixLength));
        return prepared;
    }

    /// <summary>Blind: PSS-encode and multiply by r^e. Runs on the voter's machine.</summary>
    public static BlindedMessage Blind(RSA publicKey, ReadOnlySpan<byte> preparedMessage)
    {
        var p = publicKey.ExportParameters(false);
        var n = Os2Ip(p.Modulus!);
        var e = Os2Ip(p.Exponent!);
        int length = publicKey.KeySize / 8;

        var encoded = Pss.Encode(preparedMessage, publicKey.KeySize - 1, SaltLength, HashAlgorithm);
        var m = Os2Ip(encoded);
        if (m >= n)
            throw new CryptographicException("encoded message out of the modulus range");

        var r = RandomInvertible(n, length);
        var rInverse = ModInverse(r, n);
        var z = m * BigInteger.ModPow(r, e, n) % n;

        return new BlindedMessage(I2Osp(z, length), I2Osp(rInverse, length));
    }

    /// <summary>
    /// BlindSign: raw RSA operation over the blinded message. Runs on the registrar, which at
    /// no point sees the real message.
    /// </summary>
    public static byte[] BlindSign(RSA privateKey, ReadOnlySpan<byte> blindedMessage)
    {
        var p = privateKey.ExportParameters(true);
        var n = Os2Ip(p.Modulus!);
        var e = Os2Ip(p.Exponent!);
        var d = Os2Ip(p.D!);
        int length = privateKey.KeySize / 8;

        if (blindedMessage.Length != length)
            throw new CryptographicException("blinded message of incorrect length");

        var m = Os2Ip(blindedMessage);
        if (m >= n)
            throw new CryptographicException("blinded message out of the modulus range");

        // The signer blinds on its own account: ModPow is not constant time and the input here
        // is chosen by a third party, so the private key must not be exposed to timing attacks.
        var u = RandomInvertible(n, length);
        var uInverse = ModInverse(u, n);
        var masked = m * BigInteger.ModPow(u, e, n) % n;
        var signature = BigInteger.ModPow(masked, d, n) * uInverse % n;

        // Check required by RFC 9474 §5.2: s^e must reproduce the input.
        if (BigInteger.ModPow(signature, e, n) != m)
            throw new CryptographicException("the blind signature failed its own check");

        return I2Osp(signature, length);
    }

    /// <summary>
    /// Finalize: unblind and check. Runs on the voter's machine; from here on the credential
    /// bears no relation whatsoever to the registration request.
    /// </summary>
    public static byte[] Finalize(
        RSA publicKey,
        ReadOnlySpan<byte> preparedMessage,
        ReadOnlySpan<byte> blindSignature,
        ReadOnlySpan<byte> inverse)
    {
        var p = publicKey.ExportParameters(false);
        var n = Os2Ip(p.Modulus!);
        int length = publicKey.KeySize / 8;

        if (blindSignature.Length != length)
            throw new CryptographicException("blind signature of incorrect length");

        var signature = I2Osp(Os2Ip(blindSignature) * Os2Ip(inverse) % n, length);

        if (!Verify(publicKey, preparedMessage, signature))
            throw new CryptographicException("the signature is not valid after unblinding");

        return signature;
    }

    /// <summary>Verification: plain RSA-PSS. No trace of the blind signature remains.</summary>
    public static bool Verify(RSA publicKey, ReadOnlySpan<byte> preparedMessage, ReadOnlySpan<byte> signature) =>
        publicKey.VerifyData(preparedMessage, signature, HashAlgorithm, RSASignaturePadding.Pss);
}
