using System.Numerics;
using System.Security.Cryptography;
using Anonyvote.Crypto;

namespace Anonyvote.Tests;

/// <summary>
/// Half of these tests validate against the official RFC 9474 vectors (Appendix A.1); the
/// other half check the property that actually matters: that the resulting signature is
/// accepted by .NET's standard RSA-PSS verifier, which is an implementation independent of
/// ours.
/// </summary>
public class BlindRsaTests
{
    private static byte[] Hex(string h) => Convert.FromHexString(h);

    private static RSA VectorKey()
    {
        byte[] p = Hex(Rfc9474A1.P), q = Hex(Rfc9474A1.Q), n = Hex(Rfc9474A1.N),
               e = Hex(Rfc9474A1.E), d = Hex(Rfc9474A1.D);

        var pi = RsaPrimitives.Os2Ip(p);
        var qi = RsaPrimitives.Os2Ip(q);
        var di = RsaPrimitives.Os2Ip(d);

        var rsa = RSA.Create();
        rsa.ImportParameters(new RSAParameters
        {
            Modulus = n,
            Exponent = e,
            D = d,
            P = p,
            Q = q,
            DP = RsaPrimitives.I2Osp(di % (pi - 1), p.Length),
            DQ = RsaPrimitives.I2Osp(di % (qi - 1), q.Length),
            InverseQ = RsaPrimitives.I2Osp(RsaPrimitives.ModInverse(qi, pi), p.Length)
        });
        return rsa;
    }

    private static RSA PublicOnly(RSA key)
    {
        var publicKey = RSA.Create();
        publicKey.ImportParameters(key.ExportParameters(false));
        return publicKey;
    }

    // ---- Official RFC 9474 A.1 vectors ----

    [Fact]
    public void Pss_encoding_matches_the_rfc_vector()
    {
        using var key = VectorKey();

        var encoded = Pss.Encode(
            Hex(Rfc9474A1.PreparedMsg),
            key.KeySize - 1,
            BlindRsa.SaltLength,
            BlindRsa.HashAlgorithm,
            Hex(Rfc9474A1.Salt));

        Assert.Equal(Rfc9474A1.EncodedMsg, Convert.ToHexString(encoded).ToLowerInvariant());
    }

    [Fact]
    public void Blind_signature_matches_the_rfc_vector()
    {
        using var key = VectorKey();

        var blindSig = BlindRsa.BlindSign(key, Hex(Rfc9474A1.BlindedMsg));

        Assert.Equal(Rfc9474A1.BlindSig, Convert.ToHexString(blindSig).ToLowerInvariant());
    }

    [Fact]
    public void Unblinding_matches_the_rfc_vector()
    {
        using var key = VectorKey();
        using var publicKey = PublicOnly(key);

        var sig = BlindRsa.Finalize(
            publicKey, Hex(Rfc9474A1.PreparedMsg), Hex(Rfc9474A1.BlindSig), Hex(Rfc9474A1.Inv));

        Assert.Equal(Rfc9474A1.Sig, Convert.ToHexString(sig).ToLowerInvariant());
    }

    [Fact]
    public void The_vectors_random_prefix_forms_the_prepared_message()
    {
        Assert.Equal(Rfc9474A1.MsgPrefix + Rfc9474A1.Msg, Rfc9474A1.PreparedMsg);
    }

    // ---- Protocol properties, with a freshly generated key ----

    [Fact]
    public void A_full_round_produces_a_standard_pss_signature()
    {
        using var key = RSA.Create(2048);
        using var publicKey = PublicOnly(key);

        var prepared = BlindRsa.Prepare("vote"u8);
        var blinded = BlindRsa.Blind(publicKey, prepared);
        var blindSignature = BlindRsa.BlindSign(key, blinded.Blinded);
        var signature = BlindRsa.Finalize(publicKey, prepared, blindSignature, blinded.Inverse);

        // The decisive part: whoever verifies need not know a blind signature was involved.
        Assert.True(publicKey.VerifyData(
            prepared, signature, HashAlgorithmName.SHA384, RSASignaturePadding.Pss));
    }

    [Fact]
    public void The_signer_never_sees_the_same_thing_twice_even_for_the_same_message()
    {
        using var key = RSA.Create(2048);
        using var publicKey = PublicOnly(key);
        var prepared = BlindRsa.Prepare("vote"u8);

        var a = BlindRsa.Blind(publicKey, prepared);
        var b = BlindRsa.Blind(publicKey, prepared);

        Assert.NotEqual(a.Blinded, b.Blinded);
        Assert.NotEqual(a.Inverse, b.Inverse);
    }

    [Fact]
    public void Prepare_prepends_a_different_random_prefix_every_time()
    {
        var a = BlindRsa.Prepare("vote"u8);
        var b = BlindRsa.Prepare("vote"u8);

        Assert.Equal(BlindRsa.RandomPrefixLength + 4, a.Length);
        Assert.Equal("vote"u8.ToArray(), a[BlindRsa.RandomPrefixLength..]);
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void Unblinding_with_the_wrong_inverse_fails()
    {
        using var key = RSA.Create(2048);
        using var publicKey = PublicOnly(key);

        var prepared = BlindRsa.Prepare("vote"u8);
        var blinded = BlindRsa.Blind(publicKey, prepared);
        var blindSignature = BlindRsa.BlindSign(key, blinded.Blinded);
        var other = BlindRsa.Blind(publicKey, prepared).Inverse;

        Assert.Throws<CryptographicException>(() =>
            BlindRsa.Finalize(publicKey, prepared, blindSignature, other));
    }

    [Fact]
    public void The_signature_is_no_good_for_another_message()
    {
        using var key = RSA.Create(2048);
        using var publicKey = PublicOnly(key);

        var prepared = BlindRsa.Prepare("vote"u8);
        var blinded = BlindRsa.Blind(publicKey, prepared);
        var signature = BlindRsa.Finalize(
            publicKey, prepared, BlindRsa.BlindSign(key, blinded.Blinded), blinded.Inverse);

        Assert.False(BlindRsa.Verify(publicKey, BlindRsa.Prepare("vote"u8), signature));
    }

    [Fact]
    public void A_signature_from_another_key_is_worthless()
    {
        using var registrar = RSA.Create(2048);
        using var impostor = RSA.Create(2048);
        using var registrarPublic = PublicOnly(registrar);
        using var impostorPublic = PublicOnly(impostor);

        var prepared = BlindRsa.Prepare("vote"u8);
        var blinded = BlindRsa.Blind(impostorPublic, prepared);
        var signature = BlindRsa.Finalize(
            impostorPublic, prepared, BlindRsa.BlindSign(impostor, blinded.Blinded), blinded.Inverse);

        Assert.False(BlindRsa.Verify(registrarPublic, prepared, signature));
    }

    [Fact]
    public void The_signer_rejects_inputs_of_the_wrong_length()
    {
        using var key = RSA.Create(2048);

        Assert.Throws<CryptographicException>(() => BlindRsa.BlindSign(key, new byte[255]));
        Assert.Throws<CryptographicException>(() => BlindRsa.BlindSign(key, new byte[257]));
    }

    [Fact]
    public void The_signer_rejects_a_blinded_message_larger_than_the_modulus()
    {
        using var key = RSA.Create(2048);
        var outOfRange = new byte[256];
        Array.Fill(outOfRange, (byte)0xFF);

        Assert.Throws<CryptographicException>(() => BlindRsa.BlindSign(key, outOfRange));
    }

    [Fact]
    public void The_modular_inverse_is_correct()
    {
        var m = BigInteger.Parse("340282366920938463463374607431768211507");
        for (int a = 2; a < 50; a++)
            Assert.Equal(BigInteger.One, a * RsaPrimitives.ModInverse(a, m) % m);
    }

    [Fact]
    public void I2Osp_pads_on_the_left_and_os2ip_undoes_it()
    {
        var bytes = RsaPrimitives.I2Osp(new BigInteger(258), 8);

        Assert.Equal("0000000000000102", Convert.ToHexString(bytes).ToLowerInvariant());
        Assert.Equal(new BigInteger(258), RsaPrimitives.Os2Ip(bytes));
        Assert.Throws<CryptographicException>(() => RsaPrimitives.I2Osp(new BigInteger(258), 1));
    }
}
