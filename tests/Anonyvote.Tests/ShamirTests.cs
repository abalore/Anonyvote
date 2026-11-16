using System.Security.Cryptography;
using Anonyvote.Core;

namespace Anonyvote.Tests;

public class ShamirTests
{
    private static List<(int X, byte[] Y)> Pick(IReadOnlyList<byte[]> shares, params int[] indices) =>
        indices.Select(i => (i, shares[i - 1])).ToList();

    private static IEnumerable<int[]> Combinations(int total, int take)
    {
        var current = new int[take];
        IEnumerable<int[]> Walk(int position, int from)
        {
            if (position == take) { yield return (int[])current.Clone(); yield break; }
            for (int v = from; v <= total; v++)
            {
                current[position] = v;
                foreach (var r in Walk(position + 1, v + 1)) yield return r;
            }
        }
        return Walk(0, 1);
    }

    [Fact]
    public void Any_subset_of_threshold_size_reconstructs_the_secret()
    {
        var secret = RandomNumberGenerator.GetBytes(128);
        var shares = Shamir.Split(secret, shares: 5, threshold: 3);

        foreach (var combination in Combinations(5, 3))
            Assert.Equal(secret, Shamir.Combine(Pick(shares, combination)));
    }

    [Fact]
    public void More_shares_than_the_threshold_also_reconstruct()
    {
        var secret = RandomNumberGenerator.GetBytes(64);
        var shares = Shamir.Split(secret, shares: 5, threshold: 3);

        Assert.Equal(secret, Shamir.Combine(Pick(shares, 1, 2, 3, 4, 5)));
    }

    [Fact]
    public void Below_the_threshold_the_secret_is_not_obtained()
    {
        var secret = RandomNumberGenerator.GetBytes(64);
        var shares = Shamir.Split(secret, shares: 5, threshold: 3);

        // Two shares do interpolate "something", but that something bears no relation to the secret.
        foreach (var combination in Combinations(5, 2))
            Assert.NotEqual(secret, Shamir.Combine(Pick(shares, combination)));
    }

    [Fact]
    public void A_lone_share_does_not_resemble_the_secret()
    {
        var secret = RandomNumberGenerator.GetBytes(256);
        var shares = Shamir.Split(secret, shares: 3, threshold: 2);

        foreach (var share in shares)
        {
            Assert.Equal(secret.Length, share.Length);
            Assert.NotEqual(secret, share);
        }
    }

    [Fact]
    public void Splits_and_reconstructs_a_whole_rsa_key()
    {
        using var key = RSA.Create(2048);
        var pkcs8 = key.ExportPkcs8PrivateKey();

        var shares = Shamir.Split(pkcs8, shares: 5, threshold: 3);
        var reconstructed = Shamir.Combine(Pick(shares, 2, 4, 5));

        using var recovered = RSA.Create();
        recovered.ImportPkcs8PrivateKey(reconstructed, out _);

        // The real test: the reconstructed key decrypts what the original encrypted.
        var message = "ballot"u8.ToArray();
        var ciphertext = key.Encrypt(message, RSAEncryptionPadding.OaepSHA256);
        Assert.Equal(message, recovered.Decrypt(ciphertext, RSAEncryptionPadding.OaepSHA256));
    }

    [Fact]
    public void An_altered_share_ruins_the_reconstruction()
    {
        var secret = RandomNumberGenerator.GetBytes(64);
        var shares = Shamir.Split(secret, shares: 3, threshold: 2);
        shares[0][5] ^= 0x01;

        Assert.NotEqual(secret, Shamir.Combine(Pick(shares, 1, 2)));
    }

    [Fact]
    public void The_single_trustee_case_still_works()
    {
        var secret = RandomNumberGenerator.GetBytes(32);
        var shares = Shamir.Split(secret, shares: 1, threshold: 1);

        Assert.Equal(secret, Shamir.Combine(Pick(shares, 1)));
    }

    [Theory]
    [InlineData(5, 6)]    // threshold larger than the number of shares
    [InlineData(5, 0)]
    [InlineData(0, 1)]
    [InlineData(256, 2)]  // more shares than there are abscissas in GF(256)
    public void Rejects_impossible_configurations(int shares, int threshold)
    {
        Assert.Throws<ArgumentException>(() =>
            Shamir.Split(RandomNumberGenerator.GetBytes(16), shares, threshold));
    }

    [Fact]
    public void Rejects_repeated_or_mismatched_shares()
    {
        var shares = Shamir.Split(RandomNumberGenerator.GetBytes(32), shares: 3, threshold: 2);

        Assert.Throws<ArgumentException>(() =>
            Shamir.Combine([(1, shares[0]), (1, shares[0])]));

        Assert.Throws<ArgumentException>(() =>
            Shamir.Combine([(1, shares[0]), (2, new byte[8])]));

        Assert.Throws<ArgumentException>(() =>
            Shamir.Combine([(0, shares[0]), (2, shares[1])]));
    }
}
