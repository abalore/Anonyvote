using System.Security.Cryptography;
using Anonyvote.Core;

namespace Anonyvote.Tests;

public class BallotTests
{
    private static ElectionManifest Election(int maxChoices = 3) => new(
        "test-001", "Test election",
        [new Candidate(1, "Ana"), new Candidate(2, "Bruno"), new Candidate(3, "Carla"),
         new Candidate(4, "Diego"), new Candidate(5, "Elena")],
        maxChoices, "", "");

    [Theory]
    [InlineData(new int[0])]              // blank vote
    [InlineData(new[] { 2 })]             // partial
    [InlineData(new[] { 1, 3 })]
    [InlineData(new[] { 5, 1, 4 })]       // full and out of order
    public void Accepts_valid_ballots(int[] choices)
    {
        Assert.Null(new Ballot(choices).Validate(Election()));
    }

    [Fact]
    public void Rejects_more_than_three_choices()
    {
        var error = new Ballot([1, 2, 3, 4]).Validate(Election());
        Assert.Contains("maximum is 3", error);
    }

    [Fact]
    public void Rejects_repeated_candidates()
    {
        Assert.Contains("repeats", new Ballot([2, 2]).Validate(Election()));
    }

    [Fact]
    public void Rejects_candidates_that_do_not_exist()
    {
        Assert.Contains("does not exist", new Ballot([1, 99]).Validate(Election()));
    }

    [Fact]
    public void The_encoding_is_deterministic_and_order_independent()
    {
        Assert.Equal(new Ballot([1, 3, 5]).Encode(), new Ballot([5, 1, 3]).Encode());
        Assert.NotEqual(new Ballot([1, 3, 5]).Encode(), new Ballot([1, 3, 4]).Encode());
    }

    [Fact]
    public void Encoding_and_decoding_preserves_the_choices()
    {
        var original = new Ballot([4, 2]);
        Assert.Equal([2, 4], Ballot.Decode(original.Encode()).Choices);
    }

    [Fact]
    public void Encrypting_and_decrypting_preserves_the_ballot()
    {
        using var key = RSA.Create(2048);
        var ballot = new Ballot([1, 4, 5]);

        var ciphertext = BallotCipher.Encrypt(ballot, key);

        Assert.Equal([1, 4, 5], BallotCipher.Decrypt(ciphertext, key).Choices);
    }

    [Fact]
    public void Two_identical_ballots_give_different_ciphertexts_of_the_same_size()
    {
        using var key = RSA.Create(2048);
        var ballot = new Ballot([1, 2, 3]);

        var a = BallotCipher.Encrypt(ballot, key);
        var b = BallotCipher.Encrypt(ballot, key);
        var blank = BallotCipher.Encrypt(new Ballot([]), key);

        Assert.NotEqual(a, b);                 // OAEP randomizes: ballots cannot be grouped by vote
        Assert.Equal(a.Length, b.Length);
        Assert.Equal(a.Length, blank.Length);  // the size does not betray how many candidates it carries
    }
}

public class BoardTests
{
    private static byte[] Bytes(string s) => System.Text.Encoding.UTF8.GetBytes(s);

    [Fact]
    public void The_genesis_depends_on_the_election()
    {
        Assert.NotEqual(HashChain.GenesisHex("a"), HashChain.GenesisHex("b"));
        Assert.Equal(HashChain.GenesisHex("a"), HashChain.GenesisHex("a"));
    }

    [Fact]
    public void The_chain_is_deterministic()
    {
        var previous = HashChain.Genesis("e1");
        var a = HashChain.Next(previous, 0, Bytes("nul"), Bytes("msg"), Bytes("sig"), Bytes("ct"));
        var b = HashChain.Next(previous, 0, Bytes("nul"), Bytes("msg"), Bytes("sig"), Bytes("ct"));

        Assert.Equal(a, b);
    }

    [Fact]
    public void Any_change_to_an_entry_breaks_the_chain()
    {
        var previous = HashChain.Genesis("e1");
        var original = HashChain.Next(previous, 0, Bytes("nul"), Bytes("msg"), Bytes("sig"), Bytes("ct"));

        Assert.NotEqual(original, HashChain.Next(previous, 1, Bytes("nul"), Bytes("msg"), Bytes("sig"), Bytes("ct")));
        Assert.NotEqual(original, HashChain.Next(previous, 0, Bytes("NUL"), Bytes("msg"), Bytes("sig"), Bytes("ct")));
        Assert.NotEqual(original, HashChain.Next(previous, 0, Bytes("nul"), Bytes("MSG"), Bytes("sig"), Bytes("ct")));
        Assert.NotEqual(original, HashChain.Next(previous, 0, Bytes("nul"), Bytes("msg"), Bytes("SIG"), Bytes("ct")));
        Assert.NotEqual(original, HashChain.Next(previous, 0, Bytes("nul"), Bytes("msg"), Bytes("sig"), Bytes("CT")));
    }

    [Fact]
    public void Swapping_two_entries_changes_the_head()
    {
        var genesis = HashChain.Genesis("e1");
        var ab = HashChain.Next(HashChain.Next(genesis, 0, Bytes("n1"), Bytes("a"), Bytes("s"), Bytes("c")),
                                1, Bytes("n2"), Bytes("b"), Bytes("s"), Bytes("c"));
        var ba = HashChain.Next(HashChain.Next(genesis, 0, Bytes("n2"), Bytes("b"), Bytes("s"), Bytes("c")),
                                1, Bytes("n1"), Bytes("a"), Bytes("s"), Bytes("c"));

        Assert.NotEqual(ab, ba);
    }

    [Fact]
    public void The_length_prefix_stops_bytes_moving_between_fields()
    {
        var previous = HashChain.Genesis("e1");

        Assert.NotEqual(
            HashChain.Next(previous, 0, Bytes("n"), Bytes("ab"), Bytes("c"), Bytes("d")),
            HashChain.Next(previous, 0, Bytes("n"), Bytes("a"), Bytes("bc"), Bytes("d")));
    }

    [Fact]
    public void The_nullifier_tells_credentials_apart_and_is_stable()
    {
        var message = RandomNumberGenerator.GetBytes(64);

        Assert.Equal(Nullifier.ComputeHex(message), Nullifier.ComputeHex(message));
        Assert.NotEqual(Nullifier.ComputeHex(message),
                        Nullifier.ComputeHex(RandomNumberGenerator.GetBytes(64)));
        Assert.Equal(64, Nullifier.ComputeHex(message).Length);
    }
}
