using System.Security.Cryptography;
using System.Text;

namespace Anonyvote.Core;

/// <summary>
/// Single-use census codes. 100 bits of entropy in Crockford base32 (no I, L, O or U),
/// grouped in fives: they have to be readable over the phone and typeable without slips.
///
/// The system never stores the code, only its SHA-256. Whoever steals the registrar's
/// database cannot vote with it.
/// </summary>
public static class VotingCode
{
    private const string Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    private const int Characters = 20;
    private const int GroupSize = 5;

    public static string Generate()
    {
        var chars = new char[Characters];
        for (int i = 0; i < Characters; i++)
            chars[i] = Alphabet[RandomNumberGenerator.GetInt32(Alphabet.Length)];

        var sb = new StringBuilder(Characters + Characters / GroupSize - 1);
        for (int i = 0; i < Characters; i++)
        {
            if (i > 0 && i % GroupSize == 0) sb.Append('-');
            sb.Append(chars[i]);
        }
        return sb.ToString();
    }

    /// <summary>Normalizes whatever the voter typed: ignores dashes and spaces, is
    /// case-insensitive and fixes the classic confusions (I/L to 1, O to 0).</summary>
    public static string Normalize(string code)
    {
        var sb = new StringBuilder(Characters);
        foreach (var raw in code)
        {
            var c = char.ToUpperInvariant(raw);
            c = c switch { 'I' or 'L' => '1', 'O' => '0', 'U' => 'V', _ => c };
            if (Alphabet.Contains(c)) sb.Append(c);
        }
        return sb.ToString();
    }

    public static string Hash(string code) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Normalize(code)))).ToLowerInvariant();

    public static bool LooksValid(string code) => Normalize(code).Length == Characters;
}
