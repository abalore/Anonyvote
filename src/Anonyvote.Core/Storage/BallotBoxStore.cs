using Microsoft.Data.Sqlite;

namespace Anonyvote.Core.Storage;

/// <summary>Why the ballot box turned a vote away.</summary>
public enum CastRejection { None, AlreadyVoted }

public sealed record CastOutcome(CastRejection Rejection, long Index, string EntryHash, string Head)
{
    public bool Accepted => Rejection == CastRejection.None;
}

/// <summary>
/// The ballot box's database: the board. Append-only and hash-chained.
///
/// This half of the system has no idea who votes: there is no session, no account, no IP on
/// record. Only anonymous credentials and encrypted ballots.
/// </summary>
public sealed class BallotBoxStore : IDisposable
{
    private readonly SqliteConnection _db;
    private readonly string _electionId;
    private readonly Lock _appendLock = new();

    private BallotBoxStore(SqliteConnection db, string electionId)
    {
        _db = db;
        _electionId = electionId;
    }

    public static BallotBoxStore Open(string path, string electionId)
    {
        var db = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadWriteCreate
        }.ToString());
        db.Open();

        using (var cmd = db.CreateCommand())
        {
            cmd.CommandText = """
                PRAGMA journal_mode = WAL;
                CREATE TABLE IF NOT EXISTS entries (
                    idx        INTEGER PRIMARY KEY,
                    nullifier  TEXT NOT NULL UNIQUE,
                    message    TEXT NOT NULL,
                    signature  TEXT NOT NULL,
                    ciphertext TEXT NOT NULL,
                    hash       TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS state (
                    key   TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """;
            cmd.ExecuteNonQuery();
        }

        return new BallotBoxStore(db, electionId);
    }

    public ElectionPhase Phase
    {
        get
        {
            using var cmd = _db.CreateCommand();
            cmd.CommandText = "SELECT value FROM state WHERE key = 'phase'";
            return cmd.ExecuteScalar() is string s && Enum.TryParse<ElectionPhase>(s, out var p)
                ? p
                : ElectionPhase.Setup;
        }
        set
        {
            using var cmd = _db.CreateCommand();
            cmd.CommandText = """
                INSERT INTO state (key, value) VALUES ('phase', $v)
                ON CONFLICT (key) DO UPDATE SET value = $v
                """;
            cmd.Parameters.AddWithValue("$v", value.ToString());
            cmd.ExecuteNonQuery();
        }
    }

    /// <summary>
    /// Appends a ballot to the board. The caller has already verified the credential; what is
    /// guaranteed here is the uniqueness of the nullifier and a correct chaining, both inside
    /// the same transaction.
    /// </summary>
    public CastOutcome Append(string nullifier, string message, string signature, string ciphertext)
    {
        lock (_appendLock)
        {
            using var tx = _db.BeginTransaction(deferred: false);

            var (_, nextIndex, head) = ReadState(tx);
            long index = nextIndex;
            var hash = HashChain.NextHex(
                head, index,
                Convert.FromHexString(nullifier),
                Convert.FromBase64String(message),
                Convert.FromBase64String(signature),
                Convert.FromBase64String(ciphertext));

            using var cmd = _db.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = """
                INSERT OR IGNORE INTO entries (idx, nullifier, message, signature, ciphertext, hash)
                VALUES ($i, $n, $m, $s, $c, $h)
                """;
            cmd.Parameters.AddWithValue("$i", index);
            cmd.Parameters.AddWithValue("$n", nullifier);
            cmd.Parameters.AddWithValue("$m", message);
            cmd.Parameters.AddWithValue("$s", signature);
            cmd.Parameters.AddWithValue("$c", ciphertext);
            cmd.Parameters.AddWithValue("$h", hash);

            if (cmd.ExecuteNonQuery() == 0)
            {
                tx.Rollback();
                return new CastOutcome(CastRejection.AlreadyVoted, -1, "", head);
            }

            tx.Commit();
            return new CastOutcome(CastRejection.None, index, hash, hash);
        }
    }

    public BoardHead Head()
    {
        var (count, _, head) = ReadState(null);
        return new BoardHead(count, head);
    }

    /// <summary>Number of entries, the index the next one gets, and the current chain head.
    /// The index comes from MAX(idx)+1 rather than COUNT(*): the board is append-only, but the
    /// chaining had better not depend on nobody ever having deleted a row.</summary>
    private (long Count, long NextIndex, string Head) ReadState(SqliteTransaction? tx)
    {
        using var cmd = _db.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText =
            "SELECT COUNT(*), IFNULL(MAX(idx), -1) + 1, " +
            "(SELECT hash FROM entries ORDER BY idx DESC LIMIT 1) FROM entries";
        using var reader = cmd.ExecuteReader();
        reader.Read();
        long count = reader.GetInt64(0);
        long nextIndex = reader.GetInt64(1);
        string head = reader.IsDBNull(2) ? HashChain.GenesisHex(_electionId) : reader.GetString(2);
        return (count, nextIndex, head);
    }

    public IReadOnlyList<BoardEntry> Page(long from, int limit)
    {
        using var cmd = _db.CreateCommand();
        cmd.CommandText = """
            SELECT idx, nullifier, message, signature, ciphertext, hash
            FROM entries WHERE idx >= $from ORDER BY idx LIMIT $limit
            """;
        cmd.Parameters.AddWithValue("$from", from);
        cmd.Parameters.AddWithValue("$limit", limit);

        var entries = new List<BoardEntry>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
            entries.Add(new BoardEntry(
                reader.GetInt64(0), reader.GetString(1), reader.GetString(2),
                reader.GetString(3), reader.GetString(4), reader.GetString(5)));

        return entries;
    }

    public IReadOnlyList<BoardEntry> All() => Page(0, int.MaxValue);

    public void Dispose() => _db.Dispose();
}
