using Microsoft.Data.Sqlite;

namespace Anonyvote.Core.Storage;

/// <summary>
/// The registrar's database: census and phase. This is the half of the system that DOES know
/// who is who, which is why it stores the barest minimum imaginable — the hash of each
/// single-use code and a "used" bit. No names, no emails, not even when it was used: a
/// timestamp here would be correlation material if anyone cross-referenced this database with
/// the ballot box's.
/// </summary>
public sealed class RegistrarStore : IDisposable
{
    private readonly SqliteConnection _db;

    private RegistrarStore(SqliteConnection db) => _db = db;

    public static RegistrarStore Open(string path)
    {
        var db = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadWriteCreate
        }.ToString());
        db.Open();

        Execute(db, """
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS census (
                code_hash TEXT PRIMARY KEY,
                used      INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS state (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """);

        return new RegistrarStore(db);
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

    /// <summary>Loads the census. Returns how many new codes were added.</summary>
    public int AddCodeHashes(IEnumerable<string> codeHashes)
    {
        using var tx = _db.BeginTransaction();
        using var cmd = _db.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = "INSERT OR IGNORE INTO census (code_hash, used) VALUES ($h, 0)";
        var p = cmd.Parameters.Add("$h", SqliteType.Text);

        int added = 0;
        foreach (var hash in codeHashes)
        {
            p.Value = hash;
            added += cmd.ExecuteNonQuery();
        }

        tx.Commit();
        return added;
    }

    /// <summary>
    /// Spends a code, atomically. Returns false when it is not in the census or already used;
    /// the conditional UPDATE is what stops two simultaneous requests carrying the same code
    /// from obtaining two credentials.
    /// </summary>
    public bool TryConsumeCode(string codeHash)
    {
        using var cmd = _db.CreateCommand();
        cmd.CommandText = "UPDATE census SET used = 1 WHERE code_hash = $h AND used = 0";
        cmd.Parameters.AddWithValue("$h", codeHash);
        return cmd.ExecuteNonQuery() == 1;
    }

    public long CensusSize() => Count("SELECT COUNT(*) FROM census");

    /// <summary>Credentials issued. Published at closing time: the board cannot hold more
    /// votes than this number, which makes an inflated census detectable.</summary>
    public long IssuedCount() => Count("SELECT COUNT(*) FROM census WHERE used = 1");

    private long Count(string sql)
    {
        using var cmd = _db.CreateCommand();
        cmd.CommandText = sql;
        return Convert.ToInt64(cmd.ExecuteScalar());
    }

    private static void Execute(SqliteConnection db, string sql)
    {
        using var cmd = db.CreateCommand();
        cmd.CommandText = sql;
        cmd.ExecuteNonQuery();
    }

    public void Dispose() => _db.Dispose();
}
