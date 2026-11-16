namespace Anonyvote.Admin;

/// <summary>Reader for --key value arguments. No dependencies: a command-line library is not
/// worth pulling in for six subcommands.</summary>
internal sealed class Args
{
    private readonly Dictionary<string, List<string>> _values = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _flags = new(StringComparer.OrdinalIgnoreCase);

    internal Args(IEnumerable<string> arguments)
    {
        string? pending = null;
        foreach (var arg in arguments)
        {
            if (arg.StartsWith("--", StringComparison.Ordinal))
            {
                if (pending is not null) _flags.Add(pending);
                pending = arg[2..];
            }
            else if (pending is not null)
            {
                // Repeatable: --share a --share b accumulates instead of overwriting.
                if (!_values.TryGetValue(pending, out var list))
                    _values[pending] = list = [];
                list.Add(arg);
                pending = null;
            }
        }
        if (pending is not null) _flags.Add(pending);
    }

    internal bool Has(string name) => _values.ContainsKey(name) || _flags.Contains(name);

    internal string? Get(string name) => _values.TryGetValue(name, out var v) ? v[^1] : null;

    internal IReadOnlyList<string> GetAll(string name) =>
        _values.TryGetValue(name, out var v) ? v : [];

    internal string Require(string name) =>
        Get(name) ?? throw new ArgumentException($"missing required argument --{name}");

    internal int GetInt(string name, int fallback) =>
        Get(name) is string s
            ? int.TryParse(s, out var v) ? v : throw new ArgumentException($"--{name} is not a number: {s}")
            : fallback;

    internal int RequireInt(string name) =>
        int.TryParse(Require(name), out var v) ? v : throw new ArgumentException($"--{name} is not a number");
}
