namespace Example;

internal class ArgParser
{
    private readonly Dictionary<string, ArgDefinition> argMap = new(StringComparer.OrdinalIgnoreCase);
    public ArgParser(params ArgDefinition[] args)
    {
        foreach (ArgDefinition arg in args)
        {
            argMap[arg.Name] = arg;
            foreach (string alias in arg.Aliases)
                argMap[alias] = arg;
        }
    }
    public Dictionary<string, Range> Parse(ReadOnlySpan<string> args)
    {
        Dictionary<string, Range> values = new(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < args.Length;)
        {
            string arg = args[i];
            if (!argMap.TryGetValue(arg, out ArgDefinition? argDef))
            {
                i++;
                continue;
            }
            int s = ++i;
            int e = i += argDef.ParamCount;
            values[argDef.Name] = s..e;
        }
        return values;
    }
    public static string? GetString(Dictionary<string, Range> parseResult, string name, ReadOnlySpan<string> args)
    {
        if (parseResult.TryGetValue(name, out Range range))
        {
            int start = range.Start.GetOffset(args.Length);
            if (start < args.Length)
                return args[start];
        }
        return null;
    }
    public static int? GetInt32(Dictionary<string, Range> parseResult, string name, ReadOnlySpan<string> args)
    {
        if (int.TryParse(GetString(parseResult, name, args), out int i))
            return i;
        return null;
    }
    public static long? GetInt64(Dictionary<string, Range> parseResult, string name, ReadOnlySpan<string> args)
    {
        if (long.TryParse(GetString(parseResult, name, args), out long i))
            return i;
        return null;
    }
    public static bool? GetBoolean(Dictionary<string, Range> parseResult, string name, ReadOnlySpan<string> args)
    {
        string? s = GetString(parseResult, name, args);
        if (long.TryParse(s, out long i))
            return i != 0;
        if (s is null)
            return null;
        if ("yes".StartsWith(s, StringComparison.OrdinalIgnoreCase) || "true".StartsWith(s, StringComparison.OrdinalIgnoreCase))
            return true;
        if ("no".StartsWith(s, StringComparison.OrdinalIgnoreCase) || "false".StartsWith(s, StringComparison.OrdinalIgnoreCase))
            return false;
        return null;
    }
}

internal class ArgDefinition(string name, int paramCount, params string[] aliases) : IEquatable<ArgDefinition>
{
    public string Name { get; set; } = name;
    public string[] Aliases { get; set; } = aliases;
    public int ParamCount { get; set; } = paramCount;
    public string? Info { get; set; }

    public bool Equals(ArgDefinition? other)
        => StringComparer.OrdinalIgnoreCase.Equals(Name, other?.Name);
    public override bool Equals(object? obj)
        => Equals(obj as ArgDefinition);
    public override int GetHashCode()
        => StringComparer.OrdinalIgnoreCase.GetHashCode(Name);
}