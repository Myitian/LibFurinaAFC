using Example;
using LibFurinaAFC;
using System.Diagnostics;
using System.Text;

internal class Program
{
    private static void Main(string[] args)
    {
        ArgDefinition[] argDefinitions = [
            new("-Help", 0, "-h", "-?"),
            new("-Encrypt", 0, "-enc", "-e"),
            new("-Decrypt", 0, "-dec", "-d"),
            new("-Mode", 1, "-m") { Info = "enum: Encrypt/Decrypt" },
            new("-Input", 1, "-in", "-i") { Info = "string" },
            new("-Output", 1, "-out", "-o") { Info = "string" },
            new("-KeyLength", 1, "-KeySize", "-ksize", "-keylen", "-klen", "-k") { Info = "int32: >1 (Only affects encryption)" },
            new("-BlockLength", 1, "-BlockSize", "-bsize", "-blklen", "-blen", "-b") { Info = "int32: >1 (Only affects encryption)" },
            new("-NoEncryption", 1, "-noenc", "-ne") { Info = "boolean (Only affects encryption)" },
            new("-BlockSequenceMode", 1, "-blockseq", "-blkseq", "-bseq") { Info = "enum: Auto/Random/Sequence/Stream (Only affects encryption)" },
            new("-HashMode ", 1, "-HashAlgorithm", "-hashalg", "-hash") { Info = "enum: None/CRC32/MD5Lower64/MD5Upper64/SHA1Lower64/SHA1Upper64" },
            new("-ValidateHash", 1, "-CheckHash") { Info = "boolean (Only affects decryption)" },
            new("-ValidateMainMagicHeader", 1, "-CheckMainHeader") { Info = "boolean (Only affects decryption)" },
            new("-ValidateBlockMagicHeader", 1, "-CheckBlockHeader") { Info = "boolean (Only affects decryption)" },
            new("-MainMagicHeader", 1, "-MainHeader") { Info = "int64" },
            new("-BlockMagicHeader", 1, "-BlockHeader") { Info = "int64" }
        ];
        ArgParser parser = new(argDefinitions);
        Dictionary<string, Range> parseResult = parser.Parse(args);
        if (parseResult.ContainsKey("-Help"))
        {
            int nLen = "Name".Length, cLen = "Parameter Count".Length, aLen = "Alias".Length, iLen = "Info".Length;
            foreach (ArgDefinition aDef in argDefinitions)
            {
                int nnLen = aDef.Name.Length;
                int ncLen = aDef.ParamCount.ToString().Length;
                int naLen = aDef.Aliases.Sum(a => a.Length) + Math.Max(aDef.Aliases.Length - 1, 0) * ", ".Length;
                int niLen = aDef.Info?.Length ?? 0;
                if (nnLen > nLen)
                    nLen = nnLen;
                if (ncLen > cLen)
                    cLen = ncLen;
                if (naLen > aLen)
                    aLen = naLen;
                if (niLen > iLen)
                    iLen = niLen;
            }
            StringBuilder sb = new("Arguments:");
            sb.AppendLine()
                .AppendPadLeft("Name", nLen).Append(" | ")
                .AppendPadLeft("Parameter Count", cLen).Append(" | ")
                .AppendPadLeft("Alias", aLen).Append(" | ")
                .AppendPadLeft("Info", iLen);
            foreach (ArgDefinition aDef in argDefinitions)
            {
                sb.AppendLine()
                    .AppendPadLeft(aDef.Name, nLen).Append(' ', 3)
                    .AppendPadRight(aDef.ParamCount, cLen).Append(' ', 3)
                    .AppendPadLeft(string.Join(", ", aDef.Aliases), aLen).Append(' ', 3)
                    .AppendPadLeft(aDef.Info ?? "", iLen);
            }
            Console.Error.WriteLine(sb.ToString());
            return;
        }
        string? mode = ArgParser.GetString(parseResult, "-Mode", args);
        bool enc;
        if (parseResult.ContainsKey("-Encrypt") ||
            (mode is not null && "encrypt".StartsWith(mode, StringComparison.OrdinalIgnoreCase)))
            enc = true;
        else if (parseResult.ContainsKey("-Decrypt") ||
            (mode is not null && "decrypt".StartsWith(mode, StringComparison.OrdinalIgnoreCase)))
            enc = false;
        else
        {
            Console.Error.WriteLine("ENC/DEC [0/1]:");
            enc = Console.ReadLine()?.Trim() != "1";
        }
        string? input = ArgParser.GetString(parseResult, "-Input", args);
        if (string.IsNullOrEmpty(input))
        {
            Console.Error.WriteLine("Input:");
            input = Console.ReadLine().AsSpan().Trim().Trim('"').ToString();
        }
        string? output = ArgParser.GetString(parseResult, "-Output", args);
        if (string.IsNullOrEmpty(output))
        {
            Console.Error.WriteLine("Output:");
            output = Console.ReadLine().AsSpan().Trim().Trim('"').ToString();
        }
        AFCOptions options = new();
        {
            int? i = ArgParser.GetInt32(parseResult, "-KeyLength", args);
            if (i.HasValue)
                options.KeyLength = i.Value;
        }
        {
            int? i = ArgParser.GetInt32(parseResult, "-BlockLength", args);
            if (i.HasValue)
                options.BlockLength = i.Value;
        }
        {
            bool? b = ArgParser.GetBoolean(parseResult, "-NoEncryption", args);
            if (b.HasValue)
                options.NoEncryption = b.Value;
        }
        {
            string? s = ArgParser.GetString(parseResult, "-BlockSequenceMode", args);
            if (Enum.TryParse(s, true, out BlockSequenceMode e))
                options.BlockSequenceMode = e;
        }
        {
            bool? b = ArgParser.GetBoolean(parseResult, "-ValidateHash", args);
            if (b.HasValue)
                options.ValidateHash = b.Value;
        }
        {
            bool? b = ArgParser.GetBoolean(parseResult, "-ValidateMainMagicHeader", args);
            if (b.HasValue)
                options.ValidateMainMagicHeader = b.Value;
        }
        {
            bool? b = ArgParser.GetBoolean(parseResult, "-ValidateBlockMagicHeader", args);
            if (b.HasValue)
                options.ValidateBlockMagicHeader = b.Value;
        }
        {
            long? i = ArgParser.GetInt64(parseResult, "-MainMagicHeader", args);
            if (i.HasValue)
                options.MainMagicHeader = i.Value;
        }
        {
            long? i = ArgParser.GetInt64(parseResult, "-BlockMagicHeader", args);
            if (i.HasValue)
                options.BlockMagicHeader = i.Value;
        }
        {
            string? s = ArgParser.GetString(parseResult, "-HashMode", args);
            if (Enum.TryParse(s, true, out HashMode e))
                options.HashMode = e;
        }
        Console.Error.WriteLine("Start!");
        using Stream inputStream = input == "-" ? Console.OpenStandardInput() : File.Open(input, FileMode.Open, FileAccess.Read, FileShare.Read);
        using Stream outputStream = output == "-" ? Console.OpenStandardOutput() : File.Open(output, FileMode.Create, FileAccess.Write, FileShare.Read);
        Stopwatch sw = Stopwatch.StartNew();
        if (enc)
            AdvancedFurinaCryption.Encrypt(inputStream, outputStream, options);
        else
            AdvancedFurinaCryption.Decrypt(inputStream, outputStream, options);
        sw.Stop();
        Console.Error.WriteLine(sw.Elapsed);
    }
}
