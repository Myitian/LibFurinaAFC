using System.Buffers;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace LibFurinaAFC;

public static class AdvancedFurinaCryption
{
    public static void Decrypt(string inputPath, string outputPath, AFCOptions? options = null)
    {
        using FileStream inputStream = File.Open(inputPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        using FileStream outputStream = File.Open(outputPath, FileMode.OpenOrCreate, FileAccess.Write, FileShare.Read);
        Decrypt(inputStream, outputStream, options);
    }

    public static void Decrypt(Stream inputStream, Stream outputStream, AFCOptions? options = null)
    {
        if (!inputStream.CanRead)
            throw new ArgumentException("Stream cannot read!", nameof(inputStream));
        if (!outputStream.CanWrite)
            throw new ArgumentException("Stream cannot write!", nameof(outputStream));
        AFCOptions option = options ?? new();
        AFCHeader header = AFCHeader.ReadFrom(inputStream, option.ValidateMainMagicHeader, option.MainMagicHeader);
        header.Validate();
        bool streamMode = header.AFCLength < 0;
        BlockHeader bHeader;
        long rawlen = header.RawLength;
        if (!streamMode && outputStream.CanSeek)
            outputStream.SetLength(rawlen);
        byte[] readBuffer = ArrayPool<byte>.Shared.Rent(header.BlockLength);
        byte[] keyBuffer = ArrayPool<byte>.Shared.Rent(header.KeyLength);
        try
        {
            Span<byte> readSpan = readBuffer.AsSpan(0, header.BlockLength);
            Span<byte> keySpan = keyBuffer.AsSpan(0, header.KeyLength);
            long forwardOnlyPos = 0;
            for (int i = 0; streamMode || i < header.BlockCount; i++)
            {
                bHeader = BlockHeader.ReadFrom(inputStream, option.ValidateBlockMagicHeader, option.BlockMagicHeader);
                inputStream.ReadExactly(keySpan);
                int read = inputStream.ReadAtLeast(readSpan, header.BlockLength, false);
                if (!streamMode)
                {
                    long newPos = bHeader.BlockID * header.BlockLength;
                    if (forwardOnlyPos != newPos)
                        outputStream.Position = newPos;
                    read = (int)Math.Min(read, header.RawLength - newPos);
                }
                Span<byte> toWriteSpan = readSpan[..read];
                XorChunk(toWriteSpan, keySpan);
                if (option.ValidateHash && bHeader.BlockHash != Hash(toWriteSpan, option.HashMode))
                    throw new InvalidDataException();
                outputStream.Write(toWriteSpan);
                forwardOnlyPos += read;
                if (read != header.BlockLength)
                    break;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(keyBuffer);
            ArrayPool<byte>.Shared.Return(readBuffer);
        }
    }

    public static void Encrypt(string inputPath, string outputPath, AFCOptions? options = null)
    {
        using FileStream inputStream = File.Open(inputPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        using FileStream outputStream = File.Open(outputPath, FileMode.Create, FileAccess.Write, FileShare.Read);
        Encrypt(inputStream, outputStream, options);
    }

    public static void Encrypt(Stream inputStream, Stream outputStream, AFCOptions? options = null)
    {
        if (!inputStream.CanRead)
            throw new ArgumentException("Stream cannot read!", nameof(inputStream));
        if (!outputStream.CanWrite)
            throw new ArgumentException("Stream cannot write!", nameof(outputStream));
        AFCOptions option = options ?? new();
        long rawLen;
        try
        {
            if (option.BlockSequenceMode is not BlockSequenceMode.Stream)
                rawLen = inputStream.Length;
            else
                rawLen = -1;
        }
        catch (NotSupportedException) when (option.BlockSequenceMode is BlockSequenceMode.Auto)
        {
            rawLen = -1;
        }
        bool streamMode = option.BlockSequenceMode is BlockSequenceMode.Stream;

        AFCHeader header = new(rawLen, option.BlockLength, option.KeyLength);
        header.Validate();
        header.WriteTo(outputStream, option.MainMagicHeader);
        long rawBlockLength = 32L + option.BlockLength + option.KeyLength;

        long[] list = [];
        bool cannotRandom = !inputStream.CanSeek && !outputStream.CanSeek;
        ShuffleMode shuffleMode = ShuffleMode.None;
        switch (option.BlockSequenceMode)
        {
            case BlockSequenceMode.Auto when !cannotRandom:
            case BlockSequenceMode.Random:
                list = ArrayPool<long>.Shared.Rent(header.BlockCount);
                for (int i = 0; i < header.BlockCount; i++)
                    list[i] = i;
                Random.Shared.Shuffle(list.AsSpan(0, header.BlockCount));
                if (outputStream.CanSeek)
                {
                    shuffleMode = ShuffleMode.ShuffleOutput;
                    outputStream.SetLength(header.AFCLength);
                }
                else
                    shuffleMode = ShuffleMode.ShuffleInput;
                break;
        }
        byte[] readBuffer = ArrayPool<byte>.Shared.Rent(option.BlockLength);
        byte[] keyBuffer = ArrayPool<byte>.Shared.Rent(option.KeyLength);
        try
        {
            Span<byte> readSpan = readBuffer.AsSpan(0, option.BlockLength);
            Span<byte> keySpan = keyBuffer.AsSpan(0, option.KeyLength);
            BlockHeader bHeader = new()
            {
                PadLength = 0
            };
            int read = header.BlockLength;
            int i = 0;
            while (read == header.BlockLength && (streamMode || i < header.BlockCount))
            {
                switch (shuffleMode)
                {
                    case ShuffleMode.ShuffleInput:
                        inputStream.Position = list[i] * option.BlockLength;
                        break;
                    case ShuffleMode.ShuffleOutput:
                        outputStream.Position = list[i] * rawBlockLength + 64;
                        break;
                }
                read = inputStream.ReadAtLeast(readSpan, option.BlockLength, false);
                Span<byte> toWriteSpan = readSpan[..read];
                bHeader.BlockHash = Hash(toWriteSpan, option.HashMode);
                bHeader.BlockID = i;
                bHeader.WriteTo(outputStream, option.BlockMagicHeader);
                if (!option.NoEncryption)
                {
                    RandomNumberGenerator.Fill(keySpan);
                    XorChunk(toWriteSpan, keySpan);
                }
                outputStream.Write(keySpan);
                if (option.BlockSequenceMode is BlockSequenceMode.Stream)
                    outputStream.Write(toWriteSpan);
                else
                    outputStream.Write(readSpan);
                i++;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(keyBuffer);
            ArrayPool<byte>.Shared.Return(readBuffer);
            ArrayPool<long>.Shared.Return(list);
        }
    }

    private static void XorChunk(Span<byte> chunk, ReadOnlySpan<byte> keys)
    {
        int klen = keys.Length;
        while (chunk.Length > klen)
        {
            TensorPrimitives.Xor(chunk[..klen], keys, chunk);
            chunk = chunk[klen..];
        }
        if (chunk.Length > 0)
            TensorPrimitives.Xor(chunk, keys, chunk);
    }

    private static long Hash(ReadOnlySpan<byte> data, HashMode mode)
    {
        Span<byte> hashBuffer = stackalloc byte[16];
        switch (mode)
        {
            case HashMode.CRC32:
                return CRC32.CalculateCRC32(data);
            case HashMode.MD5Upper64:
                MD5.HashData(data, hashBuffer);
                return BinaryPrimitives.ReadInt64LittleEndian(hashBuffer);
            case HashMode.MD5Lower64:
                MD5.HashData(data, hashBuffer);
                return BinaryPrimitives.ReadInt64LittleEndian(hashBuffer[8..]);
            case HashMode.SHA1Upper64:
                SHA1.HashData(data, hashBuffer);
                return BinaryPrimitives.ReadInt64LittleEndian(hashBuffer);
            case HashMode.SHA1Lower64:
                SHA1.HashData(data, hashBuffer);
                return BinaryPrimitives.ReadInt64LittleEndian(hashBuffer[8..]);
            default:
                return 0;
        }
    }

    private struct AFCHeader
    {
        public long AFCLength;
        public long RawLength;
        public int BlockCount;
        public int BlockLength;
        public int KeyLength;
        public Guid Guid;

        public AFCHeader(long rawlen, int blocklen, int keylen)
        {
            if (rawlen < 0)
            {
                BlockCount = -1;
                AFCLength = -1;
                RawLength = -1;
            }
            else
            {
                BlockCount = (int)CeilingDivide(rawlen, blocklen);
                AFCLength = 64 + (32L + blocklen + keylen) * BlockCount;
                RawLength = rawlen;
            }
            BlockLength = blocklen;
            KeyLength = keylen;
            Guid = Guid.NewGuid();
        }

        public static AFCHeader ReadFrom(Stream source, bool checkHeader, long magicHeader)
        {
            AFCHeader header = new();
            Span<byte> span = stackalloc byte[64];
            source.ReadExactly(span);
            if (checkHeader && magicHeader != BinaryPrimitives.ReadInt64LittleEndian(span))
                throw new InvalidDataException();
            header.AFCLength = BinaryPrimitives.ReadInt64LittleEndian(span[8..]);
            header.RawLength = BinaryPrimitives.ReadInt64LittleEndian(span[16..]);
            header.BlockCount = (int)BinaryPrimitives.ReadInt64LittleEndian(span[24..]);
            header.BlockLength = (int)BinaryPrimitives.ReadInt64LittleEndian(span[32..]);
            header.KeyLength = (int)BinaryPrimitives.ReadInt64LittleEndian(span[40..]);
            header.Guid = new(span[48..], false);
            return header;
        }

        public readonly void WriteTo(Stream destination, long magicHeader)
        {
            Span<byte> span = stackalloc byte[64];
            BinaryPrimitives.WriteInt64LittleEndian(span, magicHeader);
            BinaryPrimitives.WriteInt64LittleEndian(span[8..], AFCLength);
            BinaryPrimitives.WriteInt64LittleEndian(span[16..], RawLength);
            BinaryPrimitives.WriteInt64LittleEndian(span[24..], BlockCount);
            BinaryPrimitives.WriteInt64LittleEndian(span[32..], BlockLength);
            BinaryPrimitives.WriteInt64LittleEndian(span[40..], KeyLength);
            Guid.TryWriteBytes(span[48..], false, out _);
            destination.Write(span);
        }

        public readonly void Validate()
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(KeyLength, 1);
            ArgumentOutOfRangeException.ThrowIfLessThan(BlockLength, 1);
        }
    }
    private struct BlockHeader
    {
        public long PadLength, BlockID, BlockHash;

        public static BlockHeader ReadFrom(Stream source, bool checkHeader, long magicHeader)
        {
            BlockHeader header = new();
            Span<byte> span = stackalloc byte[32];
            source.ReadExactly(span);
            if (checkHeader && magicHeader != BinaryPrimitives.ReadInt64LittleEndian(span))
                throw new InvalidDataException();
            header.PadLength = BinaryPrimitives.ReadInt64LittleEndian(span[8..]);
            header.BlockID = BinaryPrimitives.ReadInt64LittleEndian(span[16..]);
            header.BlockHash = BinaryPrimitives.ReadInt64LittleEndian(span[24..]);
            return header;
        }

        public readonly void WriteTo(Stream destination, long magicHeader)
        {
            Span<byte> span = stackalloc byte[32];
            BinaryPrimitives.WriteInt64LittleEndian(span, magicHeader);
            BinaryPrimitives.WriteInt64LittleEndian(span[8..], PadLength);
            BinaryPrimitives.WriteInt64LittleEndian(span[16..], BlockID);
            BinaryPrimitives.WriteInt64LittleEndian(span[24..], BlockHash);
            destination.Write(span);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static long CeilingDivide(long dividend, int divisor)
    {
        return (dividend + (divisor - 1)) / divisor;
    }

    private enum ShuffleMode
    {
        None,
        ShuffleInput,
        ShuffleOutput,
    }
}
