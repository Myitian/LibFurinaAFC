namespace LibFurinaAFC;

public enum HashMode : byte
{
    None,
    CRC32,
    MD5Upper64,
    MD5Lower64,
    SHA1Upper64,
    SHA1Lower64
}