namespace LibFurinaAFC;

public struct AFCOptions()
{
    public int KeyLength = 256;
    public int BlockLength = 1048576;
    public bool NoEncryption = false;
    public BlockSequenceMode BlockSequenceMode = BlockSequenceMode.Auto;
    public HashMode HashMode = HashMode.None;
    public bool ValidateHash = false;
    public bool ValidateMainMagicHeader = false;
    public bool ValidateBlockMagicHeader = false;
    public long MainMagicHeader = 0x2107616E69727546;
    public long BlockMagicHeader = 0x2107616E69727546;
}
public enum BlockSequenceMode
{
    Auto,
    Random,
    Sequence,
    Stream
}