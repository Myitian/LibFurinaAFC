using System.Text;

namespace Example;

public static class Extension
{
    public static StringBuilder AppendPadLeft(this StringBuilder sb, string text, int width)
    {
        return sb.Append(text).Append(' ', Math.Max(width - text.Length, 0));
    }
    public static StringBuilder AppendPadRight(this StringBuilder sb, int number, int width)
    {
        string text = number.ToString();
        return sb.Append(' ', Math.Max(width - text.Length, 0)).Append(text);
    }
}