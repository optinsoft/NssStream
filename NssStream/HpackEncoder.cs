namespace NssSsl;

using System.Text;

public sealed class HpackEncoder
{
    private readonly Stream _stream;

    public HpackEncoder(Stream stream)
    {
        _stream = stream;
    }

    public void WriteIndexed(int index)
    {
        // Indexed Header Field:
        // 1xxxxxxx
        WriteInteger(index, 7, 0x80);
    }

    public void WriteLiteralWithoutIndexing(string name, string value)
    {
        // Literal Header Field without Indexing,
        // new name:
        // 0000xxxx
        WriteInteger(0, 4, 0x00);

        WriteString(name);
        WriteString(value);
    }

    public void WriteLiteralWithoutIndexing(int nameIndex, string value)
    {
        // Literal Header Field without Indexing,
        // indexed name:
        // 0000xxxx
        WriteInteger(nameIndex, 4, 0x00);

        WriteString(value);
    }

    private void WriteInteger(int value, int prefixBits, byte prefix)
    {
        int max = (1 << prefixBits) - 1;

        if (value < max)
        {
            _stream.WriteByte((byte)(prefix | value));
            return;
        }

        _stream.WriteByte((byte)(prefix | max));

        value -= max;

        while (value >= 128)
        {
            _stream.WriteByte((byte)((value & 0x7f) | 0x80));
            value >>= 7;
        }

        _stream.WriteByte((byte)value);
    }

    private void WriteString(string value)
    {
        byte[] bytes = Encoding.ASCII.GetBytes(value);

        // String Literal without Huffman encoding.
        WriteInteger(bytes.Length, 7, 0x00);

        _stream.Write(bytes, 0, bytes.Length);
    }
}