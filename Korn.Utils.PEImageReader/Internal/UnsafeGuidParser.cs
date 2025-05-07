using Korn.Utils;

static unsafe class UnsafeGuidParser
{
    const int GuidSize = 16;

    public static string Parse(ExternalMemory memory, Address adress, out int read)
    {
        read = GuidSize;
        var byteArray = memory.Read(adress, GuidSize);
        return Parse(byteArray);
    }

    public static string Parse(ExternalMemory memory, Address adress)
    {
        var byteArray = memory.Read(adress, GuidSize);
        return Parse(byteArray);
    }
    
    public static string Parse(byte[] byteArray)
    {
        fixed (byte* bytes = byteArray)
            return Parse(bytes);
    }   

    public static string Parse(byte* bytes, out int read)
    {
        read = GuidSize;
        return Parse(bytes);
    }

    public static string Parse(byte* bytes)
    {
        var u8 = *(ulong*)bytes;
        var u4 = (uint)u8;
        var u2a = (u8 >> 32) & 0xFFFF;
        var u2b = (u8 >> 48) & 0xFFFF;
        *(ulong*)bytes = (u4 >> 24) | ((u4 >> 8) & 0xFF00) | ((u4 & 0xFF00) << 8) | (u4 << 24) | (((u2a >> 8) | ((u2a & 0xFF) << 8)) << 32) | (((u2b >> 8) | ((u2b & 0xFF) << 8)) << 48);

        return ParseFromNormalizedBytes(bytes);
    }

    public static string ParseFromNormalizedBytes(byte* bytes)
    {
        const int FormatedByteLength = 2;

        var length = GuidSize * FormatedByteLength;
        var stringCharArray = new char[length];
        fixed (char* stringChars = stringCharArray)
            for (var index = 0; index < GuidSize; index++)
                ((uint*)stringChars)[index] = ParseByte(bytes[index]);

        return new string(stringCharArray);
    }

    static uint ParseByte(byte input)
    {
        const char zero = '0', a = 'A';

        var result = 0U;

        var left = (input & 0xF0U) >> 4;
        if (left <= 9)
            result |= zero + left;
        else result |= a + (left - 10);

        var right = input & 0x0FU;
        if (right <= 9)
            result |= (zero + right) << 16;
        else result |= (a + (right - 10)) << 16;

        return result;
    }
}