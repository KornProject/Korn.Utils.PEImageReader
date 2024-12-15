using Korn;
using System.Runtime.InteropServices;
using System.Text;

namespace Korn.Utils.PEImageReader;
public unsafe class PEImage : IDisposable
{
    public PEImage(string path) : this(File.ReadAllBytes(path)) { }

    public PEImage(byte[] bytes)
    {
        handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
        Base = (byte*)handle.AddrOfPinnedObject();
        PEBase = Base + e_lfanew;

        Verify();
    }

    GCHandle handle;
    public readonly byte* Base;
    public readonly byte* PEBase;

    uint e_lfanew => *(uint*)(Base + 0x3C);

    public ImageFileHeader* FileHeader => (ImageFileHeader*)(PEBase + 0x04);
    public ImageOptionalHeader64* OptionalHeader => (ImageOptionalHeader64*)((byte*)FileHeader + 0x14);
    public ImageSectionHeader* SectionHeader => (ImageSectionHeader*)((byte*)FileHeader + sizeof(ImageFileHeader) + FileHeader->SizeOfOptionalHeader);

    public ImageExportDirectory* ExportTableDirectory => (ImageExportDirectory*)(Base + RvaToFileOffset(OptionalHeader->ExportTable.VirtualAddress));
    public ImageDebugDirectory* DebugDirectory => (ImageDebugDirectory*)(Base + RvaToFileOffset(OptionalHeader->Debug.VirtualAddress));
    public NotImplementedImageDirectory* ImportTableDirectory => (NotImplementedImageDirectory*)(Base + RvaToFileOffset(OptionalHeader->ImportTable.VirtualAddress));
    public NotImplementedImageDirectory* ResourceTableDirectory => (NotImplementedImageDirectory*)(Base + RvaToFileOffset(OptionalHeader->ResourceTable.VirtualAddress));
    public NotImplementedImageDirectory* ExceptionTableDirectory => (NotImplementedImageDirectory*)(Base + RvaToFileOffset(OptionalHeader->ExceptionTable.VirtualAddress));
    public NotImplementedImageDirectory* CertificateTableDirectory => (NotImplementedImageDirectory*)(Base + RvaToFileOffset(OptionalHeader->CertificateTable.VirtualAddress));
    public NotImplementedImageDirectory* BaseRelocationTableDirectory => (NotImplementedImageDirectory*)(Base + RvaToFileOffset(OptionalHeader->BaseRelocationTable.VirtualAddress));
    public NotImplementedImageDirectory* ArchitectureDirectory => (NotImplementedImageDirectory*)(Base + RvaToFileOffset(OptionalHeader->Architecture.VirtualAddress));
    public NotImplementedImageDirectory* GlobalPtrDirectory => (NotImplementedImageDirectory*)(Base + RvaToFileOffset(OptionalHeader->GlobalPtr.VirtualAddress));
    public NotImplementedImageDirectory* TLSTableDirectory => (NotImplementedImageDirectory*)(Base + RvaToFileOffset(OptionalHeader->TLSTable.VirtualAddress));
    public NotImplementedImageDirectory* LoadConfigTableDirectory => (NotImplementedImageDirectory*)(Base + RvaToFileOffset(OptionalHeader->LoadConfigTable.VirtualAddress));
    public NotImplementedImageDirectory* BoundImportDirectory => (NotImplementedImageDirectory*)(Base + RvaToFileOffset(OptionalHeader->BoundImport.VirtualAddress));
    public NotImplementedImageDirectory* IATDirectory => (NotImplementedImageDirectory*)(Base + RvaToFileOffset(OptionalHeader->IAT.VirtualAddress));
    public NotImplementedImageDirectory* DelayImportDescriptorDirectory => (NotImplementedImageDirectory*)(Base + RvaToFileOffset(OptionalHeader->DelayImportDescriptor.VirtualAddress));
    public NotImplementedImageDirectory* CLRRuntimeHeaderDirectory => (NotImplementedImageDirectory*)(Base + RvaToFileOffset(OptionalHeader->CLRRuntimeHeader.VirtualAddress));

    public ImageSectionHeader* GetSectionByNumber(int number) => SectionHeader + (number - 1);
    public ImageSectionHeader* GetSectionByIndex(int index) => SectionHeader + index;

    public DebugSymbolsInfo? ReadDegubInfo()
    {
        uint RSDS_TYPE_SIGNATURE = 0x53445352;

        var entry = Base + DebugDirectory->PointerToRawData;

        var type = *(uint*)entry;
        if (type != RSDS_TYPE_SIGNATURE)
            return null;
        entry += sizeof(uint);

        // can be replaced by a specific implementation of Guid, but this way was chosen
        var formatted = stackalloc byte[16];
        formatted[0] = entry[3];
        formatted[1] = entry[2];
        formatted[2] = entry[1];
        formatted[3] = entry[0];

        formatted[4] = entry[5];
        formatted[5] = entry[4];

        formatted[6] = entry[7];
        formatted[7] = entry[6];

        *((long*)formatted + 1)= *((long*)entry + 1);

        var signature = string.Concat(new Span<byte>(formatted, 16).ToArray().Select(b => $"{b:X2}"));
        entry += sizeof(Guid);

        var age = *(uint*)entry;
        entry += sizeof(uint);

        var pathLength = 0;
        for (var i = 0; ; i++)
            if (entry[i] != 0x00)
                pathLength++;
            else break;
        var path = Encoding.UTF8.GetString(entry, pathLength);

        return new(signature, age, path);
    }

    public uint RvaToFileOffset(uint rva)
    {
        for (int i = 0; i < FileHeader->NumberOfSections; i++)
        {
            var section = SectionHeader + i;
            if (rva >= section->VirtualAddress && rva < section->VirtualAddress + section->SizeOfRawData)
                return rva - section->VirtualAddress + section->PointerToRawData;
        }
        return 0;
    }

    void Verify()
    {
        const ushort IMAGE_DOS_SIGNATURE = 0x5A4D;
        const uint IMAGE_NT_SIGNATURE = 0x00004550;
        const ushort IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b;

        var dosSignature = *(ushort*)Base;
        if (dosSignature != IMAGE_DOS_SIGNATURE)
            throw new KornError([
                "PEImage->Verify:",
                "PE Image has invalid DOS signature.",
                $"Signature: {dosSignature:X2}, expected:{IMAGE_DOS_SIGNATURE:X2}"
            ]);

        var peSignature = *(uint*)PEBase;
        if (peSignature != IMAGE_NT_SIGNATURE)
            throw new KornError([
                "PEImage->Verify:",
                "PE Image has invalid PE signature.",
                $"Signature: {peSignature:X2}, expected:{IMAGE_NT_SIGNATURE:X2}"
            ]);

        if (OptionalHeader->Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            throw new KornError([
                "PEImage->Verify:",
                "PE Image has invalid optional header magic.",
                $"Magic: {OptionalHeader->Magic:X2}, expected:{IMAGE_NT_OPTIONAL_HDR64_MAGIC:X2}",
                "This may indicate that the file has the wrong bitness."
            ]);
    }

    #region IDisposable
    bool disposed;
    public void Dispose()
    {
        if (disposed)
            return;
        disposed = true;

        handle.Free();
    }

    ~PEImage() => Dispose();
    #endregion
}

public record DebugSymbolsInfo(string Signature, uint Age, string Path)
{
    public string GetMicrosoftDebugSymbolsCacheUrl()
    {
        var fileName = System.IO.Path.GetFileName(Path);
        return $"http://msdl.microsoft.com/download/symbols/{fileName}/{Signature + Age}/{fileName}";
    }
}

public struct NotImplementedImageDirectory;

[StructLayout(LayoutKind.Sequential)]
public struct ImageDebugDirectory
{
    public uint Characteristics;
    public uint TimeDateStamp;
    public ushort MajorVersion;
    public ushort MinorVersion;
    public uint Type;
    public uint SizeOfData;
    public uint AddressOfRawData;
    public uint PointerToRawData;
}

[StructLayout(LayoutKind.Sequential)]
public struct ImageExportDirectory
{
    public uint Characteristics;
    public uint TimeDateStamp;
    public ushort MajorVersion;
    public ushort MinorVersion;
    public uint Name;
    public uint Base;
    public uint NumberOfFunctions;
    public uint NumberOfNames;
    public uint AddressOfFunctions;
    public uint AddressOfNames;
    public uint AddressOfNameOrdinals;
}

[StructLayout(LayoutKind.Sequential)]
public struct ImageFileHeader
{
    public ushort Machine;
    public ushort NumberOfSections;
    public uint TimeDateStamp;
    public uint PointerToSymbolTable;
    public uint NumberOfSymbols;
    public ushort SizeOfOptionalHeader;
    public ushort Characteristics;
}

[StructLayout(LayoutKind.Sequential)]
public struct ImageOptionalHeader64
{
    public ushort Magic;
    public byte MajorLinkerVersion;
    public byte MinorLinkerVersion;
    public uint SizeOfCode;
    public uint SizeOfInitializedData;
    public uint SizeOfUninitializedData;
    public uint AddressOfEntryPoint;
    public uint BaseOfCode;
    public ulong ImageBase;
    public uint SectionAlignment;
    public uint FileAlignment;
    public ushort MajorOperatingSystemVersion;
    public ushort MinorOperatingSystemVersion;
    public ushort MajorImageVersion;
    public ushort MinorImageVersion;
    public ushort MajorSubsystemVersion;
    public ushort MinorSubsystemVersion;
    public uint Win32VersionValue;
    public uint SizeOfImage;
    public uint SizeOfHeaders;
    public uint CheckSum;
    public ushort Subsystem;
    public ushort DllCharacteristics;
    public ulong SizeOfStackReserve;
    public ulong SizeOfStackCommit;
    public ulong SizeOfHeapReserve;
    public ulong SizeOfHeapCommit;
    public uint LoaderFlags;
    public uint NumberOfRvaAndSizes;

    public ImageDataDirectory ExportTable;
    public ImageDataDirectory ImportTable;
    public ImageDataDirectory ResourceTable;
    public ImageDataDirectory ExceptionTable;
    public ImageDataDirectory CertificateTable;
    public ImageDataDirectory BaseRelocationTable;
    public ImageDataDirectory Debug;
    public ImageDataDirectory Architecture;
    public ImageDataDirectory GlobalPtr;
    public ImageDataDirectory TLSTable;
    public ImageDataDirectory LoadConfigTable;
    public ImageDataDirectory BoundImport;
    public ImageDataDirectory IAT;
    public ImageDataDirectory DelayImportDescriptor;
    public ImageDataDirectory CLRRuntimeHeader;
    public ImageDataDirectory Reserved;
}

[StructLayout(LayoutKind.Sequential)]
public struct ImageDataDirectory
{
    public uint VirtualAddress;
    public uint Size;
}

[StructLayout(LayoutKind.Sequential)]
public unsafe struct ImageSectionHeader
{
    public fixed byte Name[8];
    public uint VirtualSize;
    public uint VirtualAddress;
    public uint SizeOfRawData;
    public uint PointerToRawData;
    public uint PointerToRelocations;
    public uint PointerToLinenumbers;
    public ushort NumberOfRelocations;
    public ushort NumberOfLinenumbers;
    public uint Characteristics;
}