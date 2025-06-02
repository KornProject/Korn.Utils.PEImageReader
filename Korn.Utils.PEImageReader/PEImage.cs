using System.Runtime.InteropServices;
using System.Linq;
using System.Text;
using System.IO;
using System;
using System.Reflection;

namespace Korn.Utils.PEImageReader
{
    public unsafe class PEImage : IDisposable
    {
        public PEImage(string path) : this(File.ReadAllBytes(path)) { }

        public PEImage(byte[] bytes)
        {
            this.bytes = bytes;
            bytesHandle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            Pointer = (byte*)bytesHandle.AddrOfPinnedObject();

            var e_lfanew = *(uint*)(Pointer + 0x3C);
            PEPointer = Pointer + e_lfanew;
            FileHeader = (ImageFileHeader*)(PEPointer + 0x04);
            OptionalHeader = (ImageOptionalHeader64*)((byte*)FileHeader + 0x14);
            SectionHeader = (ImageSectionHeader*)((byte*)FileHeader + sizeof(ImageFileHeader) + FileHeader->SizeOfOptionalHeader);

            VerifySignatures();
        }

        byte[] bytes;
        GCHandle bytesHandle;
        public readonly byte* Pointer;
        public readonly byte* PEPointer;

        public ImageFileHeader* FileHeader;
        public ImageOptionalHeader64* OptionalHeader;
        public ImageSectionHeader* SectionHeader;

        public ImageExportDirectory* ExportTableDirectory => (ImageExportDirectory*)(Pointer + RvaToFileOffset(OptionalHeader->ExportTable.VirtualAddress));
        public ImageDebugDirectory* DebugDirectory => (ImageDebugDirectory*)(Pointer + RvaToFileOffset(OptionalHeader->Debug.VirtualAddress));
        public NotImplementedImageDirectory* ImportTableDirectory => (NotImplementedImageDirectory*)(Pointer + RvaToFileOffset(OptionalHeader->ImportTable.VirtualAddress));
        public NotImplementedImageDirectory* ResourceTableDirectory => (NotImplementedImageDirectory*)(Pointer + RvaToFileOffset(OptionalHeader->ResourceTable.VirtualAddress));
        public NotImplementedImageDirectory* ExceptionTableDirectory => (NotImplementedImageDirectory*)(Pointer + RvaToFileOffset(OptionalHeader->ExceptionTable.VirtualAddress));
        public NotImplementedImageDirectory* CertificateTableDirectory => (NotImplementedImageDirectory*)(Pointer + RvaToFileOffset(OptionalHeader->CertificateTable.VirtualAddress));
        public NotImplementedImageDirectory* BaseRelocationTableDirectory => (NotImplementedImageDirectory*)(Pointer + RvaToFileOffset(OptionalHeader->BaseRelocationTable.VirtualAddress));
        public NotImplementedImageDirectory* ArchitectureDirectory => (NotImplementedImageDirectory*)(Pointer + RvaToFileOffset(OptionalHeader->Architecture.VirtualAddress));
        public NotImplementedImageDirectory* GlobalPtrDirectory => (NotImplementedImageDirectory*)(Pointer + RvaToFileOffset(OptionalHeader->GlobalPtr.VirtualAddress));
        public NotImplementedImageDirectory* TLSTableDirectory => (NotImplementedImageDirectory*)(Pointer + RvaToFileOffset(OptionalHeader->TLSTable.VirtualAddress));
        public NotImplementedImageDirectory* LoadConfigTableDirectory => (NotImplementedImageDirectory*)(Pointer + RvaToFileOffset(OptionalHeader->LoadConfigTable.VirtualAddress));
        public NotImplementedImageDirectory* BoundImportDirectory => (NotImplementedImageDirectory*)(Pointer + RvaToFileOffset(OptionalHeader->BoundImport.VirtualAddress));
        public NotImplementedImageDirectory* IATDirectory => (NotImplementedImageDirectory*)(Pointer + RvaToFileOffset(OptionalHeader->IAT.VirtualAddress));
        public NotImplementedImageDirectory* DelayImportDescriptorDirectory => (NotImplementedImageDirectory*)(Pointer + RvaToFileOffset(OptionalHeader->DelayImportDescriptor.VirtualAddress));
        public NotImplementedImageDirectory* CLRRuntimeHeaderDirectory => (NotImplementedImageDirectory*)(Pointer + RvaToFileOffset(OptionalHeader->CLRRuntimeHeader.VirtualAddress));

        public ImageSectionHeader* GetSectionByNumber(int number) => GetSectionByIndex(number - 1);
        public ImageSectionHeader* GetSectionByIndex(int index) => SectionHeader + index;

        public DebugSymbolsInfo ReadDegubInfo()
        {
            {
                uint RSDS_TYPE_SIGNATURE = 0x53445352;

                var address = Pointer + DebugDirectory->PointerToRawData;

                var typeSignature = ReadTypeSignature(&address);
                if (typeSignature != RSDS_TYPE_SIGNATURE)
                    return null;

                var signature = ReadSignature(&address);
                var age = ReadAge(&address);
                var path = ReadPath(address);
                return new DebugSymbolsInfo(signature, age, path);
            }

            uint ReadTypeSignature(byte** address)
            {
                var typeSignature = *(uint*)*address;
                *address += sizeof(uint);
                return typeSignature;
            }

            string ReadSignature(byte** address)
            {
                var bytes = Memory.Read(*address, sizeof(Guid));
                var guid = new Guid(bytes);
                var signature = guid.ToString("N").ToUpper();
                *address += sizeof(Guid);
                return signature;
            }

            uint ReadAge(byte** address)
            {
                var age = *(uint*)*address;
                *address += sizeof(uint);
                return age;
            }

            string ReadPath(byte* address) => Memory.ReadUTF8(address);
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

        void VerifySignatures()
        {
            const ushort IMAGE_DOS_SIGNATURE = 0x5A4D;
            const uint IMAGE_NT_SIGNATURE = 0x00004550;
            const ushort IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b;

            var dosSignature = *(ushort*)Pointer;
            if (dosSignature != IMAGE_DOS_SIGNATURE)
                throw new KornError(
                    "PEImage->Verify:",
                    "PE Image has invalid DOS signature.",
                    $"Signature: {dosSignature:X}, expected:{IMAGE_DOS_SIGNATURE:X}"
                );

            var peSignature = *(uint*)PEPointer;
            if (peSignature != IMAGE_NT_SIGNATURE)
                throw new KornError(
                    "PEImage->Verify:",
                    "PE Image has invalid PE signature.",
                    $"Signature: {peSignature:X}, expected:{IMAGE_NT_SIGNATURE:X}"
                );

            if (OptionalHeader->Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                throw new KornError(
                    "PEImage->Verify:",
                    "PE Image has invalid optional header magic.",
                    $"Magic: {OptionalHeader->Magic:X}, expected:{IMAGE_NT_OPTIONAL_HDR64_MAGIC:X}",
                    "This may indicate that the file has the wrong bitness."
                );
        }

        #region IDisposable
        bool disposed;
        public void Dispose()
        {
            if (disposed)
                return;
            disposed = true;

            bytesHandle.Free();
        }

        ~PEImage() => Dispose();
        #endregion
    }
}