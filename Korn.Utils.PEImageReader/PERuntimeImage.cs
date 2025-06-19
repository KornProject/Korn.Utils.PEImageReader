using Korn.Modules.Algorithms;
using System;
using System.Linq;
using System.Reflection;
using System.Text;

#pragma warning disable CS8500 // This takes the address of, gets the size of, or declares a pointer to a managed type
namespace Korn.Utils.PEImageReader
{
    public unsafe class PERuntimeImage
    {
        public PERuntimeImage(IntPtr processHandle, IntPtr pointer) : this(*(ProcessMemory*)&processHandle, pointer) { }

        public PERuntimeImage(ProcessMemory memory, IntPtr pointer)
        {
            this.memory = memory;
            Pointer = (long)pointer;

            var e_lfanew = memory.Read<uint>((IntPtr)(Pointer + 0x3C));
            var fileHeaderPointer = Pointer + e_lfanew + 4;

            OptionalHeader = memory.Read<ImageOptionalHeader64>((IntPtr)(Pointer + e_lfanew + 4 + 20));
            FileHeader = memory.Read<ImageFileHeader>((IntPtr)(fileHeaderPointer));
            ExportDirectory = memory.Read<ImageExportDirectory>((IntPtr)(Pointer + OptionalHeader.ExportTable.VirtualAddress));
            DebugDirectory = memory.Read<ImageDebugDirectory>((IntPtr)(Pointer + OptionalHeader.Debug.VirtualAddress));
            SectionHeaderAddress = fileHeaderPointer + sizeof(ImageFileHeader) + FileHeader.SizeOfOptionalHeader;
        }

        ProcessMemory memory;
        public readonly long Pointer;

        public ImageOptionalHeader64 OptionalHeader;
        public ImageFileHeader FileHeader;
        public ImageExportDirectory ExportDirectory;
        public ImageDebugDirectory DebugDirectory;
        public long SectionHeaderAddress;

        public uint ExportFunctionsCount => ExportDirectory.NumberOfNames;

        public DebugSymbolsInfo ReadDegubInfo()
        {
            {
                uint RSDS_TYPE_SIGNATURE = 0x53445352;

                var address = Pointer + DebugDirectory.PointerToRawData;

                var typeSignature = ReadTypeSignature(&address);
                if (typeSignature != RSDS_TYPE_SIGNATURE)
                    return null;

                var signature = ReadSignature(&address);
                var age = ReadAge(&address);
                var path = ReadPath(address);
                return new DebugSymbolsInfo(signature, age, path);
            }

            uint ReadTypeSignature(long* address)
            {
                var typeSignature = memory.Read<uint>((IntPtr)(*address));
                *address += sizeof(uint);
                return typeSignature;
            }

            string ReadSignature(long* address)
            {
                var bytes = memory.Read((IntPtr)(*address), sizeof(Guid));
                var guid = new Guid(bytes);
                var signature = guid.ToString("N").ToUpper();
                *address += sizeof(Guid);
                return signature;
            }

            uint ReadAge(long* address)
            {
                var age = memory.Read<uint>((IntPtr)(*address));
                *address += sizeof(uint);
                return age;
            }

            string ReadPath(long address) => memory.ReadUTF8((IntPtr)address);
        }

        public IntPtr GetExportFunctionAddress(string name) => (IntPtr)(Pointer + (long)GetEATFunction(name));

        public IntPtr GetExportFunctionAddress(int index) => (IntPtr)(Pointer + (long)GetExportFunctionRva(index));

        public uint GetExportFunctionRva(int index) => memory.Read<uint>((IntPtr)(Pointer + ExportDirectory.AddressOfFunctions + index * sizeof(uint)));

        public uint GetExportFunctionNameRva(int index) => memory.Read<uint>((IntPtr)(Pointer + ExportDirectory.AddressOfNames + index * sizeof(uint)));

        public string GetNameOfExportFunction(uint nameRva) => memory.ReadUTF8((IntPtr)(Pointer + nameRva));

        uint GetEATFunction(string name)
        {
            var index = GetEATFunctionIndex(name);
            if (index == -1)
                return 0;
            else return GetExportFunctionRva(index);
        }

        int GetEATFunctionIndex(string targetName)
        {
            for (int i = 0; i < ExportDirectory.NumberOfNames; i++)
            {
                var nameRva = GetExportFunctionNameRva(i);
                var name = GetNameOfExportFunction(nameRva);

                if (targetName == name)
                    return i;
            }
            return -1;
        }

        public ImageSectionHeader GetSectionByNumber(int number) => GetSectionByIndex(number - 1);

        public ImageSectionHeader GetSectionByIndex(int index) => memory.Read<ImageSectionHeader>((IntPtr)(SectionHeaderAddress + index * sizeof(ImageSectionHeader)));

        public class Cache
        {
            public Cache(Process process)
            {
                var memory = process.Memory;
                var moduleHandle = process.Handle;
                pe = new PERuntimeImage(memory, (IntPtr)moduleHandle);

                var functionCount = pe.ExportFunctionsCount;
                functions = new Function[functionCount];
                for (var index = 0; index < functionCount; index++)
                {
                    var nameRva = pe.GetExportFunctionNameRva(index);
                    var name = pe.GetNameOfExportFunction(nameRva);
                    var rva = pe.GetExportFunctionRva(index);
                    functions[index] = new Function(name, rva);
                }
            }

            PERuntimeImage pe;
            Function[] functions;

            public uint GetFunctionRva(string name)
            {
                var hash = HashedString.CalculateHash(name);
                foreach (var function in functions)
                    if (function.Name.Hash == hash)
                        return function.RVA;
                return 0;
            }

            struct Function
            {
                public Function(string name, uint rva) : this(new HashedString(name), rva) { }
                public Function(HashedString name, uint rva) => (Name, RVA) = (name, rva);

                public HashedString Name;
                public uint RVA;
            }
        }
    }
}