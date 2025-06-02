using Korn.Utils;
using Korn.Utils.PEImageReader;
using System.Diagnostics;
using System.Net;

unsafe
{
    using var pe = new PEImage(@"C:\Program Files\dotnet\shared\Microsoft.NETCore.App\8.0.11\coreclr.dll");

    var debugInfo = pe.ReadDegubInfo()!;

    _ = 3;
}