using Korn.Utils.PEImageReader;
using System.Net;

unsafe
{
    using var pe = new PEImage(@"C:\Program Files\dotnet\shared\Microsoft.NETCore.App\8.0.11\coreclr.dll");

    var debugInfo = pe.ReadDegubInfo()!;

    var sec = pe.GetSectionByNumber(4);

    var a = (char)sec->Name[1];

    var signature = debugInfo.Signature + debugInfo.Age;
    var fileName = Path.GetFileName(debugInfo.Path);
    var debugUrl = $"http://msdl.microsoft.com/download/symbols/{fileName}/{signature}/{fileName}";

    new WebClient().DownloadFile(debugUrl, @"C:\a.pdb");

    _ = 3;
}