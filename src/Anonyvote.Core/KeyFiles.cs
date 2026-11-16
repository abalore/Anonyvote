using System.Security.Cryptography;

namespace Anonyvote.Core;

/// <summary>Loading and saving RSA keys as PEM. Private keys are written with mode 600.</summary>
public static class KeyFiles
{
    public static void SavePrivate(RSA key, string path)
    {
        File.WriteAllText(path, key.ExportPkcs8PrivateKeyPem());
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    public static RSA LoadPrivate(string path)
    {
        var rsa = RSA.Create();
        rsa.ImportFromPem(File.ReadAllText(path));
        return rsa;
    }

    public static string PublicPem(RSA key) => key.ExportSubjectPublicKeyInfoPem();

    public static RSA FromPublicPem(string pem)
    {
        var rsa = RSA.Create();
        rsa.ImportFromPem(pem);
        return rsa;
    }

    public static RSA FromPrivatePem(string pem)
    {
        var rsa = RSA.Create();
        rsa.ImportFromPem(pem);
        return rsa;
    }
}
