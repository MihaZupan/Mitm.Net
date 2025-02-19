using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text.Json;
using System.Runtime.CompilerServices;

namespace Mitm.Net;

public static class MitmCertificateStore
{
    private const string CACommonName = "localhost";
    private const string CAOrgName = "Mitm.Net CA";

    private static readonly JsonSerializerOptions s_jsonOptions = new()
    {
        IncludeFields = true,
        WriteIndented = true
    };

    private static readonly RSAParameters s_caRsaParameters;
    private static readonly RSA s_caRsa;
    private static readonly byte[] s_caPublicKeyDer;

    static MitmCertificateStore()
    {
        string caInfoPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "MitmCA.json");

        if (!File.Exists(caInfoPath))
        {
            using RSA caRsa = RSA.Create(2048);
            RSAParameters rsaParameters = caRsa.ExportParameters(includePrivateParameters: true);
            File.WriteAllText(caInfoPath, JsonSerializer.Serialize(rsaParameters, s_jsonOptions));
        }

        s_caRsaParameters = JsonSerializer.Deserialize<RSAParameters>(File.ReadAllText(caInfoPath), s_jsonOptions);
        s_caRsa = RSA.Create(s_caRsaParameters);
        s_caPublicKeyDer = GetPublicKeyDer(s_caRsaParameters);
    }

    [ModuleInitializer]
    internal static void InitCACert()
    {
        if (!File.Exists("MitmCA.pfx"))
        {
            string certPem = GenerateCertificate(CACommonName, s_caPublicKeyDer, s_caRsa, ca: true);
            string keyPem = GetPrivateKeyPem(s_caRsaParameters);

            using X509Certificate2 caCert = X509Certificate2.CreateFromPem(certPem, keyPem);
            File.WriteAllBytes("MitmCA.pfx", caCert.Export(X509ContentType.Pfx));

            Console.WriteLine("Install MitmCA.pfx in the trusted store. Press enter when finished.");
            Console.ReadLine();
        }
    }

    public static X509Certificate2 GetCertificate(string commonName)
    {
        string certPem = GenerateCertificate(commonName, s_caPublicKeyDer, s_caRsa, ca: false);
        string keyPem = GetPrivateKeyPem(s_caRsaParameters);

        using X509Certificate2 tempCert = X509Certificate2.CreateFromPem(certPem, keyPem);
        return X509CertificateLoader.LoadPkcs12(tempCert.Export(X509ContentType.Pkcs12), password: null);
    }

    private static string GenerateCertificate(string commonName, byte[] publicKeyDer, RSA issuerRsa, bool ca)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);

        using (writer.PushSequence())
        {
            byte[] serialNumber = RandomNumberGenerator.GetBytes(16);

            WriteCertTBS(writer, serialNumber, commonName, publicKeyDer, ca);

            AsnWriter tbsWriter = new(AsnEncodingRules.DER);
            WriteCertTBS(tbsWriter, serialNumber, commonName, publicKeyDer, ca);

            byte[] signature = issuerRsa.SignData(tbsWriter.Encode(), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            // signatureAlgorithm
            using (writer.PushSequence())
            {
                // sha256WithRSAEncryption
                writer.WriteObjectIdentifier("1.2.840.113549.1.1.11");
                writer.WriteNull();
            }

            writer.WriteBitString(signature);
        }

        return GetPem(writer, "CERTIFICATE");
    }

    private static void WriteCertTBS(AsnWriter writer, byte[] serialNumber, string commonName, byte[] publicKeyDer, bool ca)
    {
        using (writer.PushSequence())
        {
            // version ([0] EXPLICIT INTEGER)
            var context0 = new Asn1Tag(TagClass.ContextSpecific, 0, true);

            using (writer.PushSequence(context0))
            {
                writer.WriteInteger(2);
            }

            // serial number
            writer.WriteInteger(new BigInteger(serialNumber, isUnsigned: true));

            // signature (algorithm)
            using (writer.PushSequence())
            {
                // sha256WithRSAEncryption
                writer.WriteObjectIdentifier("1.2.840.113549.1.1.11");
                writer.WriteNull();
            }

            // issuer
            using (writer.PushSequence())
            {
                WriteRdn(writer, "2.5.4.10", CAOrgName, UniversalTagNumber.PrintableString);
                WriteRdn(writer, "2.5.4.3", CACommonName, UniversalTagNumber.UTF8String);
            }

            // validity
            using (writer.PushSequence())
            {
                writer.WriteUtcTime(DateTimeOffset.UtcNow.Subtract(TimeSpan.FromDays(2)));
                writer.WriteUtcTime(DateTimeOffset.UtcNow.Add(TimeSpan.FromDays(180)));
            }

            // subject
            using (writer.PushSequence())
            {
                if (ca)
                {
                    WriteRdn(writer, "2.5.4.10", CAOrgName, UniversalTagNumber.PrintableString);
                }

                WriteRdn(writer, "2.5.4.3", commonName, UniversalTagNumber.UTF8String);
            }

            // subjectPublicKeyInfo
            using (writer.PushSequence())
            {
                // subjectPublicKeyInfo.algorithm
                using (writer.PushSequence())
                {
                    // rsaEncryption
                    writer.WriteObjectIdentifier("1.2.840.113549.1.1.1");
                    writer.WriteNull();
                }

                // subjectPublicKeyInfo.subjectPublicKey
                writer.WriteBitString(publicKeyDer);
            }

            // extensions ([3] EXPLICIT Extensions)
            var context3 = new Asn1Tag(TagClass.ContextSpecific, 3);

            using (writer.PushSequence(context3))
            {
                using (writer.PushSequence())
                {
                    var dnsName = new Asn1Tag(TagClass.ContextSpecific, 2);

                    // subjectAltName
                    using (writer.PushSequence())
                    {
                        writer.WriteObjectIdentifier("2.5.29.17");

                        using (writer.PushOctetString())
                        using (writer.PushSequence())
                        {
                            writer.WriteCharacterString(UniversalTagNumber.IA5String, commonName, dnsName);
                        }
                    }

                    // extKeyUsage
                    using (writer.PushSequence())
                    {
                        writer.WriteObjectIdentifier("2.5.29.37");

                        using (writer.PushOctetString())
                        using (writer.PushSequence())
                        {
                            // serverAuth
                            writer.WriteObjectIdentifier("1.3.6.1.5.5.7.3.1");
                        }
                    }

                    // basicConstraints
                    if (ca)
                    {
                        using (writer.PushSequence())
                        {
                            writer.WriteObjectIdentifier("2.5.29.19");

                            writer.WriteBoolean(true);

                            using (writer.PushOctetString())
                            using (writer.PushSequence())
                            {
                                writer.WriteBoolean(true);
                            }
                        }
                    }

                    // authorityKeyIdentifier
                    if (!ca)
                    {
                        using (writer.PushSequence())
                        {
                            writer.WriteObjectIdentifier("2.5.29.35");

                            Asn1Tag keyIdentifier = context0;
                            byte[] authorityKeyIdentifier = SHA1.HashData(publicKeyDer);

                            using (writer.PushOctetString())
                            using (writer.PushSequence())
                            {
                                writer.WriteOctetString(authorityKeyIdentifier, keyIdentifier);
                            }
                        }
                    }
                }
            }
        }
    }

    private static byte[] GetPublicKeyDer(RSAParameters parameters)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);

        using (writer.PushSequence())
        {
            WriteIntegerFromRsaParameters(writer, parameters.Modulus);
            WriteIntegerFromRsaParameters(writer, parameters.Exponent);
        }

        return writer.Encode();
    }

    private static string GetPrivateKeyPem(RSAParameters parameters)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);

        using (writer.PushSequence())
        {
            writer.WriteInteger(0);
            WriteIntegerFromRsaParameters(writer, parameters.Modulus);
            WriteIntegerFromRsaParameters(writer, parameters.Exponent);
            WriteIntegerFromRsaParameters(writer, parameters.D);
            WriteIntegerFromRsaParameters(writer, parameters.P);
            WriteIntegerFromRsaParameters(writer, parameters.Q);
            WriteIntegerFromRsaParameters(writer, parameters.DP);
            WriteIntegerFromRsaParameters(writer, parameters.DQ);
            WriteIntegerFromRsaParameters(writer, parameters.InverseQ);
        }

        return GetPem(writer, "RSA PRIVATE KEY");
    }

    private static void WriteIntegerFromRsaParameters(AsnWriter writer, byte[]? parameter)
    {
        ArgumentNullException.ThrowIfNull(parameter);

        writer.WriteInteger(new BigInteger(parameter, isUnsigned: true, isBigEndian: true));
    }

    private static string GetPem(AsnWriter writer, string type)
    {
        string der = Convert.ToBase64String(writer.Encode());
        return $"-----BEGIN {type}-----\n{der}\n-----END {type}-----";
    }

    private static void WriteRdn(AsnWriter writer, string oid, string value, UniversalTagNumber valueType)
    {
        using (writer.PushSetOf())
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(oid);
            writer.WriteCharacterString(valueType, value);
        }
    }
}
