using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;

namespace aspnet_jwt
{
    public class JWT
    {
        private static readonly char[] base64_padding = { '=' };
        private SHA512 sha512 = SHA512.Create();
        private SHA256 sha256 = SHA256.Create();
        private RSACryptoServiceProvider rsaCryptoServiceProvider;

        public JwtHeader Header { get; set; }
        public JwtBody Body { get; set; }

        [DataContract]
        public class JwtHeader
        {
            [DataMember]
            public string alg = "RS256";
            [DataMember]
            public string type = "JWT";
        }

        [DataContract]
        public class JwtBody
        {
            [DataMember]
            public string jti = Guid.NewGuid().ToString().Replace("-", "");

            // Open ID Connect
            [DataMember]
            public string iss;

            [DataMember]
            public string aud;

            [DataMember]
            public string sub;

            [DataMember]
            public int iat;

            [DataMember]
            public int exp;

            // Custom fields
            [DataMember]
            public string sid; // Session ID

            [DataMember]
            public string uam; // User Authentication method

        }

        public JWT(string pemPrivateKeyString)
        {
            this.Header = new JwtHeader();
            this.Body = new JwtBody();
            this.rsaCryptoServiceProvider = CryptoUtils.CreateRsaProviderFromPrivatePemKey(pemPrivateKeyString);
        }

        public JWT(string jwtString, string pemPublicKey)
        {
            var parts = jwtString.Split('.');
            this.Header = JsonBase64UrlSafeDeSerialize<JwtHeader>(parts[0]);
            this.Body = JsonBase64UrlSafeDeSerialize<JwtBody>(parts[1]);

            // TODO: Verify signature
            byte[] hash = sha512.ComputeHash(Encoding.UTF8.GetBytes(parts[0] + '.' + parts[1]));
            var rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsaCryptoServiceProvider);
            rsaDeformatter.SetHashAlgorithm("SHA256");
            if (!rsaDeformatter.VerifySignature(hash, FromBase64UrlSafeString(parts[2])))
            {
                throw new Exception("Failed to verify signature");
            }

            // TODO: Check if the token is expired
            // TODO: Check nbf
            // TODO: Check aud
        }

        public string SignAndEncode()
        {
            var headerBodyString = JsonBase64UrlSafeSerialize(Header) + "." + JsonBase64UrlSafeSerialize(Body);
            var signBytes = rsaCryptoServiceProvider.SignData(Encoding.UTF8.GetBytes(headerBodyString), sha256);
            var token = headerBodyString + "." + ToBase64UrlSafeString(signBytes);
            return token;
        }

        private static string JsonBase64UrlSafeSerialize<T>(T obj)
        {
            using (var memoryStream = new MemoryStream())
            {
                var jsonSerializer = new DataContractJsonSerializer(typeof(T));
                jsonSerializer.WriteObject(memoryStream, obj);
                memoryStream.Position = 0;
                return ToBase64UrlSafeString(memoryStream.ToArray());
            }
        }

        private static T JsonBase64UrlSafeDeSerialize<T>(string base64UrlSafeJson)
        {
            // Convert json to object
            using (var memoryStream = new MemoryStream(FromBase64UrlSafeString(base64UrlSafeJson)))
            {
                var jsonSerializer = new DataContractJsonSerializer(typeof(T));
                return (T)jsonSerializer.ReadObject(memoryStream);
            }
        }

        private static byte[] FromBase64UrlSafeString(string base64UrlSafeString)
        {
            // Convert back to base64 from urlsafe base64
            var base64String = base64UrlSafeString.Replace('_', '/').Replace('-', '+');
            switch (base64UrlSafeString.Length % 4)
            {
                case 2: base64String += "=="; break;
                case 3: base64String += "="; break;
            }
            return Convert.FromBase64String(base64String);
        }

        private static string ToBase64UrlSafeString(byte[] bytes)
        {
            return System.Convert.ToBase64String(bytes)
                    .TrimEnd(base64_padding)
                    .Replace('+', '-')
                    .Replace('/', '_');
        }
    }

    public class JSONUtils
    {
        public static string JsonSerialize<T>(T obj)
        {
            using (var memoryStream = new MemoryStream())
            {
                var jsonSerializer = new DataContractJsonSerializer(typeof(T));
                jsonSerializer.WriteObject(memoryStream, obj);
                memoryStream.Position = 0;
                return Encoding.UTF8.GetString(memoryStream.ToArray());
            }
        }

        private static T JsonDeSerialize<T>(string jsonString)
        {
            // Convert json to object
            using (var memoryStream = new MemoryStream(Encoding.UTF8.GetBytes(jsonString)))
            {
                var jsonSerializer = new DataContractJsonSerializer(typeof(T));
                return (T)jsonSerializer.ReadObject(memoryStream);
            }
        }
    }

    public class CryptoUtils
    {
        private const string RsaPrivateKeyHeader = "-----BEGIN RSA PRIVATE KEY-----";
        private const string RsaPrivateKeyFooter = "-----END RSA PRIVATE KEY-----";

        public static RSACryptoServiceProvider CreateRsaProviderFromPrivatePemKey(string pemPrivateKey)
        {
            // Extract base64 formated key
            var base64KeyStart = pemPrivateKey.IndexOf(RsaPrivateKeyHeader, StringComparison.Ordinal);
            var base64KeyEnd = pemPrivateKey.LastIndexOf(RsaPrivateKeyFooter, StringComparison.Ordinal);
            if (base64KeyStart < 0 || base64KeyEnd < 200) // TODO: Find better number
            {
                throw new Exception("Not a valied pem formated private key");
            }
            var start = base64KeyStart + RsaPrivateKeyHeader.Length;
            var length = base64KeyEnd - start;
            var base64PemPrivateKey = Regex.Replace(pemPrivateKey.Substring(start, length), @"\r\n?|\n", "");

            // Convert to RSACryptoServiceProvider
            var privateKeyBits = System.Convert.FromBase64String(base64PemPrivateKey);
            var rsa = new RSACryptoServiceProvider();
            var rsaParameters = new RSAParameters();

            using (var binaryReader = new BinaryReader(new MemoryStream(privateKeyBits)))
            {
                byte bt = 0;
                ushort twobytes = 0;
                twobytes = binaryReader.ReadUInt16();
                if (twobytes == 0x8130)
                {
                    binaryReader.ReadByte();
                }
                else if (twobytes == 0x8230)
                {
                    binaryReader.ReadInt16();
                }
                else
                {
                    throw new Exception("Unexpected value read binr.ReadUInt16()");
                }

                twobytes = binaryReader.ReadUInt16();
                if (twobytes != 0x0102)
                {
                    throw new Exception("Unexpected version");
                }

                bt = binaryReader.ReadByte();
                if (bt != 0x00)
                {
                    throw new Exception("Unexpected value read binr.ReadByte()");
                }

                rsaParameters.Modulus = binaryReader.ReadBytes(GetIntegerSize(binaryReader));
                rsaParameters.Exponent = binaryReader.ReadBytes(GetIntegerSize(binaryReader));
                rsaParameters.D = binaryReader.ReadBytes(GetIntegerSize(binaryReader));
                rsaParameters.P = binaryReader.ReadBytes(GetIntegerSize(binaryReader));
                rsaParameters.Q = binaryReader.ReadBytes(GetIntegerSize(binaryReader));
                rsaParameters.DP = binaryReader.ReadBytes(GetIntegerSize(binaryReader));
                rsaParameters.DQ = binaryReader.ReadBytes(GetIntegerSize(binaryReader));
                rsaParameters.InverseQ = binaryReader.ReadBytes(GetIntegerSize(binaryReader));
            }

            rsa.ImportParameters(rsaParameters);
            return rsa;
        }

        private static int GetIntegerSize(BinaryReader binr)
        {
            byte bt = 0;
            int count = 0;
            bt = binr.ReadByte();
            if (bt != 0x02)
            {
                return 0;
            }
            bt = binr.ReadByte();

            if (bt == 0x81)
            {
                count = binr.ReadByte();
            }
            else if (bt == 0x82)
            {
                var highByte = binr.ReadByte();
                var lowByte = binr.ReadByte();
                byte[] modint = { lowByte, highByte, 0x00, 0x00 };
                count = BitConverter.ToInt32(modint, 0);
            }
            else
            {
                count = bt;
            }
            while (binr.ReadByte() == 0x00)
            {
                count -= 1;
            }
            binr.BaseStream.Seek(-1, SeekOrigin.Current);
            return count;
        }
    }
}