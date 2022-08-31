using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;

namespace PaddleVerify.Net
{
    public class PaddleVerifier
    {
        private string _publicPaddleKey { get; set; } = string.Empty;
    
        public PaddleVerifier(string publicPaddleKey)
        {
            this._publicPaddleKey = publicPaddleKey;
        }

        public bool VerifyPaddleRequest(Dictionary<string, string> inputParameters)
        {
            PhpSerializer serializer = new PhpSerializer();
            byte[] signature = Convert.FromBase64String(inputParameters["p_signature"] ?? "");
            var orderedDictionary = inputParameters
                .OrderBy(x => x.Key)
                .Where(x => x.Key != "p_signature")
                .ToDictionary(t => t.Key, t => (dynamic)t.Value);
            SortedDictionary<string, dynamic> sortedDict = new SortedDictionary<string, dynamic>(orderedDictionary);
            
            return verifySignature(signature, serializer.Serialize(sortedDict));
        }
        
        public bool VerifyPaddleRequest(HttpRequest httpRequest)
        {
            var allKeys = httpRequest.Form.Keys;
            Dictionary<string, string> preppedDict = new Dictionary<string, string>();
            StringValues stringValues;

            foreach (var key in allKeys)
            {
                httpRequest.Form.TryGetValue(key, out stringValues);
                preppedDict.Add(key, stringValues);
            }

            return this.VerifyPaddleRequest(preppedDict);
        }
        
        private bool verifySignature(byte[] signatureBytes, string message)
        {
            byte[] publicKeyX509DER = convertX509PemToDer(_publicPaddleKey);
            RSA rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(publicKeyX509DER, out _);
            
            return rsa.VerifyData(Encoding.ASCII.GetBytes(message), signatureBytes, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
        }
        
        private static byte[] convertX509PemToDer(string pemContents)
        {
            return Convert.FromBase64String(pemContents
                .TrimStart("-----BEGIN PUBLIC KEY-----".ToCharArray())
                .TrimEnd("-----END PUBLIC KEY-----".ToCharArray())
                .Replace("\r\n", ""));
        }
    }
}