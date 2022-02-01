using System;
using System.Linq;
using System.Security.Authentication;
using System.Text;
using Leaf.xNet;

namespace Examples
{
    internal class Program
    {
        private static readonly byte[] GoogleCertificateHash =
            {44, 60, 36, 98, 59, 198, 43, 64, 55, 107, 112, 17, 28, 134, 231, 182, 106, 227, 103, 140};

        private static string ArrayToString(byte[] arr)
        {
            if (arr.Length == 0)
                return "{}";
            
            var sb = new StringBuilder("{");
            foreach (byte b in arr)
            {
                sb.Append(b.ToString());
                sb.Append(", ");
            }
            // remove ", "
            sb.Remove(sb.Length - 2, 2);
            sb.Append('}');
            
            return sb.ToString();
        }
        
        public static void Main(string[] args)
        {
            var req = new HttpRequest();

            var sslProvider = req.SslProvider();
            sslProvider.SslCertificateValidatorCallback += (sender, certificate, chain, errors) => {
                // Save required hash to const byte array and compare with it
                byte[] certHash = certificate.GetCertHash();

                Console.WriteLine("Received Cert Hash: ");
                Console.WriteLine(ArrayToString(certHash));

                Console.WriteLine("Expected Cert Hash: ");
                Console.WriteLine(ArrayToString(GoogleCertificateHash));
                
                return certHash.SequenceEqual(GoogleCertificateHash);
            };
            
            // When you have proxy software with HTTPS decryption
            // Certificate value hash will be changed (byte[] certHash value)

            // Set Charles (SOCKS proxy) or Fiddler (SOCKS5)
            // SOCKS must be enabled in settings of your Charles / Fiddler (any sniffer app)
            // req.Proxy = Socks5ProxyClient.Parse("127.0.0.1:8889");

            try
            {
                var resp = req.Get("https://www.facebook.com");
                string respStr = resp.ToString();
                Console.WriteLine("OK Response:");
                Console.WriteLine(respStr);
            }
            catch (AuthenticationException authenticationException)
            {

                Console.WriteLine("SSL Pinning certificate mismatch: " + authenticationException.Message);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Unknown error: " + ex.Message);
            }
        }
    }
}