using System;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace Leaf.xNet
{
    public class SystemSslProvider : ISslProvider
    {
        public bool Disposable => true;

        /// <summary>
        /// SSL Pinning / Anti-sniffer callback.
        /// Returns or sets the delegate method, called for SSL certificate validation, used for authentication.
        /// </summary>
        /// <value>By default: <see langword="null"/>. If the default value is set, the method that accepts all certificates.</value>
        public RemoteCertificateValidationCallback SslCertificateValidatorCallback { get; set; }
        
        /// <summary>
        /// Override host for SSL, when host IP has been customized.
        /// </summary>
        public string Host { get; set; }
        
        /// <summary>
        /// Returns or sets possible SSL protocols. See: <see cref="SslProtocols" />.
        /// By default: <value>SslProtocols.Tls | SslProtocols.Tls12 | SslProtocols.Tls11</value>.
        /// </summary>
        public SslProtocols SslProtocols { get; set; } = SslProtocols.Tls | SslProtocols.Tls12 | SslProtocols.Tls11;

        /// <summary>
        /// Client TLS Certificates.
        /// </summary>
        /// <example>
        /// ClientCertificates = new X509CertificateCollection {
        ///     new X509Certificate2(@"C:\YouCert.cert")
        /// };
        /// </example>
        public X509CertificateCollection ClientCertificates { get; set; }

        public Stream Initialize(Uri address, NetworkStream networkStream)
        {
            var sslStream = new SslStream(networkStream, false, 
                SslCertificateValidatorCallback ?? Http.AcceptAllCertificationsCallback, 
                null);

            // clientCerts был new X509CertificateCollection(), заменил на null
            string host = !string.IsNullOrEmpty(Host) ? Host : address.Host; 

            // Allow to provide hosts with . (dot) at the end
            host = host.TrimEnd('.');

            sslStream.AuthenticateAsClient(host, ClientCertificates, SslProtocols, false);
            return sslStream;
        }
    }
}