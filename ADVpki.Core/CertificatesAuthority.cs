/*
 * This file is part of ADVpki
 * Copyright (c) 2011 - ADVTOOLS SARL
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using MSX509 = System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Collections;
using System.Collections.Generic;
using Mono.Security.Authenticode;
using Mono.Security.X509;
using Mono.Security.X509.Extensions;
using System.Diagnostics;

namespace Advtools.ADVpki
{
    public class CertificatesAuthority
    {
        public enum Usage
        {
            /// <summary>
            /// Certificate for a root Certification Authority
            /// </summary>
            RootAuthority,
            /// <summary>
            /// SSL/TLS Server certificate
            /// </summary>
            Server,
            /// <summary>
            /// SSL/TLS Client certificate
            /// </summary>
            Client,
            /// <summary>
            /// Code certificate used to sign applications
            /// </summary>
            Code
        }

        private const int defaultCertificatesValidity_ = 2 * 365; // 2 years
        private const int defaultRootCertificateValidty_ = 10 * 365; // 10 years
        private const string defaultName_ = "ADVpki Certification Authority";

        /// <summary>
        /// Construct a CertificatesAuthority object with a default name and in the store of the current user
        /// </summary>
        public CertificatesAuthority()
        {
            name_ = defaultName_;
            store_ = MSX509.StoreLocation.CurrentUser;
        }
        
        /// <summary>
        /// Construct a CertificatesAuthority object
        /// </summary>
        /// <param name="name">Name of the certification authority</param>
        /// <param name="store">Where to store the certificates</param>
        public CertificatesAuthority(string name, MSX509.StoreLocation store)
        {
            name_ = name;
            store_ = store;
        }

        /// <summary>
        /// Get or create a certificate if it does not yet exist
        /// </summary>
        /// <param name="name">Name (subject) of the certificate</param>
        /// <param name="usage">Usage of the certificate</param>
        /// <param name="validity">Validity of the certificate or 0 to use the default validity</param>
        /// <param name="storageLocation">Where to store the certificate</param>
        /// <returns>An existing certificate or a new certificate</returns>
        public MSX509.X509Certificate2 GetCertificate(string name, Usage usage, int validity)
        {
            return InternalGetCertificate(name, usage, validity, MSX509.StoreName.My, GetRootCertificate());
        }

        private MSX509.X509Certificate2 GetRootCertificate()
        {
            return InternalGetCertificate(name_, Usage.RootAuthority, defaultRootCertificateValidty_, MSX509.StoreName.Root, null);
        }
        
        private MSX509.X509Certificate2 InternalGetCertificate(string name, Usage usage, int validity, MSX509.StoreName storeName, MSX509.X509Certificate2 issuer)
        {
            // Get the exrtension for this usage
            List<X509Extension> extensions = GetCertificateExtensions(usage);

            // Try to load the certificate from the machine store
            MSX509.X509Certificate2 certificate = LoadCertificate(name, storeName, MSX509.StoreLocation.LocalMachine);
            if(certificate != null)
                return certificate;

            // Try to load the certificate from the user store
            certificate = LoadCertificate(name, storeName, MSX509.StoreLocation.CurrentUser);
            if(certificate != null)
                return certificate;

            // Create a pair of keys
            PrivateKey key = new PrivateKey();
            key.RSA = RSA.Create();

            // Build a X509v3 certificate
            X509CertificateBuilder builder = new X509CertificateBuilder(3);
            builder.SerialNumber = GenerateSerial();
            builder.IssuerName = "CN=" + name_;
            builder.SubjectName = "CN=" + name;
            builder.SubjectPublicKey = key.RSA;
            builder.NotBefore = DateTime.Now;
            builder.NotAfter = builder.NotBefore.AddDays(validity == 0 ? defaultCertificatesValidity_ : validity);
            builder.Hash = "SHA1";

            // Add the extensions
            foreach(X509Extension extension in extensions)
                builder.Extensions.Add(extension);

            // Get the signator (issuer or itself in the case of a root certificate)
            var signator = issuer == null ? key.RSA : issuer.PrivateKey;
            // Sign the certificate
            byte[] raw = builder.Sign(signator);

            // Store the certificate
            StoreCertificate(name, raw, key.RSA, storeName);

            certificate = new MSX509.X509Certificate2(raw);
            certificate.PrivateKey = key.RSA;
            return certificate;
        }

        private List<X509Extension> GetCertificateExtensions(Usage usage)
        {
            List<X509Extension> extensions = new List<X509Extension>();

            switch(usage)
            {
                case Usage.Client: GetClientCertificateExtensions(extensions); break;
                case Usage.Server: GetServerCertificateExtensions(extensions); break;
                case Usage.Code: GetCodeCertificateExtensions(extensions); break;
                case Usage.RootAuthority: GetRootAuthorityCertificateExtensions(extensions); break;
                default: Debug.Assert(false, "Unknown usage value", "Unknown usage value: {0}", usage); break;
            }

            return extensions;
        }

        private void GetRootAuthorityCertificateExtensions(List<X509Extension> extensions)
        {
            BasicConstraintsExtension constraints = new BasicConstraintsExtension();
            constraints.CertificateAuthority = true;
            constraints.Critical = true;
            extensions.Add(constraints);

            KeyUsageExtension keyUsage = new KeyUsageExtension();
            keyUsage.KeyUsage = KeyUsages.keyCertSign | KeyUsages.cRLSign;
            extensions.Add(keyUsage);
        }

        private void GetClientCertificateExtensions(List<X509Extension> extensions)
        {
            BasicConstraintsExtension constraints = new BasicConstraintsExtension();
            constraints.CertificateAuthority = false;
            constraints.Critical = true;
            extensions.Add(constraints);

            KeyUsageExtension keyUsage = new KeyUsageExtension();
            keyUsage.KeyUsage = KeyUsages.digitalSignature | KeyUsages.nonRepudiation | KeyUsages.keyEncipherment;
            extensions.Add(keyUsage);

            ExtendedKeyUsageExtension extendedUsage = new ExtendedKeyUsageExtension();
            extendedUsage.KeyPurpose.Add("1.3.6.1.5.5.7.3.2"); // Client authentication
            extensions.Add(extendedUsage);
        }

        private void GetServerCertificateExtensions(List<X509Extension> extensions)
        {
            BasicConstraintsExtension constraints = new BasicConstraintsExtension();
            constraints.CertificateAuthority = false;
            constraints.Critical = true;
            extensions.Add(constraints);

            KeyUsageExtension keyUsage = new KeyUsageExtension();
            keyUsage.KeyUsage = KeyUsages.digitalSignature | KeyUsages.nonRepudiation | KeyUsages.keyEncipherment;
            extensions.Add(keyUsage);

            ExtendedKeyUsageExtension extendedUsage = new ExtendedKeyUsageExtension();
            extendedUsage.KeyPurpose.Add("1.3.6.1.5.5.7.3.1"); // Server authentication
            extendedUsage.KeyPurpose.Add("1.3.6.1.5.5.7.3.2"); // Client authentication
            extensions.Add(extendedUsage);
        }

        private void GetCodeCertificateExtensions(List<X509Extension> extensions)
        {
            BasicConstraintsExtension constraints = new BasicConstraintsExtension();
            constraints.CertificateAuthority = false;
            constraints.Critical = true;
            extensions.Add(constraints);

            KeyUsageExtension keyUsage = new KeyUsageExtension();
            keyUsage.KeyUsage = KeyUsages.digitalSignature | KeyUsages.nonRepudiation | KeyUsages.keyEncipherment;
            extensions.Add(keyUsage);

            ExtendedKeyUsageExtension extendedUsage = new ExtendedKeyUsageExtension();
            extendedUsage.KeyPurpose.Add("1.3.6.1.5.5.7.3.3"); // Code signing
            extensions.Add(extendedUsage);
        }
        
        private MSX509.X509Certificate2 LoadCertificate(string name, MSX509.StoreName storeName, MSX509.StoreLocation location)
        {
            if(certificates_.ContainsKey(name))
                return certificates_[name];

            MSX509.X509Store store = new MSX509.X509Store(storeName, location);
            store.Open(MSX509.OpenFlags.ReadOnly);
            var certificates = store.Certificates.Find(MSX509.X509FindType.FindBySubjectName, name, true);
            store.Close();

            if(certificates.Count <= 0)
                return null;

            MSX509.X509Certificate2 certificate = certificates[0];
            certificates_[name] = certificate;
            return certificate;
        }
        
        private byte[] GenerateSerial()
        {
            byte[] serial = Guid.NewGuid().ToByteArray();
            if((serial[0] & 0x80) == 0x80) // Have to be positive
                serial[0] -= 0x80;
            return serial;
        }

        private PKCS12 BuildPkcs12(byte[] raw, RSA key)
        {
            PKCS12 p12 = new PKCS12();
            p12.Password = "advtools";

            ArrayList list = new ArrayList();
            // we use a fixed array to avoid endianess issues (in case some tools requires the ID to be 1).
            list.Add(new byte[4] { 1, 0, 0, 0 });
            Hashtable attributes = new Hashtable(1);
            attributes.Add(PKCS9.localKeyId, list);

            p12.AddCertificate(new X509Certificate(raw), attributes);
            p12.AddPkcs8ShroudedKeyBag(key, attributes);

            return p12;
        }

        private void StoreCertificate(string name, byte[] raw, RSA key, MSX509.StoreName storeName)
        {
            PKCS12 p12 = BuildPkcs12(raw, key);

            MSX509.X509Certificate2 certificate = new MSX509.X509Certificate2(p12.GetBytes(), "advtools", MSX509.X509KeyStorageFlags.PersistKeySet | MSX509.X509KeyStorageFlags.MachineKeySet | MSX509.X509KeyStorageFlags.Exportable);

            MSX509.X509Store store = new MSX509.X509Store(storeName, store_);
            store.Open(MSX509.OpenFlags.ReadWrite);
            store.Add(certificate);
            store.Close();

            certificates_[name] = certificate;
        }
        
        private readonly string name_;
        private MSX509.StoreLocation store_;
        private Dictionary<string, MSX509.X509Certificate2> certificates_ = new Dictionary<string, MSX509.X509Certificate2>();
    }
}
