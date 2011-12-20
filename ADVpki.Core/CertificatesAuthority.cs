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
using System.IO;
using System.Collections.Generic;
using System.Diagnostics;
using MSX509 = System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;

namespace Advtools.ADVpki
{
    public class CertificatesAuthority
    {
        #region Public enumerations
        public enum Usage
        {
            /// <summary>
            /// Certificate for a root Certification Authority (CA)
            /// </summary>
            Authority,
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
        #endregion

        #region Parameters
        private const int defaultCertificatesValidity_ = 2 * 365; // 2 years
        private const int defaultRootCertificateValidty_ = 10 * 365; // 10 years
        #endregion

        #region Constructors
        /// <summary>
        /// Construct a CertificatesAuthority object with a default name and in the store of the current user
        /// </summary>
        /// <param name="name">Name of the certification authority.</param>
        public CertificatesAuthority(string name)
        {
            authorityName_ = name != null ? X509NameFromString(name) : null;
            store_ = MSX509.StoreLocation.CurrentUser;
        }
        
        /// <summary>
        /// Construct a CertificatesAuthority object
        /// </summary>
        /// <param name="name">Name of the certification authority.</param>
        /// <param name="store">Where to store the certificates</param>
        public CertificatesAuthority(string name, MSX509.StoreLocation store)
        {
            authorityName_ = name != null ? X509NameFromString(name) : null;
            store_ = store;
        }

        #endregion

        #region Public methods
        /// <summary>
        /// Generate a new certificate.
        /// </summary>
        /// <param name="name">Name (subject) of the certificate</param>
        /// <param name="usage">Usage of the certificate</param>
        /// <param name="validity">Validity of the certificate or 0 to use the default validity</param>
        /// <param name="storageLocation">Where to store the certificate</param>
        /// <returns>An existing certificate or a new certificate</returns>
        public MSX509.X509Certificate2 GenerateCertificate(string name, Usage usage, int validity)
        {
            MSX509.X509Certificate2 root = GetRootCertificate();
            if(null == root && usage != Usage.Authority)
                throw new ApplicationException("Root certificate not found");

            return InternalGenerateCertificate(X509NameFromString(name), usage, validity, MSX509.StoreName.My, root);
        }

        public MSX509.X509Certificate2 SignRequest(string csrFile, Usage usage, int validity)
        {
            return SignRequest(csrFile, usage, validity, MSX509.StoreName.My);
        }

        public MSX509.X509Certificate2 SignRequest(string csrFile, Usage usage, int validity, MSX509.StoreName storeName)
        {
            Pkcs10CertificationRequest request = ReadPkcs10(csrFile);
            var info = request.GetCertificationRequestInfo();
            SubjectPublicKeyInfo publicKeyInfo = info.SubjectPublicKeyInfo; 

            RsaPublicKeyStructure publicKeyStructure = RsaPublicKeyStructure.GetInstance(publicKeyInfo.GetPublicKey());
            RsaKeyParameters publicKey = new RsaKeyParameters(false, publicKeyStructure.Modulus, publicKeyStructure.PublicExponent);

            if(!request.Verify(publicKey))
                throw new ApplicationException("The CSR is not valid: verification failed");

            MSX509.X509Certificate2 root = GetRootCertificate();
            if(root == null)
                throw new ApplicationException("Root certificate not found");

            return InternalGenerateCertificate(info.Subject, usage, validity, storeName, publicKey, null, DotNetUtilities.GetKeyPair(root.PrivateKey).Private);
        }

        #endregion

        #region Internal methods

        private static X509Name X509NameFromString(string name)
        {
            if(name.Contains("="))
                return new X509Name(name);
            return new X509Name("CN=" + name);
        }

        private Pkcs10CertificationRequest ReadPkcs10(string file)
        {
            using(TextReader reader = new StreamReader(file))
            {
                PemReader pem = new PemReader(reader);
                return (Pkcs10CertificationRequest)pem.ReadObject();
            }
        }

        private MSX509.X509Certificate2 GetRootCertificate()
        {
            return authorityName_ == null ? null : GetCertificate(authorityName_, Usage.Authority, defaultRootCertificateValidty_, MSX509.StoreName.Root, null);
        }

        private MSX509.X509Certificate2 GetCertificate(X509Name name, Usage usage, int validity, MSX509.StoreName storeName, MSX509.X509Certificate2 issuer)
        {
            // Try to load the certificate from the machine store
            MSX509.X509Certificate2 certificate = LoadCertificate(name, storeName, MSX509.StoreLocation.LocalMachine);
            if(certificate != null)
                return certificate;

            // Try to load the certificate from the user store
            certificate = LoadCertificate(name, storeName, MSX509.StoreLocation.CurrentUser);
            if(certificate != null)
                return certificate;

            return InternalGenerateCertificate(name, usage, validity, storeName, issuer);
        }
            
        private MSX509.X509Certificate2 InternalGenerateCertificate(X509Name name, Usage usage, int validity, MSX509.StoreName storeName, MSX509.X509Certificate2 issuer)
        {
            // Create a pair of keys
            RsaKeyPairGenerator keyGenerator = new RsaKeyPairGenerator();
            keyGenerator.Init(new KeyGenerationParameters(new SecureRandom(new CryptoApiRandomGenerator()), 1024));
            var keys = keyGenerator.GenerateKeyPair();

            // Get the signator (issuer or itself in the case of a root certificate which is self-signed)
            AsymmetricKeyParameter signator = issuer == null ? keys.Private : DotNetUtilities.GetKeyPair(issuer.PrivateKey).Private;

            return InternalGenerateCertificate(name, usage, validity, storeName, keys.Public, keys.Private, signator);
        }

        private MSX509.X509Certificate2 InternalGenerateCertificate(X509Name name, Usage usage, int validity, MSX509.StoreName storeName, AsymmetricKeyParameter publicKey, AsymmetricKeyParameter privateKey, AsymmetricKeyParameter signator)
        {
            DateTime notBefore = DateTime.Now.AddDays(-1);

            // Build a X509v3 certificate
            X509V3CertificateGenerator builder = new X509V3CertificateGenerator();
            builder.SetSerialNumber(new BigInteger(GenerateSerial()));
            builder.SetIssuerDN(authorityName_ ?? name);
            builder.SetSubjectDN(name);
            builder.SetPublicKey(publicKey);
            builder.SetNotBefore(notBefore);
            builder.SetNotAfter(notBefore.AddDays(validity == 0 ? defaultCertificatesValidity_ : validity));
            builder.SetSignatureAlgorithm("SHA1WithRSA");

            // Add the extensions
            AddExtensions(builder, usage);

            // Sign the certificate
            X509Certificate newCertificate = builder.Generate(signator);

            // Create a .NET X509Certificate2 from the BouncyCastle one and put the private key into it
            MSX509.X509Certificate2 certificate = CreateCertificate(name, newCertificate, privateKey);

            // Store the certificate
            StoreCertificate(name, certificate, storeName);

            return certificate;
        }

        private string GetFriendlyName(X509Name name)
        {
            return (string)name.GetValues(X509Name.CN)[0];
        }

        private MSX509.X509Certificate2 CreateCertificate(X509Name name, X509Certificate certificate, AsymmetricKeyParameter privateKey)
        {
            var pkcs12Store = new Pkcs12StoreBuilder().Build();
            pkcs12Store.SetKeyEntry(GetFriendlyName(name), new AsymmetricKeyEntry(privateKey), new[] { new X509CertificateEntry(certificate) });
            var data = new MemoryStream();
            pkcs12Store.Save(data, pkcs12Password_.ToCharArray(), new SecureRandom(new CryptoApiRandomGenerator()));

            MSX509.X509KeyStorageFlags storage = MSX509.X509KeyStorageFlags.Exportable | MSX509.X509KeyStorageFlags.PersistKeySet |
                ((store_ == MSX509.StoreLocation.LocalMachine) ? MSX509.X509KeyStorageFlags.MachineKeySet : MSX509.X509KeyStorageFlags.UserKeySet);

            return new MSX509.X509Certificate2(data.ToArray(), pkcs12Password_, storage);
        }
        
        private void AddExtensions(X509V3CertificateGenerator builder, Usage usage)
        {
            switch(usage)
            {
                case Usage.Client: AddClientCertificateExtensions(builder); break;
                case Usage.Server: AddServerCertificateExtensions(builder); break;
                case Usage.Code: AddCodeCertificateExtensions(builder); break;
                case Usage.Authority: AddRootAuthorityCertificateExtensions(builder); break;
                default: Debug.Assert(false, "Unknown usage value", "Unknown usage value: {0}", usage); break;
            }
        }

        private void AddRootAuthorityCertificateExtensions(X509V3CertificateGenerator builder)
        {
            builder.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));
            builder.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign));
        }

        private void AddClientCertificateExtensions(X509V3CertificateGenerator builder)
        {
            builder.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
            builder.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.NonRepudiation | KeyUsage.KeyEncipherment));
            builder.AddExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeID.IdKPClientAuth));
        }

        private void AddServerCertificateExtensions(X509V3CertificateGenerator builder)
        {
            builder.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
            builder.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.NonRepudiation | KeyUsage.KeyEncipherment));
            builder.AddExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeID.IdKPClientAuth, KeyPurposeID.IdKPServerAuth));
        }

        private void AddCodeCertificateExtensions(X509V3CertificateGenerator builder)
        {
            builder.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
            builder.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.NonRepudiation | KeyUsage.KeyEncipherment));
            builder.AddExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeID.IdKPCodeSigning));
        }

        private MSX509.X509Certificate2 LoadCertificate(X509Name name, MSX509.StoreName storeName, MSX509.StoreLocation location)
        {
            if(certificates_.ContainsKey(name))
                return certificates_[name];

            string dn = name.ToString();

            MSX509.X509Store store = new MSX509.X509Store(storeName, location);
            store.Open(MSX509.OpenFlags.ReadOnly);
            var certificates = store.Certificates.Find(MSX509.X509FindType.FindBySubjectDistinguishedName, dn, true);
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

        private void StoreCertificate(X509Name name, MSX509.X509Certificate2 certificate, MSX509.StoreName storeName)
        {
            MSX509.X509Store store = new MSX509.X509Store(storeName, store_);
            store.Open(MSX509.OpenFlags.ReadWrite);
            store.Add(certificate);
            store.Close();

            certificates_[name] = certificate;
        }

        #endregion

        #region Instance fields
        private const string pkcs12Password_ = "advtools";
        private readonly X509Name authorityName_;
        private MSX509.StoreLocation store_;
        private Dictionary<X509Name, MSX509.X509Certificate2> certificates_ = new Dictionary<X509Name, MSX509.X509Certificate2>();
        #endregion
    }
}
