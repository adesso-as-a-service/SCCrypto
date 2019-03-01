using System;
using System.Collections.Generic;
using System.Text;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.Common;
using SCCrypto.Configuration;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;

namespace SCCrypto
{
    public class Certificate
    {
        public ObjectHandle ObjectHandle
        {
            get;
            internal set;
        }

        public List<ObjectAttribute> ObjectAttributes
        {
            get;
            internal set;
        }

        public ulong? StorageSize
        {
            get;
            internal set;
        }
        public bool CkaPrivate
        {
            get;
            internal set;
        }

        public ulong CkaCertificateType
        {
            get;
            internal set;
        }

        public string CkaLabel
        {
            get;
            internal set;
        }

        public byte[] CkaId
        {
            get;
            internal set;
        }

        public byte[] CkaValue
        {
            get;
            internal set;
        }

        public byte[] CkaSubject
        {
            get;
            internal set;
        }

        public byte[] CkaSubPubKeyHash
        {
            get;
            internal set;
        }

        private void calcPubKeyHash()
        {
            X509Certificate x509 = this.Get509Certificate();
            RsaKeyParameters key = x509.GetPublicKey() as RsaKeyParameters;
            byte[] exp = key.Exponent.ToByteArrayUnsigned();
            byte[] mod = key.Modulus.ToByteArrayUnsigned();
            IDigest hash = new Sha256Digest();
            CkaSubPubKeyHash = new byte[hash.GetDigestSize()];

            hash.BlockUpdate(exp, 0, exp.Length);
            hash.BlockUpdate(mod, 0, mod.Length);
            hash.DoFinal(CkaSubPubKeyHash, 0);
        }

        internal Certificate(ObjectHandle objectHandle, List<ObjectAttribute> objectAttributes, ulong? storageSize)
        {
            ObjectHandle = objectHandle;
            ObjectAttributes = objectAttributes;
            StorageSize = storageSize;
        }

        public static List<Certificate> GetCerts(Slot slot)
        {
            List<Certificate> certs = new List<Certificate>();
            using (Session session = slot.OpenSession(SessionType.ReadOnly))
            {
                List<ObjectAttribute> searchTemplate = new List<ObjectAttribute>();
                searchTemplate.Add(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE));
                searchTemplate.Add(new ObjectAttribute(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509));

                List<ObjectHandle> foundObjects = session.FindAllObjects(searchTemplate);
                foreach (ObjectHandle foundObject in foundObjects)
                {
                    // Read attributes required for sane object presentation
                    List<ulong> attributes = new List<ulong>();
                    attributes.Add((ulong)CKA.CKA_PRIVATE);
                    attributes.Add((ulong)CKA.CKA_CERTIFICATE_TYPE);
                    attributes.Add((ulong)CKA.CKA_LABEL);
                    attributes.Add((ulong)CKA.CKA_ID);
                    attributes.Add((ulong)CKA.CKA_VALUE);
                    attributes.Add((ulong)CKA.CKA_SUBJECT);

                    List<ObjectAttribute> requiredAttributes = session.GetAttributeValue(foundObject, attributes);

                    // Read attributes configured for specific object class and type
                    Config config = Config.GetDefault();
                    attributes = new List<ulong>();
                    foreach (ClassAttribute classAttribute in config.CertificateAttributes.CommonAttributes)
                        attributes.Add(classAttribute.Value);
                    ulong certType = requiredAttributes[1].GetValueAsUlong();
                    if (config.CertificateAttributes.TypeSpecificAttributes.ContainsKey(certType))
                        foreach (ClassAttribute classAttribute in config.CertificateAttributes.TypeSpecificAttributes[certType])
                            attributes.Add(classAttribute.Value);

                    List<ObjectAttribute> configuredAttributes = session.GetAttributeValue(foundObject, attributes);

                    // Read object storage size
                    ulong? storageSize = null;
                    try
                    {
                        storageSize = session.GetObjectSize(foundObject);
                    }
                    catch
                    {

                    }


                    // Construct info object
                    Certificate cert = new Certificate(foundObject, configuredAttributes, storageSize)
                    {
                        CkaPrivate = requiredAttributes[0].GetValueAsBool(),
                        CkaCertificateType = requiredAttributes[1].GetValueAsUlong(),
                        CkaLabel = requiredAttributes[2].GetValueAsString(),
                        CkaId = requiredAttributes[3].GetValueAsByteArray(),
                        CkaValue = requiredAttributes[4].GetValueAsByteArray(),
                        CkaSubject = requiredAttributes[5].GetValueAsByteArray(),
                    };
                    cert.calcPubKeyHash();


                    certs.Add(cert);
                }
            }

            return certs;
        }

        public X509Certificate Get509Certificate()
        {
            return new X509CertificateParser().ReadCertificate(this.CkaValue);
        }

        // Checks if KeyType of Cert is of the given type
        public bool CheckKeyType(Slot slot, CKK keyType)
        {
            if (this.CkaId.Length == 0)
                return false;
            bool result;

            using (Session session = slot.OpenSession(SessionType.ReadOnly))
            {
                List<ObjectAttribute> searchTemplate = new List<ObjectAttribute>();
                searchTemplate.Add(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
                searchTemplate.Add(new ObjectAttribute(CKA.CKA_ID,this.CkaId));
                searchTemplate.Add(new ObjectAttribute(CKA.CKA_KEY_TYPE,keyType));

                List<ObjectHandle> foundObjects = session.FindAllObjects(searchTemplate);
                session.FindObjectsInit(searchTemplate);
                result = session.FindObjects(1).Count != 0;
                session.FindObjectsFinal();

                return result;

            }
        }
    }

}

