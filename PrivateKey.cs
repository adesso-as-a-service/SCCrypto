using Net.Pkcs11Interop.HighLevelAPI;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using SCCrypto.Configuration;

namespace SCCrypto
{
    class PrivateKey : Key
    {
        public bool CkaDecrypt
        {
            get;
            internal set;
        }

        public bool CkaSign
        {
            get;
            internal set;
        }

        public bool CkaSignRecover
        {
            get;
            internal set;
        }

        public bool CkaUnwrap
        {
            get;
            internal set;
        }

        public byte[] CkaAllowedMechanisms
        {
            get;
            internal set;
        }

        internal PrivateKey(ObjectHandle objectHandle, List<ObjectAttribute> objectAttributes, ulong? storageSize)
        {
            ObjectHandle = objectHandle;
            ObjectAttributes = objectAttributes;
            StorageSize = storageSize;
        }

        public static List<PrivateKey> GetKeys(Session session)
        {
            List<PrivateKey> keys = new List<PrivateKey>();
            
            List<ObjectAttribute> searchTemplate = new List<ObjectAttribute>();
            searchTemplate.Add(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));

            List<ObjectHandle> foundObjects = session.FindAllObjects(searchTemplate);
            foreach (ObjectHandle foundObject in foundObjects)
            {
                // Read attributes required for sane object presentation
                List<ulong> attributes = new List<ulong>();
                attributes.Add((ulong)CKA.CKA_PRIVATE);
                attributes.Add((ulong)CKA.CKA_ID);
                attributes.Add((ulong)CKA.CKA_DECRYPT);
                attributes.Add((ulong)CKA.CKA_SIGN);
                attributes.Add((ulong)CKA.CKA_SIGN_RECOVER);
                attributes.Add((ulong)CKA.CKA_KEY_TYPE);
                attributes.Add((ulong)CKA.CKA_UNWRAP);

                List<ObjectAttribute> requiredAttributes = session.GetAttributeValue(foundObject, attributes);

                // Read attributes configured for specific object class and type
                attributes = new List<ulong>();
                Config config = Config.GetDefault();
                foreach (ClassAttribute classAttribute in config.PrivateKeyAttributes.CommonAttributes)
                    attributes.Add(classAttribute.Value);
                ulong keyType = requiredAttributes[5].GetValueAsUlong();
                if (config.PrivateKeyAttributes.TypeSpecificAttributes.ContainsKey(keyType))
                    foreach (ClassAttribute classAttribute in config.PrivateKeyAttributes.TypeSpecificAttributes[keyType])
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
                PrivateKey key = new PrivateKey(foundObject, configuredAttributes, storageSize)
                {
                    CkaPrivate = requiredAttributes[0].GetValueAsBool(),
                    CkaId = requiredAttributes[1].GetValueAsByteArray(),
                    CkaDecrypt = requiredAttributes[2].GetValueAsBool(),
                    CkaSign = requiredAttributes[3].GetValueAsBool(),
                    CkaSignRecover = requiredAttributes[4].GetValueAsBool(),
                    CkaUnwrap = requiredAttributes[6].GetValueAsBool()

                };

                keys.Add(key);
            }
            

            return keys;
        }
    }
}
