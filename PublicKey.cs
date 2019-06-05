using Net.Pkcs11Interop.HighLevelAPI;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using SCCrypto.Configuration;

namespace SCCrypto
{
    public class PubKey : Key
    {
        public bool CkaEncrypt
        {
            get;
            internal set;
        }

        public bool CkaVerify
        {
            get;
            internal set;
        }

        public bool CkaVerifyRecover
        {
            get;
            internal set;
        }

        public bool CkaWrap
        {
            get;
            internal set;
        }
        public List<ulong> CkaAllowedMechanism
        {
            get;
            internal set;
        }

        internal PubKey(ObjectHandle objectHandle, List<ObjectAttribute> objectAttributes, ulong? storageSize)
        {
            ObjectHandle = objectHandle;
            ObjectAttributes = objectAttributes;
            StorageSize = storageSize;
        }

        public static List<PubKey> GetKeys(Session session)
        {
            List<PubKey> keys = new List<PubKey>();
            
            List<ObjectAttribute> searchTemplate = new List<ObjectAttribute>();
            searchTemplate.Add(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));

            List<ObjectHandle> foundObjects = session.FindAllObjects(searchTemplate);
            foreach (ObjectHandle foundObject in foundObjects)
            {
                // Read attributes required for sane object presentation
                List<ulong> attributes = new List<ulong>();
                attributes.Add((ulong)CKA.CKA_PRIVATE);
                attributes.Add((ulong)CKA.CKA_ID);
                attributes.Add((ulong)CKA.CKA_ENCRYPT);
                attributes.Add((ulong)CKA.CKA_VERIFY);
                attributes.Add((ulong)CKA.CKA_VERIFY_RECOVER);
                attributes.Add((ulong)CKA.CKA_KEY_TYPE);
                attributes.Add((ulong)CKA.CKA_WRAP);

                List<ObjectAttribute> requiredAttributes = session.GetAttributeValue(foundObject, attributes);

                // Read attributes configured for specific object class and type
                attributes = new List<ulong>();
                Config config = Config.GetDefault();
                foreach (ClassAttribute classAttribute in config.PublicKeyAttributes.CommonAttributes)
                    attributes.Add(classAttribute.Value);
                ulong keyType = requiredAttributes[5].GetValueAsUlong();
                if (config.PublicKeyAttributes.TypeSpecificAttributes.ContainsKey(keyType))
                    foreach (ClassAttribute classAttribute in config.PublicKeyAttributes.TypeSpecificAttributes[keyType])
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
                PubKey key = new PubKey(foundObject, configuredAttributes, storageSize)
                {
                    CkaPrivate = requiredAttributes[0].GetValueAsBool(),
                    CkaId = requiredAttributes[1].GetValueAsByteArray(),
                    CkaEncrypt = requiredAttributes[2].GetValueAsBool(),
                    CkaVerify = requiredAttributes[3].GetValueAsBool(),
                    CkaVerifyRecover = requiredAttributes[4].GetValueAsBool(),
                    CkaWrap = requiredAttributes[6].GetValueAsBool()
                
                };
                keys.Add(key);
            }
            

            return keys;
        }

        public static PubKey GetKey(Session session, byte[] CkaId)
        {

            List<ObjectAttribute> searchTemplate = new List<ObjectAttribute>();
            searchTemplate.Add(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
            searchTemplate.Add(new ObjectAttribute(CKA.CKA_ID,CkaId));

            List<ObjectHandle> foundObjects = session.FindAllObjects(searchTemplate);
            if (foundObjects.Count < 1) throw new System.Exception("No key found");
            if (foundObjects.Count > 1) throw new System.Exception("Key ID not unique");
            ObjectHandle foundObject = foundObjects[0];
            // Read attributes required for sane object presentation
            List<ulong> attributes = new List<ulong>();
            attributes.Add((ulong)CKA.CKA_PRIVATE);
            attributes.Add((ulong)CKA.CKA_ID);
            attributes.Add((ulong)CKA.CKA_ENCRYPT);
            attributes.Add((ulong)CKA.CKA_VERIFY);
            attributes.Add((ulong)CKA.CKA_VERIFY_RECOVER);
            attributes.Add((ulong)CKA.CKA_KEY_TYPE);
            attributes.Add((ulong)CKA.CKA_WRAP);

            List<ObjectAttribute> requiredAttributes = session.GetAttributeValue(foundObject, attributes);

            // Read attributes configured for specific object class and type
            attributes = new List<ulong>();
            Config config = Config.GetDefault();
            foreach (ClassAttribute classAttribute in config.PublicKeyAttributes.CommonAttributes)
                attributes.Add(classAttribute.Value);
            ulong keyType = requiredAttributes[5].GetValueAsUlong();
            if (config.PublicKeyAttributes.TypeSpecificAttributes.ContainsKey(keyType))
                foreach (ClassAttribute classAttribute in config.PublicKeyAttributes.TypeSpecificAttributes[keyType])
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
            PubKey key = new PubKey(foundObject, configuredAttributes, storageSize)
            {
                CkaPrivate = requiredAttributes[0].GetValueAsBool(),
                CkaId = requiredAttributes[1].GetValueAsByteArray(),
                CkaEncrypt = requiredAttributes[2].GetValueAsBool(),
                CkaVerify = requiredAttributes[3].GetValueAsBool(),
                CkaVerifyRecover = requiredAttributes[4].GetValueAsBool(),
                CkaWrap = requiredAttributes[6].GetValueAsBool()

            };
   
            


            return key;
        }

        public static List<PubKey> GetKeys(Slot slot)
        {
            using (Session session = slot.OpenSession(SessionType.ReadWrite))
            {
                return GetKeys(session);
               

            }
        }

        public ObjectAttribute GetAttribute(CKA Attribute)
        {
            ObjectAttribute res = null;
            for (int i = 0; i < ObjectAttributes.Count; i++)
            {
                if (ObjectAttributes[i].Type == (ulong)Attribute)
                {
                    res = ObjectAttributes[i];
                }
            }

            return res;
        }

    }
}
