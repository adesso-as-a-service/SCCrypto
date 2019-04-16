using System;
using System.Collections.Generic;
using System.Text;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using SCCrypto.Configuration;

namespace SCCrypto
{
    public class SmartCard
    {

        public Settings settings
        {
            get;
            internal set;
        }


        public SmartCard(Settings settings)
        {
            this.settings = settings;
        }

        // get available Keys and their slots
        public Tuple<List<Certificate>,List<Slot>> getAvailableCertsAndSlots()
        {
            Pkcs11 pkcs11 = settings.GetLibrary();
            
            List<Slot> slots = pkcs11.GetSlotList(SlotsType.WithTokenPresent);

            List<Certificate> certs = new List<Certificate>();
            List<Slot> retSlots = new List<Slot>();

            List<Certificate> tempCerts;

            foreach (Slot slot in slots)
            {
                tempCerts = Certificate.GetCerts(slot);
                foreach (Certificate cert in tempCerts)
                {
                    // Take just Keymanagement Cert
                    if (cert.CkaId.Length == 1 && cert.CkaId[0] == 0x03)
                    {
                        // only accept RSA for now
                        if (cert.CheckKeyType(slot, CKK.CKK_RSA))
                        {
                            certs.Add(cert);
                            retSlots.Add(slot);
                        }
                    }
                }
            }
            return new Tuple<List<Certificate>, List<Slot>>(certs, retSlots);
            
        }

        // get privateKeyHandle via KeyID
        public static ObjectHandle getKeyID(Session session,byte[] keyID)
        {
            List<ObjectAttribute> searchTemplate = new List<ObjectAttribute>();
            searchTemplate.Add(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
            searchTemplate.Add(new ObjectAttribute(CKA.CKA_ID, keyID));
            session.FindObjectsInit(searchTemplate);
            List<ObjectHandle> foundObjects = session.FindObjects(1);
            if (foundObjects.Count == 0) return null;
            session.FindObjectsFinal();
            return foundObjects[0];

        }

    }
}
