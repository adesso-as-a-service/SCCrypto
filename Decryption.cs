using System;
using System.Collections.Generic;
using System.Text;
using System.Security;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

namespace SCCrypto
{
    public class Decryption
    {
        public const int NO_KEY_FOUND = -1;
        public const int DECRYPTION_FAILED = -2;
        // LinkedList filled with the Data to Encrypt
        // Tuple is (subjectName,pubKeyHash,Cipher)

        // A dictionary containing data to dercypt ordered by public key hash
        private Dictionary<byte[], LinkedList<Tuple<string, byte[]>>> fastDataToDecrypt;
        private int remaining;

        private SmartCard smartCard;

        public Decryption(SmartCard smartCard, List<Tuple<string, byte[], byte[]>> dataToDecrypt)
        {
            Tuple<string, byte[], byte[]> data;
            this.smartCard = smartCard;
            remaining = dataToDecrypt.Count;
            fastDataToDecrypt = new Dictionary<byte[], LinkedList<Tuple<string, byte[]>>>(new ArrayEqualityCompare());
            for (int i = 0; i < dataToDecrypt.Count; i++)
            {
                data = dataToDecrypt[i];
                if (!fastDataToDecrypt.ContainsKey(data.Item2))
                {
                    fastDataToDecrypt.Add(data.Item2, new LinkedList<Tuple<string, byte[]>>());
                }
                fastDataToDecrypt[data.Item2].AddLast(new Tuple<string, byte[]>(data.Item1, data.Item3));
            }
        }

        // return remaining, cipher and decrypted data
        public Tuple<int,byte[],byte[]> Do()
        {
            byte[] plainText, Cipher;
            int selection;
            
            Tuple<List<Certificate>,List<Slot>> certsAndSlots;
            List<Certificate> certs;
            List<Slot> slots;
            Certificate cert;
            Slot slot;
            do
            {


                // get Available Keys
                certsAndSlots = smartCard.getAvailableCertsAndSlots();
                certs = certsAndSlots.Item1;
                slots = certsAndSlots.Item2;

                // Remove notused keys
                for (int i = certs.Count - 1; i >= 0; i--)
                {
                    cert = certs[i];
                    if (!fastDataToDecrypt.ContainsKey(cert.CkaSubPubKeyHash))
                    {
                        certs.RemoveAt(i);
                        slots.RemoveAt(i);
                    }
                }
                // Offer Keys
                // if empty print users
                if (certs.Count == 0)
                {
                    // list needed Keys and wait for response
                    smartCard.settings.userIO.outputListAbort(getNeededKeys());
                }

                // Select Key
                selection = OfferKeys(certs, slots);
            } while (selection == -1);
            cert = certs[selection];
            slot = slots[selection];


            Cipher = fastDataToDecrypt[cert.CkaSubPubKeyHash].Last.Value.Item2;
            // DoDecryption
            plainText = DoDecrypt(Cipher,cert.CkaId,slot);

            //if fail return error
            if (plainText == null) return new Tuple<int, byte[], byte[]>(DECRYPTION_FAILED, null, null);
            // Remvoe deciphered text
            //if success
            remaining--;
            var list = fastDataToDecrypt[cert.CkaSubPubKeyHash];
            list.RemoveLast();
            if (list.Count == 0) fastDataToDecrypt.Remove(cert.CkaSubPubKeyHash);

            // return Encryption, PublicKey and remaining Datasets
            return new Tuple<int, byte[], byte[]>(remaining, Cipher, plainText);
        }

        private int OfferKeys(List<Certificate> certs, List<Slot> slots)
        {
            TokenInfo info;
            List<string> choices = new List<string>();
            for (int i = 0; i < certs.Count; i++)
            {
                // TODO String aufarbeiten
                string certStr = certs[i].Get509Certificate().SubjectDN.ToString();
                string certLabel = certs[i].CkaLabel;
                info = slots[i].GetTokenInfo();
                string tokenInfo = info.Label + " / " + info.ManufacturerId + " / " + info.Model + " / " + info.SerialNumber + " / " + info.UtcTimeString;

                choices.Add(certStr + " / " + certLabel + " / " + tokenInfo);
            }

            return smartCard.settings.userIO.selectFromList(choices);

        }

        private byte[] DoDecrypt( byte[] cipher, byte[] keyID, Slot slot)
        {
            byte[] result;
            Session session = slot.OpenSession(SessionType.ReadWrite);
            ObjectHandle keyhandle;
            byte[] PW;
            bool loop = true;
            while (loop)
            {
                // read PIN, allow for break
                PW = smartCard.settings.userIO.ReadPW("Please enter the PIN for the slected token!");
                if (PW == null)
                {
                    // print error
                    smartCard.settings.userIO.outputText("Failed reading the PIN!");
                    return null;
                }
                try
                {
                    session.Login(CKU.CKU_USER, PW);
                    for (int i = 0; i < PW.Length; i++) PW[i] = 0;
                    loop = false;
                } catch (Pkcs11Exception e)
                {
                    switch (e.RV)
                    {
                        case CKR.CKR_PIN_INCORRECT:
                            smartCard.settings.userIO.outputText("Incorret PIN! Try again!");
                            break;
                        default:
                            smartCard.settings.userIO.outputText(String.Format("Nonrecoverable Error: 0x{0:X} !",e.RV));
                            session.CloseSession();
                            return null;
                    }

                }

            }
            // get keyhandle
            keyhandle = SmartCard.getKeyID(session, keyID);
            if (keyhandle == null)
            {
                smartCard.settings.userIO.outputText("Slected Key could not be found on the token!");
                return null;
            }
            result = session.Decrypt(new Mechanism(CKM.CKM_RSA_PKCS), keyhandle, cipher);
            session.Logout();
            session.CloseSession();
            return result;
        }

        private List<string> getNeededKeys()
        {
            List<string> ret = new List<string>();
            foreach (KeyValuePair<byte[], LinkedList<Tuple<string, byte[]>>> kp in fastDataToDecrypt)
            {
                // read first owner and publickeyhash
                ret.Add(String.Format("{0} / {1}",kp.Value.First.Value.Item1, Convert.ToBase64String(kp.Key)));
            }
            return ret;
        }


    }
}
