﻿using System;
using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Net.Pkcs11Interop.HighLevelAPI;

namespace SCCrypto
{
    public class Encryption
    {
        // list of keys already used to encrypt
        private HashSet<RsaKeyParameters> usedKeys;

        // list of already used key owners
        private HashSet<string> usedOwners;

        // if true, encryption can use the same owner more than once
        private bool allowDoubleOwners;

        // if true, encryption can use the same key more than once
        private bool allowDoubleKeys;

        // LinkedList filled with the Data to Encrypt
        private LinkedList<byte[]> dataToEncrypt;

        private SmartCard smartCard;

        public Encryption(SmartCard smartCard, LinkedList<byte[]> dataToEncrypt, bool allowDoubleOwners, bool allowDoubleKeys)
        {
            usedKeys = new HashSet<RsaKeyParameters>();
            usedOwners = new HashSet<string>();
            this.allowDoubleOwners = allowDoubleOwners;
            this.allowDoubleKeys = allowDoubleKeys;
            this.smartCard = smartCard;
            this.dataToEncrypt = dataToEncrypt;
        }


        public Tuple<int, byte[], byte[], byte[], string> Do()
        {
            string owner;
            int selection;
            List<Certificate> certs;
            List<Slot> slots;
            Certificate cert;
            RsaKeyParameters key;
            X509Certificate x509;
            List<string> noCerts = new List<string>();
            noCerts.Add("Please insert a Key!");
            Tuple<byte[], byte[]> encRet;
            do
            {
                // get Available Keys
                //System.Diagnostics.Stopwatch stopwatch = new System.Diagnostics.Stopwatch();
                //stopwatch.Start();
                Tuple<List<Certificate>, List<Slot>> certSlot = smartCard.getAvailableCertsAndSlots();
                //stopwatch.Stop();
               // System.Windows.Forms.MessageBox.Show(String.Format("{0}ms", stopwatch.ElapsedMilliseconds));
                certs = certSlot.Item1;
                slots = certSlot.Item2;
                // Remove used keys
                for (int i = certs.Count - 1; i >= 0; i--)
                {
                    cert = certs[i];
                    x509 = cert.Get509Certificate();
                    key = x509.GetPublicKey() as RsaKeyParameters;
                    owner = x509.SubjectDN.ToString();
                    if ((!allowDoubleKeys && usedKeys.Contains(key)) || (!allowDoubleOwners && usedOwners.Contains(owner))) certs.RemoveAt(i);
                }
                // Offer Keys
                // handle Exceptions

                selection = OfferKeys(certs, slots);

                
            } while (selection == -1);
            cert = certs[selection];
            x509 = cert.Get509Certificate();

            // DoEncryption
            encRet = DoEncrypt(x509);

            // Store used Owners and Keys
            usedOwners.Add(x509.SubjectDN.ToString());
            usedKeys.Add(x509.GetPublicKey() as RsaKeyParameters);

            // return Encryption, PublicKey and remaining Datasets
            return new Tuple<int, byte[], byte[], byte[], string>(dataToEncrypt.Count, encRet.Item1, encRet.Item2, cert.CkaSubPubKeyHash, x509.SubjectDN.ToString());
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
                string tokenInfo = info.Label +" / "+ info.ManufacturerId + " / " + info.Model + " / " + info.SerialNumber + " / " + info.UtcTimeString;
                   
                choices.Add(certStr + " / " + certLabel + " / " + tokenInfo);
            }

            return smartCard.settings.userIO.selectFromList(choices);

        }

        private Tuple<byte[],byte[]> DoEncrypt( X509Certificate cert)
        {
            byte[] result;
            byte[] input = dataToEncrypt.Last.Value;
            var encryptEngine = new Pkcs1Encoding(new RsaEngine());
            encryptEngine.Init(true, cert.GetPublicKey());

            result = encryptEngine.ProcessBlock(input, 0, input.Length);

            dataToEncrypt.RemoveLast();

            return new Tuple<byte[],byte[]> (input, result);
        }


    }
}
