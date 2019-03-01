using System;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

namespace SCCrypto
{
    public class Settings
    {
        private string pkcs11LibraryPath;

        public Mechanism encryptionMechanism
        {
            internal set;
            get;
        }

        public IUserIO userIO
        {
            internal set;
            get;
        }

        public Settings(string pkcs11LibraryPath, IUserIO userIO)
        {
            this.pkcs11LibraryPath = pkcs11LibraryPath;
            encryptionMechanism = new Mechanism(CKM.CKM_RSA_PKCS);
            this.userIO = userIO;
        }

        public Settings(string pkcs11LibraryPath, Mechanism encryptionMechanism, IUserIO userIO)
        {
            this.pkcs11LibraryPath = pkcs11LibraryPath;
            this.encryptionMechanism = encryptionMechanism;
            this.userIO = userIO;
        }

        public Pkcs11 GetLibrary()
        {
            return new Pkcs11(pkcs11LibraryPath, AppType.SingleThreaded);
        }
    }
}
