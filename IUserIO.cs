using System;
using System.Collections.Generic;
using System.Text;

namespace SCCrypto
{
    public interface IUserIO
    {
        int selectFromList(List<string> list);

        void outputText(string text);

        byte[] ReadPW(string Prompt);

        void outputListAbort(List<string> list);

    }
}
