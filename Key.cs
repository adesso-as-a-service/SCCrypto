/*
 *  Pkcs11Admin - GUI tool for administration of PKCS#11 enabled devices
 *  Copyright (c) 2014-2017 Jaroslav Imrich <jimrich@jimrich.sk>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 3 
 *  as published by the Free Software Foundation.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

using Net.Pkcs11Interop.HighLevelAPI;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using SCCrypto.Configuration;

namespace SCCrypto
{
    public abstract class Key
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

        public byte[] CkaId
        {
            get;
            internal set;
        }

        public ulong CkaKeyType
        {
            get;
            internal set;
        }


        public ObjectAttribute GetAttribute(CKA Attribute)
        {
            ObjectAttribute res = null;
            for (int i = 0; i < ObjectAttributes.Count; i++)
            {
                if (ObjectAttributes[i].Type == (ulong) Attribute)
                {
                    res = ObjectAttributes[i];
                }
            }

            return res;
        }



    }
}
