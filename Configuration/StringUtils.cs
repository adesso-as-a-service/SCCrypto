﻿/*
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

using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using System;
using System.Collections.Generic;

namespace SCCrypto.Configuration
{
    public static class StringUtils // TODO - Rename to more appropriate name
    {

        private static Config config = Config.GetDefault();

        public static string BytesToHexString(byte[] bytes)
        {
            return (bytes == null) ? null : BitConverter.ToString(bytes).Replace('-', ' ');
        }

        public static byte[] HexStringToBytes(string hexString)
        {
            return (string.IsNullOrEmpty(hexString)) ? null : ConvertUtils.HexStringToBytes(hexString.Replace(" ", ""));
        }

        /// <summary>
        /// Compares two specified cryptoki versions and returns an integer that indicates their relative position in the sort order.
        /// </summary>
        /// <param name="version1">The first version to compare</param>
        /// <param name="version2">The second version to compare</param>
        /// <returns>Less than zero - versionA is less than versionB. Zero - versionA equals versionB. Greater than zero - versionA is greater than versionB.</returns>
        public static int CompareCkVersions(string versionA, string versionB)
        {
            return string.Compare(versionA, versionB);
        }

        public static void GetAttributeNameAndValue(ObjectAttribute objectAttribute, out string name, out string value)
        {
            if (objectAttribute == null)
                throw new ArgumentNullException("objectAttribute");

            string tmpName = null;
            string tmpValue = null;

            // Find attribute definition in configuration
            AttributeDefinition pkcs11Attribute = null;
            if (config.AttributeDefinitions.ContainsKey(objectAttribute.Type))
                pkcs11Attribute = config.AttributeDefinitions[objectAttribute.Type];

            // Determine attribute name
            if (pkcs11Attribute == null)
                tmpName = string.Format("Unknown ({0})", objectAttribute.Type.ToString());
            else
                tmpName = pkcs11Attribute.Name;
    
            // Determine attribute value
            if (pkcs11Attribute == null)
            {
                if (objectAttribute.CannotBeRead)
                    tmpValue = "<unextractable>";
                else
                    tmpValue = BytesToHexString(objectAttribute.GetValueAsByteArray());
            }
            else
            {
                if (objectAttribute.CannotBeRead)
                {
                    tmpValue = "<unextractable>";
                }
                else
                {
                    // TODO - More robust conversions
                    switch (pkcs11Attribute.Type)
                    {
                        case AttributeType.Bool:

                            tmpValue = objectAttribute.GetValueAsBool().ToString();

                            break;

                        case AttributeType.ByteArray:

                            tmpValue = BytesToHexString(objectAttribute.GetValueAsByteArray());

                            break;

                        case AttributeType.DateTime:

                            DateTime? dateTime = objectAttribute.GetValueAsDateTime();
                            tmpValue = (dateTime == null) ? null : dateTime.Value.ToShortDateString();

                            break;

                        case AttributeType.String:

                            tmpValue = objectAttribute.GetValueAsString();

                            break;

                        case AttributeType.ULong:

                            tmpValue = GetAttributeEnumValue(pkcs11Attribute, objectAttribute.GetValueAsUlong(), false);

                            break;

                        case AttributeType.AttributeArray:
                        case AttributeType.MechanismArray:
                        case AttributeType.ULongArray:

                            tmpValue = "<unsupported>"; // TODO

                            break;

                        default:

                            tmpValue = "<unknown>";

                            break;
                    }

                    if (string.IsNullOrEmpty(tmpValue))
                        tmpValue = "<empty>";
                }
            }

            // Set output parameters
            name = tmpName;
            value = tmpValue;
        }

        public static string GetAttributeEnumValue(ulong attribute, ulong value, bool preferFriendlyName)
        {
            string strValue = value.ToString();

            AttributeDefinition pkcs11Attribute = null;
            if (config.AttributeDefinitions.ContainsKey(attribute))
            {
                pkcs11Attribute = config.AttributeDefinitions[attribute];
                strValue = GetAttributeEnumValue(pkcs11Attribute, value, preferFriendlyName);
            }

            return strValue;
        }

        public static string GetAttributeEnumValue(AttributeDefinition attributeDefinition, ulong attributeValue, bool preferFriendlyName)
        {
            if (attributeDefinition == null)
                throw new ArgumentNullException("attributeDefinition");

            string strValue = attributeValue.ToString();

            if (!string.IsNullOrEmpty(attributeDefinition.Enum))
            {
                if ((config.EnumDefinitions.ContainsKey(attributeDefinition.Enum)) &&
                    (config.EnumDefinitions[attributeDefinition.Enum].ContainsKey(attributeValue)))
                {
                    EnumMember enumMember = config.EnumDefinitions[attributeDefinition.Enum][attributeValue];
                    if ((preferFriendlyName == true) && (!string.IsNullOrEmpty(enumMember.FriendlyName)))
                        strValue = enumMember.FriendlyName;
                    else
                        strValue = enumMember.Name;
                }
                else
                {
                    strValue = string.Format("Unknown ({0})", attributeValue.ToString());
                }
            }

            return strValue;
        }

        private static ObjectAttribute GetDefaultAttribute(ulong type, string defaultValue)
        {
            ObjectAttribute objectAttribute = null;

            if (defaultValue == null)
            {
                objectAttribute = new ObjectAttribute(type);
            }
            else
            {
                if (defaultValue.StartsWith("ULONG:"))
                {
                    string ulongString = defaultValue.Substring("ULONG:".Length);
                    ulong ulongValue = Convert.ToUInt64(ulongString);
                    objectAttribute = new ObjectAttribute(type, ulongValue);
                }
                else if (defaultValue.StartsWith("BOOL:"))
                {
                    string boolString = defaultValue.Substring("BOOL:".Length);
                    
                    bool boolValue = false;
                    if (0 == string.Compare(boolString, "TRUE", true))
                        boolValue = true;
                    else if (0 == string.Compare(boolString, "FALSE", true))
                        boolValue = false;
                    else
                        throw new Exception("Unable to parse default value of class attribute");
                    
                    objectAttribute = new ObjectAttribute(type, boolValue);
                }
                else if (defaultValue.StartsWith("STRING:"))
                {
                    string strValue = defaultValue.Substring("STRING:".Length);
                    objectAttribute = new ObjectAttribute(type, strValue);
                }
                else if (defaultValue.StartsWith("BYTES:"))
                {
                    string hexString = defaultValue.Substring("BYTES:".Length);
                    byte[] bytes = ConvertUtils.HexStringToBytes(hexString);
                    objectAttribute = new ObjectAttribute(type, bytes);
                }
                else if (defaultValue.StartsWith("DATE:"))
                {
                    // TODO
                    throw new NotImplementedException();
                }
                else
                {
                    throw new Exception("Unable to parse default value of class attribute");
                }
            }

            return objectAttribute;
        }

        private static List<Tuple<ObjectAttribute, ClassAttribute>> GetDefaultAttributes(ClassAttributesDefinition classAttributes, ulong? objectType, bool createObject)
        {
            if (classAttributes == null)
                throw new ArgumentNullException("classAttributes");

            List<Tuple<ObjectAttribute, ClassAttribute>> objectAttributes = new List<Tuple<ObjectAttribute, ClassAttribute>>();

            foreach (ClassAttribute classAttribute in classAttributes.CommonAttributes)
            {
                ObjectAttribute objectAttribute = (createObject) ? GetDefaultAttribute(classAttribute.Value, classAttribute.CreateDefaultValue) : GetDefaultAttribute(classAttribute.Value, classAttribute.GenerateDefaultValue);
                objectAttributes.Add(new Tuple<ObjectAttribute, ClassAttribute>(objectAttribute, classAttribute));
            }

            if ((objectType != null) && (classAttributes.TypeSpecificAttributes.ContainsKey(objectType.Value)))
            {
                foreach (ClassAttribute classAttribute in classAttributes.TypeSpecificAttributes[objectType.Value])
                {
                    ObjectAttribute objectAttribute = (createObject) ? GetDefaultAttribute(classAttribute.Value, classAttribute.CreateDefaultValue) : GetDefaultAttribute(classAttribute.Value, classAttribute.GenerateDefaultValue);
                    objectAttributes.Add(new Tuple<ObjectAttribute, ClassAttribute>(objectAttribute, classAttribute));
                }
            }

            return objectAttributes;
        }

        public static List<Tuple<ObjectAttribute, ClassAttribute>> GetCreateDefaultAttributes(ClassAttributesDefinition classAttributes, ulong? objectType)
        {
            if (classAttributes == null)
                throw new ArgumentNullException("classAttributes");

            return GetDefaultAttributes(classAttributes, objectType, true);
        }

        public static List<Tuple<ObjectAttribute, ClassAttribute>> GetGenerateDefaultAttributes(ClassAttributesDefinition classAttributes, ulong? objectType)
        {
            if (classAttributes == null)
                throw new ArgumentNullException("classAttributes");

            return GetDefaultAttributes(classAttributes, objectType, false);
        }
    }
}
