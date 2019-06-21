using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace EnCryptContext
{
    public static class DesCryptProvider
    {
        public static string Encrypt(string stringToEncrypt)
        {
            DESCryptoServiceProvider des = new DESCryptoServiceProvider();

            byte[] inputByteArray = Encoding.GetEncoding("UTF-8").GetBytes(stringToEncrypt);

            var length = stringToEncrypt.Length;
            var inputlen = (Math.Truncate(length / 8d) + 1) * 8;
            for (int i = 0; i < inputlen - length; i++)
            {
                inputByteArray = inputByteArray.Concat(new byte[] { 0 }).ToArray();
            }
            des.Padding = PaddingMode.None;
            var sKey = ConfigurationManager.AppSettings["EncryptKey"];
            des.Key = ASCIIEncoding.UTF8.GetBytes(sKey);
            des.IV = new byte[des.KeySize / 8];
            MemoryStream ms = new MemoryStream();
            CryptoStream cs = new CryptoStream(ms, des.CreateEncryptor(), CryptoStreamMode.Write);

            cs.Write(inputByteArray, 0, inputByteArray.Length);
            cs.FlushFinalBlock();

            StringBuilder ret = new StringBuilder();
            foreach (byte b in ms.ToArray())
            {
                ret.AppendFormat("{0:X2}", b);
            }
            ret.ToString();
            return ret.ToString();
        }
        public static string Decrypt(string stringToDecrypt)
        {
            DESCryptoServiceProvider des = new DESCryptoServiceProvider();

            byte[] inputByteArray = new byte[stringToDecrypt.Length / 2];
            for (int x = 0; x < stringToDecrypt.Length / 2; x++)
            {
                int i = (Convert.ToInt32(stringToDecrypt.Substring(x * 2, 2), 16));
                inputByteArray[x] = (byte)i;
            }
            des.Padding = PaddingMode.None;
            var sKey = ConfigurationManager.AppSettings["EncryptKey"];
            des.Key = ASCIIEncoding.UTF8.GetBytes(sKey);
            des.IV = new byte[des.KeySize / 8];
            MemoryStream ms = new MemoryStream();
            CryptoStream cs = new CryptoStream(ms, des.CreateDecryptor(), CryptoStreamMode.Write);
            cs.Write(inputByteArray, 0, inputByteArray.Length);
            cs.FlushFinalBlock();

            StringBuilder ret = new StringBuilder();

            return System.Text.Encoding.Default.GetString(ms.ToArray());
        }
    }
}
