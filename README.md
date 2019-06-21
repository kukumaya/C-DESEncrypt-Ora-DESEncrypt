# CSharp-DESEncrypt-Ora-DESEncrypt
DECEncrypt&amp;DESDecrypt realized by C# and Oracle
# CSharp Realized
```CSharp
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
```
# Oracle Realized
```Oracle
create or replace function Func_encrypt_des(p_text varchar2)
return varchar2 is
p_key varchar2(20);
v_text varchar2(4000);
v_enc varchar2(4000);
raw_input RAW(128) ;
key_input RAW(128) ;
decrypted_raw RAW(2048);
begin 
    p_key:='EnCryptK';
  if p_text is null or p_text='' then
    return '';
  end if;
v_text := rpad( p_text, (trunc(length(p_text)/8)+1)*8, chr(0));
raw_input := UTL_RAW.CAST_TO_RAW(v_text);
key_input := UTL_RAW.CAST_TO_RAW(p_key);
dbms_obfuscation_toolkit.DESEncrypt(input => raw_input,key => key_input,encrypted_data =>decrypted_raw);
v_enc := rawtohex(decrypted_raw);
return v_enc;
end;

create or replace function Func_decrypt_des(p_text varchar2)
return varchar2 is
p_key varchar2(20);
v_text varchar2(2000); 
begin
 if nvl(p_text,'-1')='-1' then
   return '';
 end if;
 p_key:='EnCryptK';
dbms_obfuscation_toolkit.DESDECRYPT(input_string => UTL_RAW.CAST_TO_varchar2(p_text),key_string =>p_key, decrypted_string=> v_text);
v_text := rtrim(v_text,chr(0));
dbms_output.put_line(v_text);
return v_text;
exception 
  when others  then
  return '';
end;
```
