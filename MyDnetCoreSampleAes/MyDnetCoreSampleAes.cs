using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

using System.IO;
using System.Security.Cryptography;
using System.Text;


namespace MyAes
{
    public class MyAes
    {
        public static void Main(string[] args)
        {
            String pwd = "ThisIsMyPassword";
            byte[] OriginalData = Encoding.ASCII.GetBytes(
                "This is my original data, and it will be encrypted and then decrypted for testing" );


            byte[] EncriptedData = EncryptDecrypt( OriginalData,  pwd, false );
            byte[] DecryptedData = EncryptDecrypt( EncriptedData, pwd, true );


            Console.WriteLine("OriginalData  = " + Encoding.ASCII.GetString( OriginalData ));
            Console.WriteLine("DecryptedData = " + Encoding.ASCII.GetString( DecryptedData ));

            Console.WriteLine("OriginalData.Length  = " + OriginalData.Length );
            Console.WriteLine("EncriptedData.Length = " + EncriptedData.Length );
            Console.WriteLine("EncriptedData.ToBase64String = " + Convert.ToBase64String(EncriptedData) );

        }


        public static byte[] EncryptDecrypt(byte[] bData, string password, bool IsDecrypt)
        {
            // FYI: In real world scenario avoid using a constant value for 'salt'
            byte[] salt   = Encoding.ASCII.GetBytes("#MySalt+!33vs./s@&"); // salt must be at least 8 bytes

            // iterations count should be greater than zero. 
            // The minimum recommended number of iterations is 1000.
            int iterations = 2000;

            // Implements password-based key derivation functionality, 
            // PBKDF2, by using a pseudo-random number generator based on HMACSHA1.
            // The iterations, Repeatedly hash the user password along with the salt.
            Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations);

            Aes aes = Aes.Create();
            aes.Key = pbkdf2.GetBytes(32); // set a 32*8 = 256-bit key 
            aes.IV  = pbkdf2.GetBytes(16); // set a 18*8 = 128-bit IV 

            ICryptoTransform xfrm;
            if (IsDecrypt)
            {
                xfrm = aes.CreateDecryptor();
            }
            else
            {
                xfrm = aes.CreateEncryptor();
            }

            MemoryStream ms = new MemoryStream();
            using (CryptoStream cs = new CryptoStream(ms, xfrm, CryptoStreamMode.Write))
            {
                cs.Write(bData, 0, bData.Length);
            }

            return( ms.ToArray() );
        }
    }
}


