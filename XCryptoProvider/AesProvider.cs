using System;
using System.IO;
using System.Security.Cryptography;

namespace MD.XCryptoProvider
{
    /// <summary>
    /// Encapsulates AES encryption and decryption functionality
    /// 
    /// http://security.stackexchange.com/questions/52665/which-is-the-best-cipher-mode-and-padding-mode-for-aes-encryption
    /// </summary>
    public class AesProvider
    {
        const int KeyLength = 32;
        const int IvLength = 16;
        byte[] IV;
        byte[] Key;
        PaddingMode PaddingModeChoice = PaddingMode.ISO10126;

        /// <summary>
        /// Auto-generates a unique Key and IV
        /// </summary>
        /// <param name="paddingMode">Defaults to ISO10126 (random) padding. Set to NONE only if the cipher text will be a multiple of the block size</param>
        public AesProvider(PaddingMode paddingMode = PaddingMode.ISO10126)
        {
            PaddingModeChoice = paddingMode;
            using (var aes = new AesManaged())
            {
                Key = aes.Key;
                IV = aes.IV;
            }
        }

        /// <summary>
        /// Initialize AES with a given KEY and IV
        /// </summary>
        /// <param name="key">32 byte key</param>
        /// <param name="iv">16 byte IV</param>
        /// <param name="paddingMode">Defaults to ISO10126 (random) padding. Set to NONE only if the cipher text will be a multiple of the block size</param>
        public AesProvider(byte[] key, byte[] iv, PaddingMode paddingMode = PaddingMode.ISO10126)
        {
            PaddingModeChoice = paddingMode;
            if (key.Length != KeyLength)
            {
                throw new ArgumentException($"The {"key"} must be exactly {KeyLength} bytes in length. The {"key"} given is {key.Length} bytes in length.");
            }
            if (iv.Length != IvLength)
            {
                throw new ArgumentException($"The {"iv"} must be exactly {IvLength} bytes in length. The {"iv"} given is {iv.Length} bytes in length.");
            }
            Key = key;
            IV = iv;
        }

        public byte[] Encrypt(byte[] plainText)
        {
            return Encrypt(plainText, Key, IV);
        }

        public byte[] Decrypt(byte[] cipherText)
        {
            return Decrypt(cipherText, Key, IV);
        }

        byte[] Encrypt(byte[] plainText, byte[] key, byte[] iv)
        {

            using (AesManaged aes = new AesManaged() { Key = key, IV = iv, Padding = PaddingModeChoice })
            using (ICryptoTransform encryptor = aes.CreateEncryptor())
            using (MemoryStream stream = new MemoryStream())
            using (CryptoStream cstream = new CryptoStream(stream, encryptor,
                CryptoStreamMode.Write))
            {
                cstream.Write(plainText, 0, plainText.Length);
                cstream.FlushFinalBlock();
                byte[] encryptedData = stream.ToArray();
                return encryptedData;
            }
        }

        byte[] Decrypt(byte[] cipherText, byte[] key, byte[] iv)
        {

            using (var memoryStream = new MemoryStream())
            using (AesManaged aes = new AesManaged() { Key = key, IV = iv, Padding = PaddingModeChoice })
            using (ICryptoTransform decryptor = aes.CreateDecryptor())
            using (var cryptoStream = new CryptoStream(memoryStream, decryptor,
                CryptoStreamMode.Write))
            {
                cryptoStream.Write(cipherText, 0, cipherText.Length);
                cryptoStream.FlushFinalBlock();
                return memoryStream.ToArray();
            }
        }
    }
}
