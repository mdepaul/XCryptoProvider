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
        readonly byte[] IV;
        readonly byte[] Key;
        readonly PaddingMode PaddingModeChoice = PaddingMode.PKCS7;
        readonly CipherMode CipherModeChoice = CipherMode.CBC;

        /// <summary>
        /// Auto-generates a unique Key and IV
        /// </summary>
        /// <param name="paddingMode">Defaults to PKCS7 padding. Set to NONE only if the cipher text will be a multiple of the block size</param>
        public AesProvider(PaddingMode paddingMode = PaddingMode.PKCS7, CipherMode cipherMode = CipherMode.CBC)
        {
            PaddingModeChoice = paddingMode;
            CipherModeChoice = cipherMode;
            using (var aes = Aes.Create())
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
        public AesProvider(byte[] key, byte[] iv, PaddingMode paddingMode = PaddingMode.PKCS7, CipherMode cipherMode = CipherMode.CBC)
        {
            PaddingModeChoice = paddingMode;
            CipherModeChoice = cipherMode;
            if (key.Length != 16 && key.Length != 24 && key.Length != 32)
            {
                throw new ArgumentException($"The {"key"} must be 16, 24 or 32 bytes in length. The {"key"} given is {key.Length} bytes in length.");
            }
            if (iv.Length != 16)
            {
                throw new ArgumentException($"The {"iv"} must be exactly 16 bytes in length. The {"iv"} given is {iv.Length} bytes in length.");
            }
            Key = key;
            IV = iv;
        }

        public byte[] Encrypt(byte[] plainBytes)
        {
            return Encrypt(plainBytes, Key, IV);
        }

        public byte[] Decrypt(byte[] cipherText)
        {
            return Decrypt(cipherText, Key, IV);
        }

        byte[] Encrypt(byte[] plainBytes, byte[] key, byte[] iv)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Padding = PaddingModeChoice;
                aes.Mode = CipherModeChoice;

                #region debug logging
#if DEBUG
                //Below requires referencing https://github.com/mdepaul/XConvert.git
                //System.Console.Out.WriteLine($"Plain Text ==> {plainText.ToHex()}\nKey ==> {key.ToHex()}\nIV ===> {iv.ToHex()}\nPadding ==> {aes.Padding.ToString()}\nCipher Mode ==> {aes.Mode.ToString()}");
#endif
                #endregion

                using (ICryptoTransform encryptor = aes.CreateEncryptor())
                using (MemoryStream stream = new MemoryStream())
                using (CryptoStream cstream = new CryptoStream(stream, encryptor,
                    CryptoStreamMode.Write))
                {
                    cstream.Write(plainBytes, 0, plainBytes.Length);
                    cstream.FlushFinalBlock();
                    return stream.ToArray();
                }
            }
        }

        byte[] Decrypt(byte[] cipherText, byte[] key, byte[] iv)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Padding = PaddingModeChoice;
                aes.Mode = CipherModeChoice;
                using (var memoryStream = new MemoryStream())
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
}
