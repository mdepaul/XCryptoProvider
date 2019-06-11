using MD.XConvert;
using MD.XCryptoProvider;
using System;
using Xunit;

namespace UnitTests
{
    public class AesTests
    {
        [Theory]
        [InlineData(32, 16)]
        public void GoodKeyAndIVTest(int keyLen, int ivLen)
        {
            AesProvider aes = new AesProvider();
            ShaProvider sha = new ShaProvider();
            byte[] plain = new byte[] { 0x96, 0x0D, 0x38, 0x4E, 0xE8, 0xE2, 0xE4, 0x7C, 0x32, 0x7D, 0xDB, 0x28, 0x50, 0x15, 0x23, 0x5E, 0xC1, 0xD8, 0x7A, 0x05, 0x19, 0x62, 0x63, 0x23, 0x1F, 0x27, 0x9C, 0x3B, 0xA9, 0x0E, 0x81, 0xB6 };
            string plainHex = plain.ToHex();

            byte[] encrypted = aes.Encrypt(plain);
            byte[] decrypted = aes.Decrypt(encrypted);

            Assert.Equal(plainHex, decrypted.ToHex());
        }

        [Theory]
        [InlineData(31, 16)]
        [InlineData(33, 16)]
        [InlineData(32, 1)]
        [InlineData(32, 17)]
        [InlineData(32, 21)]
        [InlineData(32, 33)]
        public void BadKeyOrIVTest(int keyLen, int ivLen)
        {
            byte[] key = new byte[keyLen];
            byte[] iv = new byte[ivLen];
            AesProvider aes;

            Exception ex = Assert.Throws<ArgumentException>(() => aes = new AesProvider(key, iv));

            Assert.Contains(" must be ", ex.Message);
        }

        //https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers#AES
        [Theory]
        [InlineData("8000000000000000000000000000000000000000000000000000000000000000", "00000000000000000000000000000000", "00000000000000000000000000000000", "e35a6dcb19b201a01ebcfa8aa22b5759")]
        [InlineData("0000000000000000000000000000000000000000000000000000000000000000", "00000000000000000000000000000000", "80000000000000000000000000000000", "ddc6bf790c15760d8d9aeb6f9a75fd4e")]
        [InlineData("0000000000000000000000000000000000000000000000000000000000000000", "00000000000000000000000000000000", "f0000000000000000000000000000000", "7f2c5ece07a98d8bee13c51177395ff7")]
        [InlineData("b43d08a447ac8609baadae4ff12918b9f68fc1653f1269222f123981ded7a92f", "00000000000000000000000000000000", "00000000000000000000000000000000", "4663446607354989477a5c6f0f007ef4")]
        public void ConfirmTestVectors(string hexKey, string hexIv, string plainText, string expectedCipherText)
        {
            byte[] key = hexKey.FromHex();
            byte[] iv = hexIv.FromHex();
            AesProvider aes = new AesProvider(key, iv, System.Security.Cryptography.PaddingMode.None);
            byte[] plainBytes = plainText.FromHex();
            byte[] encrptedBytes = aes.Encrypt(plainBytes);

            string cipherText = encrptedBytes.ToHex();
            Assert.Equal(expectedCipherText, cipherText, true);

        }

        [Theory]
        [InlineData("0000000000000000000000000000000000000000000000000000000000000000", "00000000000000000000000000000000", "AABBCCDDEEFF00000000000011223344")]
        [InlineData("00000000000000000000000000000000000000000000000000000000000000FF", "AA000000000000000000000000000000", "AABBCCDDEEFF000000000000112233")]
        [InlineData("000000000000000000000000000000000000000000000000000000000000AAFF", "FF000000000000000000000000000000", "AABBCCDDEEFF0000000000001122")]
        [InlineData("0000000000000000000000000000000000000000000000000000000000000011", "DEAD0000000000000000000000000000", "AABBCCDDEEFF00000000000011")]
        public void EncryptDecryptTest(string hexKey, string hexIv, string plainText)
        {

            byte[] key = hexKey.FromHex();
            byte[] iv = hexIv.FromHex();
            byte[] plainBytes = plainText.FromHex();

            AesProvider aes = new AesProvider(key, iv);
            byte[] encrptedBytes = aes.Encrypt(plainBytes);
            byte[] decryptedBytes = aes.Decrypt(encrptedBytes);

            string encryptedHex = encrptedBytes.ToHex();
            string decryptedHex = decryptedBytes.ToHex();
            Assert.Equal(plainText, decryptedHex, true);
        }

        [Theory]
        [InlineData("00000000000000000000000000000000000000000000000000000000000000FF", "AA000000000000000000000000000000", "AABBCCDDEEFF000000000000112233", System.Security.Cryptography.PaddingMode.None)]
        [InlineData("000000000000000000000000000000000000000000000000000000000000AAFF", "FF000000000000000000000000000000", "AABBCCDDEEFF0000000000001122", System.Security.Cryptography.PaddingMode.None)]
        [InlineData("0000000000000000000000000000000000000000000000000000000000000011", "DEAD0000000000000000000000000000", "AABBCCDDEEFF00000000000011", System.Security.Cryptography.PaddingMode.None)]
        public void InvalidPaddingMode(string hexKey, string hexIv, string plainText, System.Security.Cryptography.PaddingMode paddingMode)
        {
            byte[] key = hexKey.FromHex();
            byte[] iv = hexIv.FromHex();
            byte[] plainBytes = plainText.FromHex();
            byte[] encrptedBytes;

            //None of the cipher texts are an even multiple of the block size, so using no padding causes .NET to throw an error
            AesProvider aes = new AesProvider(key, iv, paddingMode);
            Exception ex = Assert.Throws<System.Security.Cryptography.CryptographicException>(() => encrptedBytes = aes.Encrypt(plainBytes));
        }
    }
}
