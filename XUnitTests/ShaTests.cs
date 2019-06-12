using MD.XConvert;
using MD.XCryptoProvider;
using System;
using Xunit;

namespace UnitTests
{

    public class ShaTests
    {
        //https://en.wikipedia.org/wiki/SHA-1#Examples_and_pseudocode
        [Theory]
        [InlineData("The quick brown fox jumps over the lazy dog", ShaProvider.Algorithm.SHA1, "L9ThxnotKPzthJ7hu3bnORuT6xI=")]
        public void ValidateSha1(string input, ShaProvider.Algorithm algorithm, string expectedHash)
        {

            ShaProvider sha = new ShaProvider(algorithm);
            string computedHash = sha.ComputeHash(input.GetBytes()).ToBase64String();

            Assert.Equal(expectedHash, computedHash);
        }

        //https://en.wikipedia.org/wiki/SHA-2#Test_vectors
        [Theory]
        [InlineData("", ShaProvider.Algorithm.SHA256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")]
        [InlineData("", ShaProvider.Algorithm.SHA384, "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b")]
        [InlineData("", ShaProvider.Algorithm.SHA512, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")]
        public void ValidateSha256(string input, ShaProvider.Algorithm algorithm, string expectedHash)
        {
            ShaProvider sha = new ShaProvider(algorithm);
            string computedHash = sha.ComputeHash(input.GetBytes()).ToHex();

            Assert.Equal(expectedHash, computedHash, true);
        }

        [Fact]
        public void ValidateSha256_Default()
        {
            byte[] input = "".GetBytes();
            const string expectedHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

            ShaProvider sha = new ShaProvider();
            string computedHash = sha.ComputeHash(input).ToHex();

            Assert.Equal(expectedHash, computedHash, true);
        }
    }
}
