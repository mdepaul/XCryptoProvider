using System;
using System.Security.Cryptography;

namespace MD.XCryptoProvider
{
    public class ShaProvider
    {
        readonly Algorithm SelectedAlgorithm;
        public enum Algorithm
        {
            SHA1,
            SHA256,
            SHA384,
            SHA512
        }

        /// <summary>
        /// Creates a SHA-256 hash provider
        /// </summary>
        public ShaProvider()
        {
            SelectedAlgorithm = Algorithm.SHA256;
        }

        public ShaProvider(Algorithm hashAlgorithm)
        {
            SelectedAlgorithm = hashAlgorithm;
        }

        public byte[] ComputeHash(byte[] input)
        {
            switch (SelectedAlgorithm)
            {
                case Algorithm.SHA1:
                    return SHA1Cng.Create().ComputeHash(input);
                case Algorithm.SHA256:
                    return SHA256Cng.Create().ComputeHash(input);
                case Algorithm.SHA384:
                    return SHA384Cng.Create().ComputeHash(input);
                case Algorithm.SHA512:
                    return SHA512Cng.Create().ComputeHash(input);
                default:
                    throw new ArgumentException("Valid options are: SHA1, SHA256, SHA384 or SHA512");
            }
        }
    }
}
