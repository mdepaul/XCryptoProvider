using System;

namespace MD.XCryptoProvider
{
    public class ShaProvider
    {
        Algorithm SelectedAlgorithm;
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
                    return System.Security.Cryptography.SHA1Managed.Create().ComputeHash(input);
                case Algorithm.SHA256:
                    return System.Security.Cryptography.SHA256Managed.Create().ComputeHash(input);
                case Algorithm.SHA384:
                    return System.Security.Cryptography.SHA384Managed.Create().ComputeHash(input);
                case Algorithm.SHA512:
                    return System.Security.Cryptography.SHA512Managed.Create().ComputeHash(input);
                default:
                    throw new ArgumentException("Valid options are: SHA1, SHA256, SHA384 or SHA512");
            }
        }
    }
}
