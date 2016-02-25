using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;
using Windows.Storage.Streams;
using Windows.Security.Cryptography;
using static Windows.Security.Cryptography.CryptographicBuffer;

namespace Skryptonite.Tests
{
    [TestClass]
    public class ScryptTests
    {
        void Scrypt_Test_Vectors()
        {
            IBuffer output0 = new Scrypt(1, 16, 1).DeriveKey(new Windows.Storage.Streams.Buffer(0), new Windows.Storage.Streams.Buffer(0), 64);
            IBuffer output1 = new Scrypt(2, 32, 2).DeriveKey(ConvertStringToBinary("password", BinaryStringEncoding.Utf8), ConvertStringToBinary("NaCl", BinaryStringEncoding.Utf8), 64);
            IBuffer output2 = new Scrypt(8, 1024, 16).DeriveKey(ConvertStringToBinary("password", BinaryStringEncoding.Utf8), ConvertStringToBinary("NaCl", BinaryStringEncoding.Utf8), 64);

            IBuffer expectedOutput0 = DecodeFromHexString("77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906");
            IBuffer expectedOutput1 = DecodeFromHexString("b034a96734ebdc650fca132f40ffde0823c2f780d675eb81c85ec337d3b1176017061beeb3ba18df59802b95a325f5f850b6fd9efb1a6314f835057c90702b19");
            IBuffer expectedOutput2 = DecodeFromHexString("fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640");

            Assert.AreEqual(EncodeToHexString(expectedOutput0), EncodeToHexString(output0));
            Assert.AreEqual(EncodeToHexString(expectedOutput1), EncodeToHexString(output1));
            Assert.AreEqual(EncodeToHexString(expectedOutput2), EncodeToHexString(output2));

            // Longer running tests
            IBuffer output3 = new Scrypt(8, 16384, 1).DeriveKey(ConvertStringToBinary("pleaseletmein", BinaryStringEncoding.Utf8), ConvertStringToBinary("SodiumChloride", BinaryStringEncoding.Utf8), 64);
            IBuffer output4 = new Scrypt(8, 1048576, 1).DeriveKey(ConvertStringToBinary("pleaseletmein", BinaryStringEncoding.Utf8), ConvertStringToBinary("SodiumChloride", BinaryStringEncoding.Utf8), 64);

            IBuffer expectedOutput3 = DecodeFromHexString("7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887");
            IBuffer expectedOutput4 = DecodeFromHexString("2101cb9b6a511aaeaddbbe09cf70f881ec568d574a2ffd4dabe5ee9820adaa478e56fd8f4ba5d09ffa1c6d927c40f4c337304049e8a952fbcbf45c6fa77a41a4");

            Assert.AreEqual(EncodeToHexString(expectedOutput3), EncodeToHexString(output3));
            Assert.AreEqual(EncodeToHexString(expectedOutput4), EncodeToHexString(output4));
        }

        [TestMethod]
        public void CreateOptimal__Correct()
        {
            Assert.Inconclusive();
        }

        [TestMethod]
        public void Handle_Out_Of_Memory()
        {
            Assert.Inconclusive();
        }

#if INTEL
        [TestMethod]
        public void Scrypt_Test_Vectors_AVX2()
        {
            DetectInstructionSet.MaxInstructionSet = InstructionSet.AVX2;
            Scrypt_Test_Vectors();
        }

        [TestMethod]
        public void Scrypt_Test_Vectors_AVX()
        {
            DetectInstructionSet.MaxInstructionSet = InstructionSet.AVX;
            Scrypt_Test_Vectors();
        }

        [TestMethod]
        public void Scrypt_Test_Vectors_SSE41()
        {
            DetectInstructionSet.MaxInstructionSet = InstructionSet.SSE41;
            Scrypt_Test_Vectors();
        }

        [TestMethod]
        public void Scrypt_Test_Vectors_SSSE3()
        {
            DetectInstructionSet.MaxInstructionSet = InstructionSet.SSSE3;
            Scrypt_Test_Vectors();
        }

        [TestMethod]
        public void Scrypt_Test_Vectors_SSE2()
        {
            DetectInstructionSet.MaxInstructionSet = InstructionSet.SSE2;
            Scrypt_Test_Vectors();
        }
#elif ARM
        [TestMethod]
        public void Scrypt_Test_Vectors_NEON()
        {
            DetectInstructionSet.MaxInstructionSet = InstructionSet.NEON;
            Scrypt_Test_Vectors();
        }
#endif
    }
}