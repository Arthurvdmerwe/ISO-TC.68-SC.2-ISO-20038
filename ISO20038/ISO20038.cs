using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ConsoleApp1
{
    public class ISO20038
    {
        //simulate the pin protect key
        private static readonly byte[] keyBytes128 = Hex.Decode("2b7e151628aed2a6abf7158809cf4f3c");
        private static readonly byte[] keyBytes192 = Hex.Decode("8e73b0f7da0e6452c810f32b809079e5" + "62f8ead2522c6b7b");
        private static readonly byte[] keyBytes256 = Hex.Decode("603deb1015ca71be2b73aef0857d7781" + "1f352c073b6108d72d9810a30914dff4");
        private static byte[] Derived_Encryption_Key { get; set; }
        private static byte[] Derived_MAC_Key { get; set; }
        public ISO20038()
        {

        }

        public void runTest()
        {

            IBlockCipher cipher = new AesEngine();
            IMac mac = new CMac(cipher, 128);
            KeyParameter key = new KeyParameter(keyBytes128);

            var Encryption_derived_Block_AES128 = new KeyDerevationBlock() { Counter = "01", KeyUsageIndicator = "0000", Seperator = "00", AlgorithmIndicator = "0002", Length = "0080" };
            byte[] EncryptionBlockInput = Encryption_derived_Block_AES128.CreateKeyDevBytes();
            var MAC_derived_Block_AES128 = new KeyDerevationBlock() { Counter = "01", KeyUsageIndicator = "0001", Seperator = "00", AlgorithmIndicator = "0002", Length = "0080" };
            byte[] MACnBlockInput = MAC_derived_Block_AES128.CreateKeyDevBytes();
            Console.WriteLine("----------------------------------------------------------------");
            Console.WriteLine("Deriving a Key for Encryption");
            Console.WriteLine("Using input derivation key: " + Encryption_derived_Block_AES128.CreateKeyDev());

            mac.Init(key);
            mac.BlockUpdate(EncryptionBlockInput, 0, EncryptionBlockInput.Length);
            byte[] outBytes = new byte[16];
            mac.DoFinal(outBytes, 0);
            Console.WriteLine("Derived Encryption Key:" + Hex.ToHexString(outBytes));
            Derived_Encryption_Key = outBytes;

            Console.WriteLine("----------------------------------------------------------------");
            Console.WriteLine("Deriving a Key for MAC");
            Console.WriteLine("Using input derivation key: " + MAC_derived_Block_AES128.CreateKeyDev());
            mac.Init(key);
            mac.BlockUpdate(MACnBlockInput, 0, MACnBlockInput.Length);

            mac.DoFinal(outBytes, 0);
            Console.WriteLine("Derived MAC Key:" + Hex.ToHexString(outBytes));
            Derived_MAC_Key = outBytes;         
            Console.WriteLine("----------------------------------------------------------------");
            //build block


        }


        byte[] getDerivedMACKey()
        {

            return Derived_MAC_Key;

        }
        byte[] getDerivedEncryptionKey()
        {

            return Derived_Encryption_Key;

        }


    }
}
