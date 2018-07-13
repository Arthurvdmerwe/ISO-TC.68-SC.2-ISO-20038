using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ConsoleApp1
{
   public  class KeyDerevationBlock
    {


    
            public KeyDerevationBlock()
            {
                Counter = "01";
                Seperator = "00";
            }
            /// <summary>
            /// A counter that is incremented for each CMAC operation
            /// </summary>
            public string Counter { get; set; }

            /// <summary>
            /// Set the counter value
            /// </summary>
            /// <param name="counter">0x01–0x02</param>
            public void setCounter(string counter)
            {
                Counter = counter;
            }

            /// <summary>
            /// 4H Encoding
            /// </summary>
            public string KeyUsageIndicator { get; set; }

            /// <summary>
            /// Indicates whether the key to be derived is to be used for encryption/decryption or MAC generation/verification
            /// Possible values that can be used are>
            /// 0x0000 = encryption CBC mode
            /// 0x0001 = MAC
            /// 0x0002 = encryption CTR mode
            /// </summary>
            /// <param name="keyUsageIndicator"></param>
            public void setKeyUsageIndicator(string keyUsageIndicator)
            {
                KeyUsageIndicator = keyUsageIndicator;
            }


            /// <summary>
            /// Indicates whether the key to be derived is to be used for
            /// encryption/decryption or MAC
            /// generation/verification
            /// </summary>
            public string Seperator { get; set; }

            /// <summary>
            /// Indicates the encryption and MAC block cipher algorithm that is going to use the two derived keys (and is used to derive those keys)
            /// </summary>
            public string AlgorithmIndicator { get; set; }

            /// <summary>
            /// Indicates the encryption and MAC block cipher algorithm that is going to use the two derived keys (and is used to derive those keys)
            /// 0x0002 = AES 128 bit
            /// 0x0003 = AES 192 bit
            /// 0x0004 = AES 256 bit
            /// </summary>
            /// <param name="algorithmIndicator">0002 / 0003 / 0004</param>
            public void setAlgorithmIndicator(string algorithmIndicator)
            {
                AlgorithmIndicator = algorithmIndicator;
            }

            /// <summary>
            /// Length, in bits, of the keying material being generated for the pair of encryption and MAC keys
            /// </summary>
            public string Length { get; set; }

            /// <summary>
            /// Length, in bits, of the keying material being generated for the pair of encryption and MAC keys
            /// 0x0080 if AES-128 keys are being generated
            /// 0x00C0 if AES-192 keys are being generated
            /// 0x0100 if AES-256 keys are being generated
            /// </summary>
            /// <param name="length"></param>
            public void setLength(string length)
            {
                Length = length;
            }

            public string CreateKeyDev()
            {
                return Counter + KeyUsageIndicator + Seperator + AlgorithmIndicator + Length;
            }

            public byte[] CreateKeyDevBytes()
            {
                string hexkeyDev = CreateKeyDev();
                return StringToByteArray(hexkeyDev);

            }


            public static byte[] StringToByteArray(string hex)
            {
                return Enumerable.Range(0, hex.Length)
                                 .Where(x => x % 2 == 0)
                                 .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                                 .ToArray();
            }
        }



    
}
