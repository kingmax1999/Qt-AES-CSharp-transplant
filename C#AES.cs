using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;


namespace yourNameSpace
{

    public class CSharpAESEncryption
    {
        //transplant from qt-aes
        //https://github.com/bricke
        //thanks bricke
        public CSharpAESEncryption(Aes level, Mode mode, Padding padding = Padding.ISO)
        {
            m_nb = 4;
            m_blocklen = 16;
            m_level = level;
            m_mode = mode;
            m_padding = padding;
            m_aesNIAvailable = false;
            m_state = null;
            switch (level)
            {
                case Aes.AES_128:
                    var aes128 = new AES128();
                    m_nk = aes128.nk;
                    m_keyLen = aes128.keylen;
                    m_nr = aes128.nr;
                    m_expandedKey = aes128.expandedKey;
                    break;
                case Aes.AES_192:
                    var aes192 = new AES192();
                    m_nk = aes192.nk;
                    m_keyLen = aes192.keylen;
                    m_nr = aes192.nr;
                    m_expandedKey = aes192.expandedKey;
                    break;
                case Aes.AES_256:
                    var aes256 = new AES256();
                    m_nk = aes256.nk;
                    m_keyLen = aes256.keylen;
                    m_nr = aes256.nr;
                    m_expandedKey = aes256.expandedKey;
                    break;
                default:
                    var defaultAes = new AES128();
                    m_nk = defaultAes.nk;
                    m_keyLen = defaultAes.keylen;
                    m_nr = defaultAes.nr;
                    m_expandedKey = defaultAes.expandedKey;
                    break;
            }
        }

        public enum Aes
        {
            AES_128,
            AES_192,
            AES_256
        };

        public enum Mode
        {
            ECB,
            CBC,
            CFB,
            OFB
        };

        public enum Padding
        {
            ZERO,
            PKCS7,
            ISO
        };

        int m_nb;
        int m_blocklen;
        Aes m_level;
        Mode m_mode;
        int m_nk;
        int m_keyLen;
        int m_nr;
        int m_expandedKey;
        Padding m_padding;
        bool m_aesNIAvailable;
        byte[] m_state;  //QByteArray* m_state;
        public class AES256
        {
            public  int nk = 8;
            public int keylen = 32;
            public int nr = 14;
            public int expandedKey = 240;
            public int userKeySize = 256;
        };

       public class AES192
        {
            public int nk = 6;
            public int keylen = 24;
            public int nr = 12;
            public int expandedKey = 209;
            public int userKeySize = 192;
        };

      public  class AES128
        {
            public int nk = 4;
            public int keylen = 16;
            public int nr = 10;
            public int expandedKey = 176;
            public int userKeySize = 128;
        };


        // The round constant word array, Rcon[i], contains the values given by
        // x to th e power (i-1) being powers of x (x is denoted as {02}) in the field GF(2^8)
        // Only the first 14 elements are needed
        public static readonly byte[] Rcon = new byte[]
        {
             0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab
        };

        // Constant byte array representing the S-Box 

        public static readonly byte[] sbox = new byte[]
        {
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
        };

        // Constant byte array representing the inverse S-Box (逆S-Box)
        public static readonly byte[] rsbox = new byte[]
        {
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
        0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
        0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
        0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
        0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
        0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
        0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
        0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
        0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
        };

        /*
     * Static Functions
     * */
        /*!
     * \brief static method call to encrypt data given by rawText
     * \param level:    AES::Aes level
     * \param mode:     AES::Mode mode
     * \param rawText:  input text
     * \param key:      user-key (key.size either 128, 192, 256 bits depending on AES::Aes)
     * \param iv:       initialisation-vector (iv.size is 128 bits (16 Bytes))
     * \param padding:  AES::Padding standard
     * \return encrypted cipher
     */
        static byte[] Crypt(Aes level, Mode mode, ref byte[] rawText, byte[] key,
                            byte[] iv, Padding padding=Padding.ISO)
        {
            CSharpAESEncryption instance = new CSharpAESEncryption(level, mode, padding);
            return instance.encode(rawText, key, iv);
        }

        /*!
    * \brief static method call to decrypt data given by rawText
    * \param level:    AES::Aes level
    * \param mode:     AES::Mode mode
    * \param rawText:  input text
    * \param key:      user-key (key.size either 128, 192, 256 bits depending on AES::Aes)
    * \param iv:       initialisation-vector (iv.size is 128 bits (16 Bytes))
    * \param padding:  AES::Padding standard
    * \return decrypted cipher with padding
    */
        static byte[] Decrypt(Aes level, Mode mode, byte[] rawText, byte[] key,
                              byte[] iv, Padding padding=Padding.ISO)
        {
            CSharpAESEncryption instance = new CSharpAESEncryption(level, mode, padding);
            return instance.decode(rawText, key, iv);
        }
        /*!
        * \brief static method call to expand the user key to fit the encrypting/decrypting algorithm
        * \param level:            AES::Aes level
        * \param mode:             AES::Mode mode
        * \param key:              user-key (key.size either 128, 192, 256 bits depending on AES::Aes)
        * \param expKey:           output expanded key
        * \param isEncryptionKey:    always 'true' || only 'false' when DECRYPTING in CBC or EBC mode with aesni (check if supported)
        * \return AES-ready key
        */
        static byte[] ExpandKey(Aes level, Mode mode, byte[] key, bool isEncryptionKey)
        {
            CSharpAESEncryption instance = new CSharpAESEncryption(level, mode,Padding.PKCS7);
            return instance.expandKey(key, isEncryptionKey);
        }
        /*!
       * \brief static method call to remove padding from decrypted cipher given by rawText
       * \param rawText:  inputText
       * \param padding:  AES::Padding standard
       * \return decrypted cipher with padding removed
       */
        static byte[] RemovePadding(byte[] rawText, Padding padding=Padding.ISO)
        {
            if (rawText == null || rawText.Length == 0)
                return rawText;

            byte[] ret = new byte[rawText.Length];
            Array.Copy(rawText, ret, rawText.Length);

            switch (padding)
            {
                case Padding.ZERO:
                    // Works only if the last byte of the decoded array is not zero
                    int zeroPaddingIndex = ret.Length - 1;
                    while (zeroPaddingIndex >= 0 && ret[zeroPaddingIndex] == 0x00)
                    {
                        zeroPaddingIndex--;
                    }
                    Array.Resize(ref ret, zeroPaddingIndex + 1);
                    break;

                case Padding.PKCS7:
                    int pkcs7PaddingLength = ret[ret.Length - 1];
                    Array.Resize(ref ret, ret.Length - pkcs7PaddingLength);
                    break;

                case Padding.ISO:
                    // Find the last byte which is not zero
                    int markerIndex = ret.Length - 1;
                    for (; markerIndex >= 0; --markerIndex)
                    {
                        if (ret[markerIndex] != 0x00)
                        {
                            break;
                        }
                    }

                    // And check if it's the byte for marking padding
                    if (markerIndex >= 0 && ret[markerIndex] == 0x80)
                    {
                        Array.Resize(ref ret, markerIndex);
                    }
                    break;

                default:
                    // Do nothing
                    break;
            }

            return ret;
        }
        /*
        * End Static function declarations
        * */

        /*
         * Local Functions
         * */
        public static byte XTime(byte x)
        {
            return (byte)((x << 1) ^ (((x >> 7) & 1) * 0x1b));
        }

        public static byte Multiply(byte x, byte y)
        {
            return (byte)((((y & 1) * x) ^
                           ((y >> 1 & 1) * XTime(x)) ^
                           ((y >> 2 & 1) * XTime(XTime(x))) ^
                           ((y >> 3 & 1) * XTime(XTime(XTime(x)))) ^
                           ((y >> 4 & 1) * XTime(XTime(XTime(XTime(x)))))));
        }
        /*
         * End Local functions
         * */
        /*!
         * \brief object method call to encrypt data given by rawText
         * \param rawText:  input text
         * \param key:      user-key (key.size either 128, 192, 256 bits depending on AES::Aes)
         * \param iv:       initialisation-vector (iv.size is 128 bits (16 Bytes))
         * \return encrypted cipher
         */
        public byte[] encode(byte[] rawText, byte[] key, byte[] iv)
        {

            if ((m_mode >= Mode.CBC && (iv == null || iv.Length != m_blocklen)) || key.Length != m_keyLen)
                return null;

            byte[] expandedKey = expandKey(key, true);
            byte[] alignedText = new byte[rawText.Length + getPadding(rawText.Length, m_blocklen).Length];
            Buffer.BlockCopy(rawText, 0, alignedText, 0, rawText.Length);
            Buffer.BlockCopy(getPadding(rawText.Length, m_blocklen), 0, alignedText, rawText.Length, getPadding(rawText.Length, m_blocklen).Length);

            switch (m_mode)
            {
                case Mode.ECB:
                    {
                   

                        byte[] ret = new byte[alignedText.Length];
                        for (int i = 0; i < alignedText.Length; i += m_blocklen)
                        {
                            byte[] block = new byte[m_blocklen];
                            Buffer.BlockCopy(alignedText, i, block, 0, m_blocklen);
                            byte[] encryptedBlock = cipher(expandedKey, block);
                            Buffer.BlockCopy(encryptedBlock, 0, ret, i, m_blocklen);
                        }
                        return ret;
                    }
                case Mode.CBC:
                    {
                      

                        byte[] ret = new byte[alignedText.Length];
                        byte[] ivTemp = new byte[m_blocklen];
                        Buffer.BlockCopy(iv, 0, ivTemp, 0, m_blocklen);

                        for (int i = 0; i < alignedText.Length; i += m_blocklen)
                        {
                            byte[] block = new byte[m_blocklen];
                            Buffer.BlockCopy(alignedText, i, block, 0, m_blocklen);
                            block = byteXor(block, ivTemp);
                            byte[] encryptedBlock = cipher(expandedKey, block);
                            Buffer.BlockCopy(encryptedBlock, 0, ret, i, m_blocklen);
                            Buffer.BlockCopy(encryptedBlock, 0, ivTemp, 0, m_blocklen);
                        }
                        return ret;
                    }
                case Mode.CFB:
                    {
                        byte[] ret = new byte[alignedText.Length];
                        byte[] block = new byte[m_blocklen];
                        Buffer.BlockCopy(alignedText, 0, block, 0, m_blocklen);
                        byte[] xorBlock = byteXor(block, cipher(expandedKey, iv));
                        Buffer.BlockCopy(xorBlock, 0, ret, 0, m_blocklen);

                        for (int i = m_blocklen; i < alignedText.Length; i += m_blocklen)
                        {
                            int remaining = Math.Min(m_blocklen, alignedText.Length - i);
                            Buffer.BlockCopy(alignedText, i, block, 0, remaining);
                            xorBlock = byteXor(block, cipher(expandedKey, xorBlock));
                            Buffer.BlockCopy(xorBlock, 0, ret, i, remaining);
                        }
                        return ret;
                    }
                case Mode.OFB:
                    {
                        byte[] ret = new byte[alignedText.Length];
                        byte[] ofbTemp = cipher(expandedKey, iv);
                        for (int i = 0; i < alignedText.Length; i += m_blocklen)
                        {
                            int remaining = Math.Min(m_blocklen, alignedText.Length - i);
                            byte[] block = new byte[m_blocklen];
                            Buffer.BlockCopy(alignedText, i, block, 0, remaining);
                            byte[] xorBlock = byteXor(block, ofbTemp);
                            Buffer.BlockCopy(xorBlock, 0, ret, i, remaining);
                            ofbTemp = cipher(expandedKey, ofbTemp);
                        }
                        return ret;
                    }
                default:
                    return null;
            }
        }
        /*!
    * \brief object method call to decrypt data given by rawText
    * \param rawText:  input text
    * \param key:      user-key (key.size either 128, 192, 256 bits depending on AES::Aes)
    * \param iv:       initialisation-vector (iv.size is 128 bits (16 Bytes))
    * \param padding:  AES::Padding standard
    * \return decrypted cipher with padding
    */
        public byte[] decode(byte[] rawText, byte[] key, byte[] iv)
        {
            if ((m_mode >= Mode.CBC && (iv == null || iv.Length != m_blocklen)) || key.Length != m_keyLen || rawText.Length % m_blocklen != 0)
                return null;

            byte[] ret = new byte[rawText.Length];
            byte[] expandedKey = expandKey(key, false);
            //false or true here is very important
            //the expandedKeys aren't the same for !aes-ni! ENcryption and DEcryption (only CBC and EBC)
            //but if you are !NOT! using aes-ni then the expandedKeys for encryption and decryption are the SAME!!!
            switch (m_mode)
            {
                case Mode.ECB:
                    {
                        for (int i = 0; i < rawText.Length; i += m_blocklen)
                        {
                            byte[] block = rawText.Skip(i).Take(m_blocklen).ToArray();
                            byte[] decryptedBlock = invCipher(expandedKey, block);
                            Buffer.BlockCopy(decryptedBlock, 0, ret, i, m_blocklen);
                        }
                        break;
                    }
                case Mode.CBC:
                    {
                        byte[] ivTemp = iv.ToArray();
                        for (int i = 0; i < rawText.Length; i += m_blocklen)
                        {
                            byte[] block = rawText.Skip(i).Take(m_blocklen).ToArray();
                            byte[] decryptedBlock = invCipher(expandedKey, block);
                            byte[] xorBlock = byteXor(decryptedBlock, ivTemp);
                            Buffer.BlockCopy(xorBlock, 0, ret, i, m_blocklen);
                            ivTemp = block;
                        }
                        break;
                    }
                case Mode.CFB:
                    {
                        byte[] xorBlock = byteXor(rawText.Take(m_blocklen).ToArray(), invCipher(expandedKey, iv));
                        Buffer.BlockCopy(xorBlock, 0, ret, 0, m_blocklen);

                        for (int i = m_blocklen; i < rawText.Length; i += m_blocklen)
                        {
                            if (i + m_blocklen < rawText.Length)
                            {
                                byte[] block = rawText.Skip(i + m_blocklen).Take(m_blocklen).ToArray();
                                xorBlock = byteXor(block, invCipher(expandedKey, rawText.Skip(i).Take(m_blocklen).ToArray()));
                                Buffer.BlockCopy(xorBlock, 0, ret, i, m_blocklen);
                            }
                        }
                        break;
                    }
                case Mode.OFB:
                    {
                        byte[] ofbTemp = invCipher(expandedKey, iv);
                        for (int i = m_blocklen; i < rawText.Length; i += m_blocklen)
                        {
                            ofbTemp = invCipher(expandedKey, ofbTemp);
                        }
                        Buffer.BlockCopy(byteXor(rawText, ofbTemp), 0, ret, 0, rawText.Length);
                        break;
                    }
                default:
                    throw new NotSupportedException("Cipher mode not supported.");
            }

            return ret;
        }
        /*!
        * \brief object method call to expand the user key to fit the encrypting/decrypting algorithm
        * \param key:              user-key (key.size either 128, 192, 256 bits depending on AES::Aes)
        * \param isEncryptionKey:    always 'true' || only 'false' when DECRYPTING in CBC or EBC mode with aesni (check if supported)
        * \return AES-ready key
        */
        byte[] expandKey(byte[] key, bool isEncryptionKey)
        {
            List<byte> roundKey = new List<byte>(key); // The first round key is the key itself.

            // All other round keys are found from the previous round keys.
            int i = m_nk;
            while (i < m_nb * (m_nr + 1))
            {
                byte[] tempa = new byte[4];
                tempa[0] = roundKey[(i - 1) * 4 + 0];
                tempa[1] = roundKey[(i - 1) * 4 + 1];
                tempa[2] = roundKey[(i - 1) * 4 + 2];
                tempa[3] = roundKey[(i - 1) * 4 + 3];

                if (i % m_nk == 0)
                {
                    // RotWord
                    byte k = tempa[0];
                    tempa[0] = tempa[1];
                    tempa[1] = tempa[2];
                    tempa[2] = tempa[3];
                    tempa[3] = k;

                    // Subword
                    tempa[0] = getSBoxValue(tempa[0]);
                    tempa[1] = getSBoxValue(tempa[1]);
                    tempa[2] = getSBoxValue(tempa[2]);
                    tempa[3] = getSBoxValue(tempa[3]);

                    tempa[0] ^= Rcon[i / m_nk];
                }

                if (m_level == Aes.AES_256 && i % m_nk == 4)
                {
                    // Subword
                    tempa[0] = getSBoxValue(tempa[0]);
                    tempa[1] = getSBoxValue(tempa[1]);
                    tempa[2] = getSBoxValue(tempa[2]);
                    tempa[3] = getSBoxValue(tempa[3]);
                }

                roundKey.Add((byte)(roundKey[(i - m_nk) * 4 + 0] ^ tempa[0]));
                roundKey.Add((byte)(roundKey[(i - m_nk) * 4 + 1] ^ tempa[1]));
                roundKey.Add((byte)(roundKey[(i - m_nk) * 4 + 2] ^ tempa[2]));
                roundKey.Add((byte)(roundKey[(i - m_nk) * 4 + 3] ^ tempa[3]));

                i++;
            }

            return roundKey.ToArray();
        }
        /*!
       * \brief object method call to remove padding from decrypted cipher given by rawText
       * \param rawText:  inputText
       * \return decrypted cipher with padding removed
       */
       public byte[] removePadding(byte[] rawText)
        {
            return RemovePadding(rawText, (Padding)m_padding);
        }

        byte[] printArray(byte[] arr, int size)
        {
            StringBuilder hex = new StringBuilder(arr.Length * 2);
            foreach (byte b in arr)
            {
                hex.AppendFormat("{0:x2}", b);
            }
            
            return Encoding.ASCII.GetBytes(hex.ToString());
        }

        byte getSBoxValue(byte num)
        { return sbox[num]; }
        byte getSBoxInvert(byte num)
        { return rsbox[num]; }

        void addRoundKey( byte round,byte[] expKey)
            {
            for (int i = 0; i < 16; ++i)
            {
                m_state[i] ^= expKey[round * m_nb * 4 + (i / 4) * m_nb + (i % 4)];
            }
        }
        // The SubBytes Function Substitutes the values in the
        // state matrix with values in an S-box.
        void subBytes()
        {
            for (int i = 0; i < 16; i++)
            {
                m_state[i] = getSBoxValue(m_state[i]);
            }
        }
        // The ShiftRows() function shifts the rows in the state to the left.
        // Each row is shifted with different offset.
        // Offset = Row number. So the first row is not shifted.
        void shiftRows()
        {
            byte temp;

            // Keep in mind that the state array is column-driven!!

            // Shift 1 to left
            temp = m_state[1];
            m_state[1] = m_state[5];
            m_state[5] = m_state[9];
            m_state[9] = m_state[13];
            m_state[13] = temp;

            // Shift 2 to left
            temp = m_state[2];
            m_state[2] = m_state[10];
            m_state[10] = temp;
            temp = m_state[6];
            m_state[6] = m_state[14];
            m_state[14] = temp;

            // Shift 3 to left
            temp = m_state[3];
            m_state[3] = m_state[15];
            m_state[15] = m_state[11];
            m_state[11] = m_state[7];
            m_state[7] = temp;
        }
        // MixColumns function mixes the columns of the state matrix
        //optimized!!
        void mixColumns()
        {
            byte tmp, tm, t;

            for (int i = 0; i < 16; i += 4)
            {
                t = m_state[i];
                tmp = (byte)(m_state[i] ^ m_state[i + 1] ^ m_state[i + 2] ^ m_state[i + 3]);

                tm = XTime((byte)(m_state[i] ^ m_state[i + 1]));
                m_state[i] ^= (byte)(tm ^ tmp);

                tm = XTime((byte)(m_state[i + 1] ^ m_state[i + 2]));
                m_state[i + 1] ^= (byte)(tm ^ tmp);

                tm = XTime((byte)(m_state[i + 2] ^ m_state[i + 3]));
                m_state[i + 2] ^= (byte)(tm ^ tmp);

                tm = XTime((byte)(m_state[i + 3] ^ t));
                m_state[i + 3] ^= (byte)(tm ^ tmp);
            }
        }


        // MixColumns function mixes the columns of the state matrix.
        // The method used to multiply may be difficult to understand for the inexperienced.
        // Please use the references to gain more information.
        void invMixColumns()
        {
            byte a, b, c, d;

            for (int i = 0; i < 16; i += 4)
            {
                a = m_state[i];
                b = m_state[i + 1];
                c = m_state[i + 2];
                d = m_state[i + 3];

                m_state[i] = (byte)(Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09));
                m_state[i + 1] = (byte)(Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d));
                m_state[i + 2] = (byte)(Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b));
                m_state[i + 3] = (byte)(Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e));
            }
        }

        // The SubBytes Function Substitutes the values in the
        // state matrix with values in an S-box.
        void invSubBytes()
        {
            for (int i = 0; i < 16; ++i)
            {
                m_state[i] = getSBoxInvert(m_state[i]);
            }
        }
        void invShiftRows()
        {
            byte temp;

            // Shift 1 to right
            temp = m_state[13];
            m_state[13] = m_state[9];
            m_state[9] = m_state[5];
            m_state[5] = m_state[1];
            m_state[1] = temp;

            // Shift 2
            temp = m_state[10];
            m_state[10] = m_state[2];
            m_state[2] = temp;
            temp = m_state[14];
            m_state[14] = m_state[6];
            m_state[6] = temp;

            // Shift 3
            temp = m_state[7];
            m_state[7] = m_state[11];
            m_state[11] = m_state[15];
            m_state[15] = m_state[3];
            m_state[3] = temp;
        }
        byte[] getPadding(int currSize, int alignment)
        {
            int size = (alignment - currSize % alignment) % alignment;
            switch (m_padding)
            {
                case Padding.ZERO:
                    return new byte[size];
                case Padding.PKCS7:
                    if (size == 0)
                        size = alignment;
                    var pkcs7Padding = new byte[size];
                    for (int i = 0; i < size; i++)
                    {
                        pkcs7Padding[i] = (byte)size;
                    }
                    return pkcs7Padding;
                case Padding.ISO:
                    if (size > 0)
                    {
                        var isoPadding = new List<byte>(new byte[size - 1]);
                        isoPadding.Insert(0, 0x80);
                        return isoPadding.ToArray();
                    }
                    break;
                default:
                    return new byte[size];
            }
            return new byte[0];
        }

        byte[] cipher(byte[] expKey, byte[] input) {
            // m_state is the input buffer...
            byte[] output = new byte[input.Length];
            Array.Copy(input, output, input.Length);
            m_state = output;

            // Add the First round key to the state before starting the rounds.
            addRoundKey(0, expKey);

            // There will be Nr rounds.
            // The first Nr-1 rounds are identical.
            // These Nr-1 rounds are executed in the loop below.
            for (byte round = 1; round < m_nr; ++round)
            {
                subBytes();
                shiftRows();
                mixColumns();
                addRoundKey(round, expKey);
            }

            // The last round is given below.
            // The MixColumns function is not here in the last round.
            subBytes();
            shiftRows();
            addRoundKey((byte)m_nr, expKey);

            return output; byte[] data = new byte[16];
            return data;
        }

        byte[] invCipher(byte[] expKey,byte[] input){
            // m_state is the input buffer...
            byte[] output = new byte[input.Length];
            Array.Copy(input, output, input.Length);
            m_state = output;

            // Add the First round key to the state before starting the rounds.
            addRoundKey((byte)m_nr, expKey);

            // There will be Nr rounds.
            // The first Nr-1 rounds are identical.
            // These Nr-1 rounds are executed in the loop below.
            for (byte round = (byte)(((byte)m_nr) - 1); round > 0; round--)
            {
                invShiftRows();
                invSubBytes();
                addRoundKey(round, expKey);
                invMixColumns();
            }

            // The last round is given below.
            // The MixColumns function is not here in the last round.
            invShiftRows();
            invSubBytes();
            addRoundKey(0, expKey);

            return output;
        }

        // The byteXor function performs a bitwise XOR operation on two byte arrays
        byte[] byteXor(byte[] a, byte[] b){
            int minLength = Math.Min(a.Length, b.Length);
            byte[] result = new byte[minLength];

            for (int i = 0; i < minLength; i++)
            {
                result[i] = (byte)(a[i] ^ b[i]);
            }

            return result;
        }
    }


}
