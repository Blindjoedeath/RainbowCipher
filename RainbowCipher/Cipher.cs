using System;
using System.Linq;
using System.Collections.Generic;

namespace RainbowCipher
{
    public interface ICryptor
    {
        byte[] Encrypt(byte[] block);
        byte[] Decrypt(byte[] block);
        byte[] Key { get; set; }
    }

    public class Rainbow : ICryptor
    {
        int _rounds;
        ImmutableBitArray[][] _decryptionKeys;
        ImmutableBitArray[][] _encryptionKeys;

        private byte[] _key;
        public byte[] Key
        {
            get => _key;
            set
            {
                _key = value;
                var blockKey = RainbowBlock.FromBytes(_key).value;
                CreateRoundKeys(blockKey);
            }
        }

        public Rainbow(int rounds = 7)
        {
            _rounds = rounds;
        }

        private void CreateRoundKeys(ImmutableBitArray[] key)
        {
            _encryptionKeys = new ImmutableBitArray[2 * (_rounds + 1)][];
            _decryptionKeys = new ImmutableBitArray[2 * (_rounds + 1)][];
            _encryptionKeys[0] = key;

            var i = 1;
            var constant1 = new ImmutableBitArray(0xb7e15163);
            var constant2 = new ImmutableBitArray(0xffffffff);
            while (i < 2 * (_rounds + 1))
            {
                _encryptionKeys[i] = _encryptionKeys[i - 1].Clone() as ImmutableBitArray[];

                var shifts = new int[4] { 3, 5, 7, 11 };
                for (var q = 0; q < 4; ++q)
                {
                    _encryptionKeys[i][q] =
                        _encryptionKeys[i][0].RightShift(shifts[q % 4])
                        .Xor(_encryptionKeys[i][1].RightShift(shifts[(1 + q) % 4]))
                        .Xor(_encryptionKeys[i][2].RightShift(shifts[(2 + q) % 4]))
                        .Xor(_encryptionKeys[i][3].RightShift(shifts[(3 + q) % 4]))
                        .Xor(constant1);
                }
                ++i;
            }
            var j = 0;
            while (j < _rounds + 1)
            {
                i = 2 * j + 1;
                _encryptionKeys[i][0] = _encryptionKeys[i][1].Xor(_encryptionKeys[i][2]).Xor(_encryptionKeys[i][3]).Xor(constant2);
                _decryptionKeys[2 * (_rounds + 1) - i] = _encryptionKeys[i];
                ++j;
            }
            j = 0;
            while (j < _rounds + 1)
            {
                i = 2 * j;
                var i1 = 2 * (_rounds - j);
                var i2 = i1 + 1;

                _decryptionKeys[i] = new ImmutableBitArray[4];

                var shifts = new List<int>() { 0, 1, 2, 3 };
                for (int q = 0; q < 4; ++q)
                {
                    _decryptionKeys[i][q] =
                        _encryptionKeys[i1][0].And(_encryptionKeys[i2][shifts[q % 4]])
                        .Xor(_encryptionKeys[i1][1].And(_encryptionKeys[i2][shifts[(1 + q) % 4]]))
                        .Xor(_encryptionKeys[i1][2].And(_encryptionKeys[i2][shifts[(2 + q) % 4]]))
                        .Xor(_encryptionKeys[i1][3].And(_encryptionKeys[i2][shifts[(3 + q) % 4]]));
                }
                ++j;
            }

        }

        private byte[] Crypt(byte[] data, ImmutableBitArray[][] keys)
        {
            var block = RainbowBlock.FromBytes(data);
            for (int i = 0; i < _rounds + 1; ++i)
            {
                var key1 = new RainbowBlock(keys[2 * i]);
                var key2 = new RainbowBlock(keys[2 * i + 1]);
                block = block.G(key1).B(key2);
                if (i != _rounds)
                {
                    block = block.R();
                }
            }
            return block.ToBytes();
        }

        public byte[] Encrypt(byte[] data)
        {
            return Crypt(data, _encryptionKeys);
        }

        public byte[] Decrypt(byte[] data)
        {
            return Crypt(data, _decryptionKeys);
        }
    }


    class RainbowBlock
    {

        private static readonly byte[] f = new byte[256]
        {
                0x00, 0x0e, 0x1c, 0x08, 0x38, 0xe5, 0x10, 0x19,
                0x70, 0x16, 0xcb, 0x42, 0x20, 0xe7, 0x32, 0xd4,
                0xe0, 0xcc, 0x2c, 0x65, 0x97, 0xa7, 0x84, 0x1f,
                0x40, 0x67, 0xcf, 0x78, 0x64, 0x2d, 0xa9, 0xbe,
                0xc1, 0xc2, 0x99, 0xec, 0x58, 0xd1, 0xca, 0xfb,
                0x2f, 0x8e, 0x4f, 0x6d, 0x09, 0x50, 0x3e, 0x2a,
                0x80, 0x56, 0xce, 0x11, 0x9f, 0x0c, 0xf0, 0xa4,
                0xc8, 0xdf, 0x5a, 0xb1, 0x53, 0x73, 0x7d, 0x6f,
                0x83, 0x79, 0x85, 0xf9, 0x33, 0xe9, 0xd9, 0x4b,
                0xb0, 0x74, 0xa3, 0x14, 0x95, 0x03, 0xf7, 0xdc,
                0x5e, 0x7a, 0x1d, 0xc0, 0x9e, 0x55, 0xda, 0x26,
                0x12, 0x6b, 0xa0, 0xd5, 0x7c, 0x98, 0x54, 0x72,
                0x01, 0x48, 0xac, 0x0f, 0x9d, 0xad, 0x22, 0x36,
                0x3f, 0x82, 0x18, 0xba, 0xe1, 0x57, 0x49, 0x2e,
                0x91, 0xf1, 0xbf, 0x4a, 0xb4, 0x62, 0x63, 0xee,
                0xa6, 0x51, 0xe6, 0x71, 0xfa, 0xc9, 0xde, 0x43,
                0x07, 0x04, 0xf2, 0x8c, 0x0b, 0x21, 0xf3, 0x6a,
                0x66, 0xb2, 0xd3, 0x8f, 0xb3, 0x3c, 0x96, 0x5f,
                0x61, 0x76, 0xe8, 0xfd, 0x47, 0xb6, 0x28, 0x15,
                0x2b, 0x88, 0x06, 0x52, 0xef, 0xd8, 0xb9, 0xb7,
                0xbc, 0xfc, 0xf4, 0xa5, 0x3a, 0x0a, 0x81, 0x6e,
                0x3d, 0x60, 0xaa, 0x13, 0xb5, 0xea, 0x4c, 0x39,
                0x24, 0x87, 0xd6, 0x1b, 0x41, 0x5d, 0xab, 0x17,
                0xf8, 0x25, 0x31, 0x77, 0xa8, 0xb8, 0xe4, 0xa1,
                0x02, 0x46, 0x90, 0x35, 0x59, 0xc7, 0x1e, 0xaf,
                0x3b, 0xfe, 0x5b, 0x8a, 0x44, 0x29, 0x6c, 0xdb,
                0x7e, 0xd2, 0x05, 0x37, 0x30, 0x89, 0x75, 0x9c,
                0xc3, 0x8d, 0xae, 0x8b, 0x92, 0xbb, 0x5c, 0xd0,
                0x23, 0x9a, 0xe3, 0xd7, 0x7f, 0x45, 0x94, 0xed,
                0x69, 0x9b, 0xc4, 0x4e, 0xc6, 0xc5, 0xdd, 0x68,
                0x4d, 0xeb, 0xa2, 0xf6, 0xcd, 0x27, 0xe2, 0x34,
                0xf5, 0x7b, 0x93, 0x1a, 0xbd, 0x0d, 0x86, 0xff
        };

        private static readonly byte[] f_1 = new byte[]
        {
                0x00, 0x60, 0xc0, 0x4d, 0x81, 0xd2, 0x9a, 0x80,
                0x03, 0x2c, 0xa5, 0x84, 0x35, 0xfd, 0x01, 0x63,
                0x06, 0x33, 0x58, 0xab, 0x4b, 0x97, 0x09, 0xb7,
                0x6a, 0x07, 0xfb, 0xb3, 0x02, 0x52, 0xc6, 0x17,
                0x0c, 0x85, 0x66, 0xe0, 0xb0, 0xb9, 0x57, 0xf5,
                0x96, 0xcd, 0x2f, 0x98, 0x12, 0x1d, 0x6f, 0x28,
                0xd4, 0xba, 0x0e, 0x44, 0xf7, 0xc3, 0x67, 0xd3,
                0x04, 0xaf, 0xa4, 0xc8, 0x8d, 0xa8, 0x2e, 0x68,
                0x18, 0xb4, 0x0b, 0x7f, 0xcc, 0xe5, 0xc1, 0x94,
                0x61, 0x6e, 0x73, 0x47, 0xae, 0xf0, 0xeb, 0x2a,
                0x2d, 0x79, 0x9b, 0x3c, 0x5e, 0x55, 0x31, 0x6d,
                0x24, 0xc4, 0x3a, 0xca, 0xde, 0xb5, 0x50, 0x8f,
                0xa9, 0x90, 0x75, 0x76, 0x1c, 0x13, 0x88, 0x19,
                0xef, 0xe8, 0x87, 0x59, 0xce, 0x2b, 0xa7, 0x3f,
                0x08, 0x7b, 0x5f, 0x3d, 0x49, 0xd6, 0x91, 0xbb,
                0x1b, 0x41, 0x51, 0xf9, 0x5c, 0x3e, 0xd0, 0xe4,
                0x30, 0xa6, 0x69, 0x40, 0x16, 0x42, 0xfe, 0xb1,
                0x99, 0xd5, 0xcb, 0xdb, 0x83, 0xd9, 0x29, 0x8b,
                0xc2, 0x70, 0xdc, 0xfa, 0xe6, 0x4c, 0x8e, 0x14,
                0x5d, 0x22, 0xe1, 0xe9, 0xd7, 0x64, 0x54, 0x34,
                0x5a, 0xbf, 0xf2, 0x4a, 0x37, 0xa3, 0x78, 0x15,
                0xbc, 0x1e, 0xaa, 0xb6, 0x62, 0x65, 0xda, 0xc7,
                0x48, 0x3b, 0x89, 0x8c, 0x74, 0xac, 0x95, 0x9f,
                0xbd, 0x9e, 0x6b, 0xdd, 0xa0, 0xfc, 0x1f, 0x72,
                0x53, 0x20, 0x21, 0xd8, 0xea, 0xed, 0xec, 0xc5,
                0x38, 0x7d, 0x26, 0x0a, 0x11, 0xf4, 0x32, 0x1a,
                0xdf, 0x25, 0xd1, 0x8a, 0x0f, 0x5b, 0xb2, 0xe3,
                0x9d, 0x46, 0x56, 0xcf, 0x4f, 0xee, 0x7e, 0x39,
                0x10, 0x6c, 0xf6, 0xe2, 0xbe, 0x05, 0x7a, 0x0d,
                0x92, 0x45, 0xad, 0xf1, 0x23, 0xe7, 0x77, 0x9c,
                0x36, 0x71, 0x82, 0x86, 0xa2, 0xf8, 0xf3, 0x4e,
                0xb8, 0x43, 0x7c, 0x27, 0xa1, 0x93, 0xc9, 0xff
        };


        public ImmutableBitArray[] value { get; private set; }

        public RainbowBlock(ImmutableBitArray[] bitArrays)
        {
            value = bitArrays;
        }

        public static RainbowBlock FromBytes(byte[] bytes)
        {
            int length = bytes.Length / 4;
            var arrays = bytes.Chunk(length).Select((chunk) => new ImmutableBitArray(chunk.ToArray())).ToArray();
            var block = new RainbowBlock(arrays);
            return block;
        }


        public RainbowBlock G(RainbowBlock key)
        {
            var result = new ImmutableBitArray[4];
            for (int i = 0; i < 4; ++i)
            {
                result[i] = value[i].Xor(key.value[i]);
            }
            return new RainbowBlock(result);
        }

        public RainbowBlock B(RainbowBlock key)
        {
            var result = new ImmutableBitArray[4];
            for (int i = 0; i < 4; ++i)
            {
                result[i] =
                    value[0].And(key.value[i % 4])
                    .Xor(value[1].And(key.value[(1 + i) % 4]))
                    .Xor(value[2].And(key.value[(2 + i) % 4]))
                    .Xor(value[3].And(key.value[(3 + i) % 4]));
            }
            return new RainbowBlock(result);
        }

        private ImmutableBitArray P1(ImmutableBitArray bits)
        {
            var x = new byte[4];
            bits.value.CopyTo(x, 0);
            var converted = new byte[4] { f[x[1]], f_1[x[0]], f[x[3]], f_1[x[2]] };
            return new ImmutableBitArray(converted);
        }

        private ImmutableBitArray P2(ImmutableBitArray bits)
        {
            var x = new byte[4];
            bits.value.CopyTo(x, 0);
            var converted = new byte[4] { f[x[2]], f[x[3]], f_1[x[0]], f_1[x[1]] };
            return new ImmutableBitArray(converted);
        }

        private ImmutableBitArray P3(ImmutableBitArray bits)
        {
            var x = new byte[4];
            bits.value.CopyTo(x, 0);
            var converted = new byte[4] { f[x[3]], f[x[2]], f_1[x[1]], f_1[x[0]] };
            return new ImmutableBitArray(converted);
        }

        public RainbowBlock R()
        {
            var result = new ImmutableBitArray[4]
            {
                P2(value[0]), P3(value[1]), P2(value[2]), P1(value[3])
            };
            return new RainbowBlock(result);
        }

        public byte[] ToBytes()
        {
            var result = new byte[16];
            for (int i = 0; i < value.Length; ++i)
            {
                var bytes = new byte[4];
                value[i].value.CopyTo(bytes, 0);
                bytes.CopyTo(result, i * bytes.Length);
            }
            return result;
        }

    }

}
