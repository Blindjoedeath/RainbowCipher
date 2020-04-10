using System;
using System.Collections;

namespace RainbowCipher
{
    public class ImmutableBitArray
    {
        public BitArray value { get; private set; }

        public ImmutableBitArray(BitArray array)
        {
            value = array;
        }

        public ImmutableBitArray(byte[] bytes)
        {
            value = new BitArray(bytes);
        }

        public ImmutableBitArray(uint number)
        {
            var bytes = BitConverter.GetBytes(number);
            value = new BitArray(bytes);
        }

        public ImmutableBitArray Xor(ImmutableBitArray array)
        {
            var clone = value.Clone() as BitArray;
            var bitArray = clone.Xor(array.value);
            return new ImmutableBitArray(bitArray);
        }

        public ImmutableBitArray And(ImmutableBitArray array)
        {
            var clone = value.Clone() as BitArray;
            var bitArray = clone.And(array.value);
            return new ImmutableBitArray(bitArray);
        }

        public ImmutableBitArray RightShift(int count)
        {
            var clone = value.Clone() as BitArray;
            var bitArray = clone.RightShift(count);
            return new ImmutableBitArray(bitArray);
        }

        public ImmutableBitArray LeftShift(int count)
        {
            var clone = value.Clone() as BitArray;
            var bitArray = clone.LeftShift(count);
            return new ImmutableBitArray(bitArray);
        }
    }
}
