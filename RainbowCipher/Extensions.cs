using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace RainbowCipher
{
    public static class Extensions
    {
        public static IEnumerable<IEnumerable<T>> Chunk<T>(this IEnumerable<T> list, int chunkSize)
        {
            if (chunkSize <= 0)
            {
                throw new ArgumentException("chunkSize must be greater than 0.");
            }

            while (list.Any())
            {
                yield return list.Take(chunkSize);
                list = list.Skip(chunkSize);
            }
        }

        public static byte[] Xor(this byte[] a, byte[] b)
        {
            var bitA = new BitArray(a);
            var bitB = new BitArray(b);
            var xor = bitA.Xor(bitB);
            var result = new byte[a.Length];
            xor.CopyTo(result, 0);
            return result;
        }
    }
}
