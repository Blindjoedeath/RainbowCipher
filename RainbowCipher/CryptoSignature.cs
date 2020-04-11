using System;
using System.Numerics;

namespace RainbowCipher
{
    public struct Signature
    {
        public byte[] h;
        public byte[] r;
        public byte[] s;
        public byte[] y;
    }

    public class CryptoSignature
    {
        private BigInteger _p = BigInteger.Parse("255211775190703847597530955573826158579");
        private BigInteger _q = BigInteger.Parse("252991020016994668398330411224101");
        private IHashGenerator _hashGenerator;

        public CryptoSignature(IHashGenerator hashGenerator)
        {
            _hashGenerator = hashGenerator;
        }

        private BigInteger g
        {
            get
            {
                return BigInteger.ModPow(666, (_p - 1) / _q, _p);
            }
        }

        private BigInteger GenerateBigInteger(BigInteger min, BigInteger max)
        {
            var random = new RandomBigInteger();
            return random.NextBigInteger(min, max);
        }

        public Signature CreateSignature(byte[] data)
        {
            var h = new BigInteger(_hashGenerator.Hash(data));

            // Actually hash already has to be positive number, but for now,
            // we don't care about hash integrity
            if (h.Sign == -1)
            {
                h *= -1;
            }

            var k = GenerateBigInteger(2, _q - 1);
            var x = GenerateBigInteger(2, _q - 1);  
            var y = BigInteger.ModPow(g, x, _p);
            var r = BigInteger.ModPow(g, k, _p);
            var po = BigInteger.ModPow(r, 1, _q);
            var s = po * k - BigInteger.ModPow(h * x, 1, _q);

            return new Signature()
            {
                h = h.ToByteArray(),
                r = r.ToByteArray(),
                s = s.ToByteArray(),
                y = y.ToByteArray()
            };
        }


        public bool IsCorrect(Signature signature)
        {
            var r = new BigInteger(signature.r);
            var h = new BigInteger(signature.h);
            var s = new BigInteger(signature.s);
            var y = new BigInteger(signature.y);
            var po = BigInteger.ModPow(r, 1, _q);
            var left = BigInteger.ModPow(r, po, _p);
            var right = BigInteger.ModPow(BigInteger.ModPow(g, s, _p) * BigInteger.ModPow(y, h, _p), 1, _p);
            return left == right;
        }
    }
}
