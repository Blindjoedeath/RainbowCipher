using System;
namespace RainbowCipher
{
    public class HashGenerator
    {
        private const int _blockLength = 16;
        private ICipher _cipher;
        private BlockSplitter _splitter = new BlockSplitter(_blockLength);
        private byte[] _h0;

        private void CreateH0()
        {
            _h0 = new byte[_blockLength];

            var random = new Random();
            random.NextBytes(_h0);
        }

        public HashGenerator(ICipher cipher)
        {
            CreateH0();
            _cipher = cipher;
        }

        public byte[] Hash(byte[] data)
        {
            var blocks = _splitter.SplitOnBlocks(data);
            var h = _h0;
            foreach(var m in blocks)
            {
                var a = h;
                var b = m.Xor(h);
                var c = m.Xor(h);

                _cipher.Key = a;
                h = _cipher.Encrypt(b).Xor(c);
            }
            return h;
        }
    }
}
