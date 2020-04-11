using System;
using System.Text;
namespace RainbowCipher
{

    public interface IHashGenerator
    {
        public byte[] Hash(byte[] data, byte[] key = null);
    }

    public class HashGenerator: IHashGenerator
    {
        private const int _blockLength = 16;
        private ICryptor _cryptor;
        private BlockSplitter _splitter = new BlockSplitter(_blockLength);
        private byte[] _h0;

        private void CreateH0()
        {
            _h0 = Encoding.UTF8.GetBytes("1234567812345678");
        }

        public HashGenerator(ICryptor cryptor)
        {
            CreateH0();
            _cryptor = cryptor;
        }

        private byte[] HashWithoutKey(byte[] data)
        {
            var blocks = _splitter.SplitOnBlocks(data);
            var h = _h0;
            foreach (var m in blocks)
            {
                var a = h;
                var b = m.Xor(h);
                var c = m.Xor(h);

                _cryptor.Key = a;
                h = _cryptor.Encrypt(b).Xor(c);
            }
            return h;
        }

        private byte[] HashWithKey(byte[] data, byte[] key)
        {
            var blocks = _splitter.SplitOnBlocks(data);
            var h = key;
            foreach (var m in blocks)
            {
                _cryptor.Key = h;
                h = _cryptor.Encrypt(m);
            }
            return h;
        }

        public byte[] Hash(byte[] data, byte[] key = null)
        {
            if (key == null)
            {
                return HashWithoutKey(data);
            }
            return HashWithKey(data, key);
        }
    }
}
