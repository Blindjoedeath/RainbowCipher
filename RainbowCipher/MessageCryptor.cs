using System;

namespace RainbowCipher
{
    public class MessageCryptor
    {
        private const int _blockLength = 16;
        private ICipher _cipher;
        private byte[] _IV;
        private BlockSplitter _splitter = new BlockSplitter(_blockLength);

        private void CreateInitializationVector()
        {
            _IV = new byte[_blockLength];

            var random = new Random();
            random.NextBytes(_IV);
        }

        public MessageCryptor(ICipher cipher)
        {
            _cipher = cipher;
            CreateInitializationVector();
        }

        private byte[] CFBEncryption(byte[][] blocks)
        {
            var c = _IV;
            var result = new byte[blocks.Length * _blockLength];
            for (int i = 0; i < blocks.Length; ++i)
            {
                var encrypted = _cipher.Encrypt(c);
                c = encrypted.Xor(blocks[i]);
                c.CopyTo(result, _blockLength * i);
            }
            return result;
        }

        private byte[] CFBDecryption(byte[][] blocks)
        {
            var result = new byte[blocks.Length * _blockLength];
            for (int i = 0; i < blocks.Length; ++i)
            {
                var encrypted = _cipher.Encrypt(i == 0 ? _IV : blocks[i - 1]);
                var block = encrypted.Xor(blocks[i]);
                block.CopyTo(result, _blockLength * i);
            }
            return result;
        }

        public byte[] Encrypt(byte[] data)
        {
            var blocks = _splitter.SplitOnBlocks(data);
            return CFBEncryption(blocks);
        }

        public byte[] Decrypt(byte[] data)
        {
            var blocks = _splitter.SplitOnBlocks(data, false);
            var decrypted = CFBDecryption(blocks);
            var pure = _splitter.RemoveEndBlock(decrypted);
            return pure;
        }
    }
}
