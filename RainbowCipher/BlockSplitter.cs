using System;
using System.Linq;

namespace RainbowCipher
{
    public class BlockSplitter
    {
        private int _blockLength;

        public BlockSplitter(int blockLength)
        {
            _blockLength = blockLength;
        }

        private byte[] EndBlock
        {
            get
            {
                var result = new byte[_blockLength];
                result[0] = 80;
                return result;
            }
        }

        private byte[] AddEndToPartial(byte[] partial)
        {
            var append = EndBlock.Take(_blockLength - partial.Length).ToArray();
            var result = new byte[_blockLength];
            partial.CopyTo(result, 0);
            append.CopyTo(result, partial.Length);
            return result;
        }

        public byte[] RemoveEndBlock(byte[] data)
        {
            var length = data.Length;
            for (int i = data.Length - 1; i >= 0; --i)
            {
                if (data[i] == 80)
                {
                    length = i;
                    break;
                }
            }
            return data.Take(length).ToArray();
        }

        public byte[][] SplitOnBlocks(byte[] data, bool withEndBlock = true)
        {
            var blocks = (from t in data.Chunk(_blockLength) select t.ToArray()).ToList();

            if (!withEndBlock)
            {
                return blocks.ToArray();
            }

            var last = blocks.Last();
            if (last.Length == _blockLength)
            {
                blocks.Add(EndBlock);
            }
            else
            {
                var filled = AddEndToPartial(last);
                blocks.Remove(last);
                blocks.Insert(blocks.Count, filled);
            }
            return blocks.ToArray();
        }
    }
}
