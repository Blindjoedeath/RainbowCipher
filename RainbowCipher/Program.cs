using System;
using System.Linq;
using System.Collections.Generic;
using System.Collections;
using System.Text;

namespace RainbowCipher
{
    class Program
    {
        static void Main(string[] args)
        {
            bool isCorrect;
            int count = 0;
            do
            {
                var cipher = new Rainbow();
                var hasher = new HashGenerator(cipher);
                var signature = new CryptoSignature(hasher);

                var random = new Random();
                var messageLength = random.Next() % 100 + 50;
                var message = new byte[messageLength];
                random.NextBytes(message);

                var sign = signature.CreateSignature(message);
                isCorrect = signature.IsCorrect(sign);
                Console.WriteLine($"Success {++count}");
            } while (isCorrect);
        }
    }
}