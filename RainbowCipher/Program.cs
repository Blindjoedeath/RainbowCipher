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
            var cipher = new Rainbow();
            var hashGenerator = new HashGenerator(cipher);
            var signature = new CryptoSignature(hashGenerator);

            var message = Encoding.UTF8.GetBytes("test");
            var sign = signature.CreateSignature(message);
            Console.WriteLine(signature.IsCorrect(sign));

        }
    }
}