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

            var message = "Hello world!!!!!!:))))";
            var messageData = Encoding.UTF8.GetBytes(message);
            var resultData = hashGenerator.Hash(messageData);

            
            var result = Encoding.UTF8.GetString(resultData);
            Console.WriteLine(result);
        }
    }
}