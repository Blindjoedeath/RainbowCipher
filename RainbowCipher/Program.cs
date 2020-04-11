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
            var hash = new HashGenerator(cipher);
            var key = "1234567812345678";
            var keyData = Encoding.UTF8.GetBytes(key);

            var message = "asdfmlasjf;weihfpaioifja;ufsgh'osieh";
            var data = Encoding.UTF8.GetBytes(message);
            var withKey = hash.Hash(data, keyData);
            var withoutKey = hash.Hash(data);

            Console.WriteLine(Encoding.UTF8.GetString(withKey));
            Console.WriteLine(Encoding.UTF8.GetString(withoutKey));
        }
    }
}