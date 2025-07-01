using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FEW_Engine
{
    internal class CompilerHelper
    {
        //This function will return the position of the string in the string list, or -1 if it does not exist.
        public static int GetPositionStringList(List<String> strings, string NewString)
        {
            return strings.IndexOf(NewString);
        }

        //This function will basically encode the parameters given in the argument. In this case it basically works in the
        //opposite way of the GetParameters function in the DecrypterHelper class.
        public static List<byte> EncodeParameters(string argument)
        {
            var bytes = new List<byte>();

            if (argument.StartsWith("g"))
            {
                bytes.Add(0x3F);
                short value = short.Parse(argument.Substring(1));
                bytes.AddRange(BitConverter.GetBytes(value));
            }
            else if (argument.StartsWith("f"))
            {
                bytes.Add(0x3E);
                short value = short.Parse(argument.Substring(1));
                bytes.AddRange(BitConverter.GetBytes(value));
            }
            else
            {
                bytes.Add(0x41);
                int value = int.Parse(argument);
                bytes.AddRange(BitConverter.GetBytes(value));
            }

            return bytes;
        }

    }
}
