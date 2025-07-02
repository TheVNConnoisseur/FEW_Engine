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

        //This function will return yes or no depending on if the label exists already or not
        public static bool ExistsLabel(List<Label> labels, string labelName)
        {
            foreach (var label in labels)
            {
                if (label.Name == labelName)
                    return true;
            }
            return false;
        }

        //This function will return the label with the asked name alongside its information
        public static Label GetLabel(List<Label> labels, string labelName)
        {
            foreach (var label in labels)
            {
                if (label.Name == labelName)
                    return label;
            }

            throw new Exception("Label " + labelName + " not found");
        }

        //This function is used to encode certain flags that are arguments in certain flags. While they don't seem to be pretty much different
        //in theory from the rest, apparently they need to be encoded in a different way. Sadly, the analyzed game doesn't use any instruction
        //that goes through this function, so it is not known how it works in practice. When we get a result of 0x45 in the end, we also need
        //to write the entire argument to the string list, but that is done outside of this function.
        public static byte[] EncodeStringParameters(string argument, int onlyStringFlagsAllowed)
        {
            var bytes = new List<byte>();

            if (argument[0] == 's')
            {
                if (onlyStringFlagsAllowed != 1)
                {
                    bytes.Add(0x44);
                }
                bytes.AddRange(BitConverter.GetBytes(short.Parse(argument.Substring(1))));
            }
            else if (onlyStringFlagsAllowed == 1)
            {
                bytes.Add(0x45);
            }
            return bytes.ToArray();
        }
    }
}
