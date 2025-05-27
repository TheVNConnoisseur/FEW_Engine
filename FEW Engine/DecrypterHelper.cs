using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FEW_Engine
{
    internal class DecrypterHelper
    {

        //Function that obtains the parameter given a data array
        //This function it is expected to be called given the proper context,
        //since it will look at the data array given as a parameter independently
        //of where it came from.
        //Important to always to ensure that the parameter given is at least 5 bytes
        //long, so it can parse all of the bytes needed for each case.
        //It will return a string array of 2 values, first it will be the actual
        //parameter to parse, and second value will be the amount of bytes
        //that have been parsed, so that we do not skip any unprocessed byte
        public string[] GetParameters(byte[] Data)
        {
            string[] Parameters = new string[2];
            switch (Data[0])
            {
                case 0x3F:
                    {
                        Parameters[0] = "g" + Convert.ToString
                            (BitConverter.ToInt16(Data, 1));
                        Parameters[1] = "3";
                        break;
                    }
                case 0x3E:
                    {
                        Parameters[0] = "f" + Convert.ToString
                            (BitConverter.ToInt16(Data, 1));
                        Parameters[1] = "3";
                        break;
                    }
                case 0x41:
                    {
                        Parameters[0] = Convert.ToString
                            (BitConverter.ToInt32(Data, 1));
                        Parameters[1] = "5";
                        break;
                    }
            }
            return Parameters;
        }
    }
}
