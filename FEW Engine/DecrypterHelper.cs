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

        //Function that obtains the parameters given a data array.
        //This function is also expected to be called given the proper context,
        //so the conditions must be before calling to ensure that there are no
        //issues.
        //In this case, there are two types of modes possible: strict mode and
        //non-strict mode. In strict mode, if the parameter does NOT start with an
        //"s" (lowercase or uppercase), it will not be accepted. In non-strict mode,
        //it will be accepted but treated differently.
        //Important to always to ensure that the parameter given is at least 5 bytes
        //long, so it can parse all of the bytes needed for each case.
        public string[] GetStringParameters(byte[] Data, int StrictMode)
        {
            string[] Parameters = new string[2];
            if (StrictMode == 0)
            {
                if (Data[0] == 0x44)
                {
                    Parameters[0] = "s" + Convert.ToString(BitConverter.ToInt16(Data, 1)); //We pass the flag as a string
                    Parameters[1] = "3";
                }
                else if (Data[0] == 0x45)
                {
                    Parameters[0] = Convert.ToString(BitConverter.ToInt32(Data, 1)); //We pass the number of the string list index
                    Parameters[1] = "5";
                }
            }
            else if (StrictMode == 1)
            {
                //Only when the flag starts with an "s" there is the possibility of having an array of
                //2 bytes generated
                if (Data[2] == 0x00 && Data[3] == 0x00 && Data[4] == 0x00)
                {
                    Parameters[0] = "s" + Convert.ToString(BitConverter.ToInt16(Data, 1)); //We pass the flag as a string
                    Parameters[1] = "3";
                }
                else
                {
                    Parameters[0] = Convert.ToString(BitConverter.ToInt32(Data, 2)); //We pass the number of the string list index
                    Parameters[1] = "5";
                }
            }
                return Parameters;
        }
    }
}
