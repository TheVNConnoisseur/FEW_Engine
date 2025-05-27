using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Text;
using System.Threading.Tasks;

namespace FEW_Engine
{
    class Dat
    {
        List<Instruction> instructions = new List<Instruction>();
        List<String> strings = new List<String>();
        public Dat()
        {
            instructions.Clear();
        }

        //Function that removes the decryption method used for the script
        public byte[] Decrypt(byte[] Data)
        {
            //First we obtain the initial key, which is located from bytes 4 to 20
            byte[] Key = new byte[16];
            Buffer.BlockCopy(Data, 4, Key, 0, 16);

            //Now we generate the final byte array with the actual contents of the script file
            byte[] DecryptedData = new byte[Data.Length - 20];
            Buffer.BlockCopy(Data, 20, DecryptedData, 0, DecryptedData.Length);

            //The actual decryption process is a standard XOR one with the current key
            int DecryptionKeyIndex = 0;
            for (int CurrentOffset = 0; CurrentOffset < DecryptedData.Length; CurrentOffset++)
            {
                DecryptedData[CurrentOffset] = (byte)(Key[DecryptionKeyIndex] ^ DecryptedData[CurrentOffset]);
                DecryptionKeyIndex++;

                //Each 16 bytes, the key gets renewed
                if (DecryptionKeyIndex == 16)
                {
                    DecryptionKeyIndex = 0;
                    Key = UpdateKey(Key, DecryptedData[CurrentOffset - 1]);
                }
            }
            return DecryptedData;
        }

        //Function that obtains the new key whenever it is needed to be updated.
        //It does not follow a commonly-known pattern, it is completely custom.
        private static byte[] UpdateKey(byte[] Key, int PreviousOffset)
        {
            byte UnchangedPreviousOffset = (byte)PreviousOffset;

            //Bitwise AND operation with the value 7 (in binary
            //is 00000111), so the last 3 bits will always by 0.
            PreviousOffset &= 7;
            switch (PreviousOffset)
            {
                case 0:
                    Key[0] = (byte)(Key[0] + UnchangedPreviousOffset);
                    Key[3] = (byte)(Key[3] + UnchangedPreviousOffset + 2);
                    Key[4] = (byte)(Key[2] + UnchangedPreviousOffset + 11);
                    Key[8] = (byte)(Key[6] + 7);
                    break;
                case 1:
                    Key[2] = (byte)(Key[9] + Key[10]);
                    Key[6] = (byte)(Key[7] + Key[15]);
                    Key[8] = (byte)(Key[8] + Key[1]);
                    Key[15] = (byte)(Key[5] + Key[3]);
                    break;
                case 2:
                    Key[1] = (byte)(Key[1] + Key[2]);
                    Key[5] = (byte)(Key[5] + Key[6]);
                    Key[7] = (byte)(Key[7] + Key[8]);
                    Key[10] = (byte)(Key[10] + Key[11]);
                    break;
                case 3:
                    Key[9] = (byte)(Key[2] + Key[1]);
                    Key[11] = (byte)(Key[6] + Key[5]);
                    Key[12] = (byte)(Key[8] + Key[7]);
                    Key[13] = (byte)(Key[11] + Key[10]);
                    break;
                case 4:
                    Key[0] = (byte)(Key[1] + 111);
                    Key[3] = (byte)(Key[4] + 71);
                    Key[4] = (byte)(Key[5] + 17);
                    Key[14] = (byte)(Key[15] + 64);
                    break;
                case 5:
                    Key[2] = (byte)(Key[2] + Key[10]);
                    Key[4] = (byte)(Key[5] + Key[12]);
                    Key[6] = (byte)(Key[8] + Key[14]);
                    Key[8] = (byte)(Key[11] + Key[0]);
                    break;
                case 6:
                    Key[9] = (byte)(Key[11] + Key[1]);
                    Key[11] = (byte)(Key[13] + Key[3]);
                    Key[13] = (byte)(Key[15] + Key[5]);
                    Key[15] = (byte)(Key[9] + Key[7]);
                    Key[1] = (byte)(Key[9] + Key[5]);
                    Key[2] = (byte)(Key[10] + Key[6]);
                    Key[3] = (byte)(Key[11] + Key[7]);
                    Key[4] = (byte)(Key[12] + Key[8]);
                    break;
                case 7:
                    Key[1] = (byte)(Key[9] + Key[5]);
                    Key[2] = (byte)(Key[10] + Key[6]);
                    Key[3] = (byte)(Key[11] + Key[7]);
                    Key[4] = (byte)(Key[12] + Key[8]);
                    break;
            }
            return Key;
        }

        //Function that parses the decrypted script to a human readable format
        public List<Instruction> Parse(byte[] Data)
        {
            //Bytes from offset 1 to 3 include the offset where presumably
            //resides some garbage data (probably included to confuse decompilation attempts)
            int offsetGarbage = BitConverter.ToInt32(Data, 0);

            //Bytes from offset 4 to 7 include the offset where the script
            //starts in the original file (when decrypted)
            int offsetList = BitConverter.ToInt32(Data, 4);

            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            Encoding shiftJIS = Encoding.GetEncoding("shift-jis");

            int currentOffset = offsetList;

            while (currentOffset < Data.Length)
            {
                Instruction instruction = new Instruction();

                int sizeInstructionArray = 0;

                //All instruction values are always null-terminated strings
                while (Data[currentOffset] != 0x00)
                {
                    sizeInstructionArray++;
                    currentOffset++;
                }

                //The last instruction is always a null byte, but we ensure that we
                //have reached it before assuming that is the case
                if (sizeInstructionArray == 0 && currentOffset == Data.Length - 2)
                {
                    sizeInstructionArray++;
                    currentOffset++;
                }

                byte[] instructionArray = new byte[sizeInstructionArray];
                Buffer.BlockCopy(Data, currentOffset - sizeInstructionArray, instructionArray, 0, instructionArray.Length);
                string instructionString = shiftJIS.GetString(instructionArray);

                strings.Add(instructionString);

                //We add 1 to the currentOffset value since we want to omit the 0x00
                //byte when parsing the next variable
                currentOffset++;
            }

            //The first 12 bytes are reserved for the header
            currentOffset = 12;

            //For compatibility purposes, the engine offers backwards support for some commands
            //only offered in older versions of the engine
            bool isTakanoScript = false;

            while (currentOffset < offsetGarbage)
            {
                Instruction instruction = new Instruction();

                switch(Data[currentOffset])
                {
                    case 0x4:
                        {
                            instruction.Type = "VideoEnd"; //or VE
                            currentOffset += 1;
                            break;
                        }
                    case 0xD:
                        {
                            instruction.Type = "MacroEnd"; //or Return
                            currentOffset++;
                            break;
                        }
                    case 0x15:
                        {
                            instruction.Type = "AutoSave"; //or AS
                            currentOffset++;
                            break;
                        }
                    case 0x19:
                        {
                            instruction.Type = "FlagAdd";
                            currentOffset++;

                            DecrypterHelper decrypterHelper = new DecrypterHelper();
                            byte[] argumentArray = new byte[5];
                            Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                            string[] argument = decrypterHelper.GetParameters(argumentArray);
                            instruction.Arguments[0] = argument[0];
                            currentOffset += Convert.ToInt32(argument[1]);

                            instruction.Arguments[1] =
                                    Convert.ToString(BitConverter.ToInt32(Data, currentOffset));
                            currentOffset += 4;

                            break;
                        }
                    case 0x1A:
                        {
                            instruction.Type = "FlagSub";
                            currentOffset++;

                            DecrypterHelper decrypterHelper = new DecrypterHelper();
                            byte[] argumentArray = new byte[5];
                            Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                            string[] argument = decrypterHelper.GetParameters(argumentArray);
                            instruction.Arguments[0] = argument[0];
                            currentOffset += Convert.ToInt32(argument[1]);

                            instruction.Arguments[1] =
                                    Convert.ToString(BitConverter.ToInt32(Data, currentOffset));
                            currentOffset += 4;

                            break;
                        }
                    case 0x1B:
                        {
                            instruction.Type = "FlagMul";
                            currentOffset++;

                            DecrypterHelper decrypterHelper = new DecrypterHelper();
                            byte[] argumentArray = new byte[5];
                            Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                            string[] argument = decrypterHelper.GetParameters(argumentArray);
                            instruction.Arguments[0] = argument[0];
                            currentOffset += Convert.ToInt32(argument[1]);

                            instruction.Arguments[1] =
                                    Convert.ToString(BitConverter.ToInt32(Data, currentOffset));
                            currentOffset += 4;

                            break;
                        }
                    case 0x1C:
                        {
                            instruction.Type = "FlagDiv";
                            currentOffset++;

                            DecrypterHelper decrypterHelper = new DecrypterHelper();
                            byte[] argumentArray = new byte[5];
                            Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                            string[] argument = decrypterHelper.GetParameters(argumentArray);
                            instruction.Arguments[0] = argument[0];
                            currentOffset += Convert.ToInt32(argument[1]);

                            instruction.Arguments[1] =
                                    Convert.ToString(BitConverter.ToInt32(Data, currentOffset));
                            currentOffset += 4;

                            break;
                        }
                    case 0x1D:
                        {
                            instruction.Type = "FlagExc";
                            currentOffset++;

                            DecrypterHelper decrypterHelper = new DecrypterHelper();
                            byte[] argumentArray = new byte[5];
                            Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                            string[] argument = decrypterHelper.GetParameters(argumentArray);
                            instruction.Arguments[0] = argument[0];
                            currentOffset += Convert.ToInt32(argument[1]);

                            instruction.Arguments[1] =
                                    Convert.ToString(BitConverter.ToInt32(Data, currentOffset));
                            currentOffset += 4;

                            break;
                        }
                    case 0x1E:
                        {
                            instruction.Type = "FlagSet";
                            currentOffset++;

                            DecrypterHelper decrypterHelper = new DecrypterHelper();
                            byte[] argumentArray = new byte[5];
                            Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                            string[] argument = decrypterHelper.GetParameters(argumentArray);
                            instruction.Arguments[0] = argument[0];
                            currentOffset += Convert.ToInt32(argument[1]);

                            instruction.Arguments[1] =
                                    Convert.ToString(BitConverter.ToInt32(Data, currentOffset));
                            currentOffset += 4;

                            break;
                        }
                    case 0x31:
                        {
                            instruction.Type = "F2FAdd";
                            currentOffset++;

                            DecrypterHelper decrypterHelper = new DecrypterHelper();
                            for (int currentArgument = 0; currentArgument < 2; currentArgument++)
                            {
                                byte[] argumentArray = new byte[5];
                                Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                                string[] argument = decrypterHelper.GetParameters(argumentArray);
                                instruction.Arguments[currentArgument] = argument[0];
                                currentOffset += Convert.ToInt32(argument[1]);
                            }
                            break;
                        }
                    case 0x32:
                        {
                            instruction.Type = "F2FSub";
                            currentOffset++;

                            DecrypterHelper decrypterHelper = new DecrypterHelper();
                            for (int currentArgument = 0; currentArgument < 2; currentArgument++)
                            {
                                byte[] argumentArray = new byte[5];
                                Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                                string[] argument = decrypterHelper.GetParameters(argumentArray);
                                instruction.Arguments[currentArgument] = argument[0];
                                currentOffset += Convert.ToInt32(argument[1]);
                            }
                            break;
                        }
                    case 0x33:
                        {
                            instruction.Type = "F2FMul";
                            currentOffset++;

                            DecrypterHelper decrypterHelper = new DecrypterHelper();
                            for (int currentArgument = 0; currentArgument < 2; currentArgument++)
                            {
                                byte[] argumentArray = new byte[5];
                                Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                                string[] argument = decrypterHelper.GetParameters(argumentArray);
                                instruction.Arguments[currentArgument] = argument[0];
                                currentOffset += Convert.ToInt32(argument[1]);
                            }
                            break;
                        }
                    case 0x34:
                        {
                            instruction.Type = "F2FDiv";
                            currentOffset++;

                            DecrypterHelper decrypterHelper = new DecrypterHelper();
                            for (int currentArgument = 0; currentArgument < 2; currentArgument++)
                            {
                                byte[] argumentArray = new byte[5];
                                Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                                string[] argument = decrypterHelper.GetParameters(argumentArray);
                                instruction.Arguments[currentArgument] = argument[0];
                                currentOffset += Convert.ToInt32(argument[1]);
                            }
                            break;
                        }
                    case 0x35:
                        {
                            instruction.Type = "F2FExc";
                            currentOffset++;

                            DecrypterHelper decrypterHelper = new DecrypterHelper();
                            for (int currentArgument = 0; currentArgument < 2; currentArgument++)
                            {
                                byte[] argumentArray = new byte[5];
                                Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                                string[] argument = decrypterHelper.GetParameters(argumentArray);
                                instruction.Arguments[currentArgument] = argument[0];
                                currentOffset += Convert.ToInt32(argument[1]);
                            }
                            break;
                        }
                    case 0x36:
                        {
                            instruction.Type = "F2FSet";
                            currentOffset++;

                            DecrypterHelper decrypterHelper = new DecrypterHelper();
                            for (int currentArgument = 0; currentArgument < 2; currentArgument++)
                            {
                                byte[] argumentArray = new byte[5];
                                Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                                string[] argument = decrypterHelper.GetParameters(argumentArray);
                                instruction.Arguments[currentArgument] = argument[0];
                                currentOffset += Convert.ToInt32(argument[1]);
                            }
                            break;
                        }
                    case 0x37:
                        {
                            instruction.Type = "F2FRand";
                            currentOffset++;

                            DecrypterHelper decrypterHelper = new DecrypterHelper();
                            byte[] argumentArray = new byte[5];
                            Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                            string[] argument = decrypterHelper.GetParameters(argumentArray);
                            instruction.Arguments[0] = argument[0];
                            currentOffset += Convert.ToInt32(argument[1]);

                            instruction.Arguments[1] =
                                    Convert.ToString(BitConverter.ToInt32(Data, currentOffset));

                            argumentArray.Initialize();
                            Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                            argument = decrypterHelper.GetParameters(argumentArray);
                            instruction.Arguments[2] = argument[0];
                            currentOffset += Convert.ToInt32(argument[1]);

                            break;
                        }
                    case 0x47:
                        {
                            instruction.Type = "CgFullClear"; //or CFC
                            currentOffset++;
                            break;
                        }
                    case 0x4A:
                        {
                            instruction.Type = "CgMidMove";
                            instruction.Arguments[0] =
                                    Convert.ToString(Data[currentOffset + 1]);
                            currentOffset += 2;
                            instruction.Arguments[1] =
                                    Convert.ToString(BitConverter.ToInt32(Data, currentOffset));
                            currentOffset += 4;

                            break;
                        }
                    case 0x4B:
                        {
                            instruction.Type = "CgMidXY"; //or CMXY

                            instruction.Arguments[0] =
                                    Convert.ToString(Data[currentOffset + 1]);
                            currentOffset += 2;

                            for (int currentArgument = 0; currentArgument < 2; currentArgument++)
                            {
                                instruction.Arguments[currentArgument + 1] =
                                    Convert.ToString(BitConverter.ToInt32(Data, currentOffset + (currentArgument * 4)));
                            }
                            currentOffset += 8;

                            break;
                        }
                    case 0x4C:
                        {
                            instruction.Type = "GetMiddlePos"; //or GetMidPos, GMPos
                            currentOffset++;

                            instruction.Arguments[0] =
                                   Convert.ToString(Data[currentOffset]);
                            currentOffset++;

                            DecrypterHelper decrypterHelper = new DecrypterHelper();
                            byte[] argumentArray = new byte[5];
                            Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                            string[] argument = decrypterHelper.GetParameters(argumentArray);
                            instruction.Arguments[0] = argument[0];
                            currentOffset += Convert.ToInt32(argument[1]);

                            break;
                        }
                    case 0x4D:
                        {
                            instruction.Type = "CgMidClear"; //or CMC
                            instruction.Arguments[0] =
                                    Convert.ToString(Data[currentOffset + 1]);
                            currentOffset += 2;

                            break;
                        }
                    case 0x4F:
                        {
                            instruction.Type = "CModeFlash";

                            for (int currentArgument = 0; currentArgument < 7; currentArgument++)
                            {
                                instruction.Arguments[currentArgument] =
                                    Convert.ToString(BitConverter.ToInt32(Data, currentOffset + 1 + (currentArgument * 4)));
                            }
                            currentOffset += 29;
                            break;
                        }
                    case 0x50:
                        {
                            instruction.Type = "EffectFlash"; //or EFF
                            instruction.Arguments[0] =
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset + 1));
                            currentOffset += 3;
                            break;
                        }
                    case 0x51:
                        {
                            instruction.Type = "EffectShake";
                            for (int currentArgument = 0; currentArgument < 4; currentArgument++)
                            {
                                instruction.Arguments[currentArgument] =
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset + 1 + (currentArgument * 2)));
                            }
                            currentOffset += 9;
                            break;
                        }
                    case 0x55:
                        {
                            instruction.Type = "EffectEnvStop"; //or EFES
                            currentOffset += 1;
                            break;
                        }
                    case 0x56:
                        {
                            instruction.Type = "EffectEnvStopNoCreate"; //or EFESNC
                            currentOffset += 1;
                            break;
                        }
                    case 0x57:
                        {
                            instruction.Type = "ColorFill"; //or CFill

                            for (int currentArgument = 0; currentArgument < 3; currentArgument++)
                            {
                                instruction.Arguments[currentArgument] =
                                    Convert.ToString(Data[currentOffset + 1 + currentArgument]);
                            }
                            currentOffset += 4;

                            for (int currentArgument = 0; currentArgument < 2; currentArgument++)
                            {
                                instruction.Arguments[currentArgument + 3] =
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset + (currentArgument * 2)));
                            }
                            currentOffset += 4;

                            break;
                        }
                    case 0x58:
                        {
                            instruction.Arguments[0] = Convert.ToString
                                (BitConverter.ToInt32(Data, currentOffset + 1));
                            currentOffset += 5;

                            //To know which of instructions is the one we are dealing with, we need
                            //to check its first argument
                            int firstArgument = Convert.ToInt32(instruction.Arguments[0]);

                            switch (firstArgument)
                            {
                                case 0: instruction.Type = "ColorModeNone"; break; // or CModeNone (2nd argument is always 0)
                                case 1: instruction.Type = "ColorModeDark"; break; // or CModeDark
                                case 2: instruction.Type = "ColorModeLight"; break; // or CModeLight
                                case 3: instruction.Type = "ColorModeSepia"; break; // or CModeSepia (2nd argument is always 0)
                                case 4: instruction.Type = "ColorModeMono"; break; // or CModeMono (2nd argument is always 0)
                                default: instruction.Type = "ColorMode"; break;    // or CMode
                            }
                            
                            for (int currentArgument = 0; currentArgument < 3; currentArgument++)
                            {
                                instruction.Arguments[currentArgument + 1] =
                                    Convert.ToString(Data[currentOffset + (currentArgument * 1)]);
                            }
                            currentOffset += 3;

                            break;
                        }
                    case 0x59:
                        {
                            instruction.Type = "EffectEnvLoadAlpha"; //or EFELA
                            currentOffset++;
                            break;
                        }
                    case 0x5E:
                        {
                            instruction.Type = "SoundEffectPlayLoop"; //or SEPL, WavePlayLoop, WPL
                            int stringIndex = BitConverter.ToInt32(Data, currentOffset + 1);
                            instruction.Arguments[0] = strings[stringIndex];
                            currentOffset += 5;
                            break;
                        }
                    case 0x60:
                        {
                            instruction.Type = "SoundEffectPlayLoopABCD"; //or SEPLAD
                            instruction.Arguments[0] =
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset + 1));
                            int stringIndex = BitConverter.ToInt32(Data, currentOffset + 3);
                            instruction.Arguments[1] = strings[stringIndex];
                            currentOffset += 7;
                            break;
                        }
                    case 0x7D:
                        {
                            instruction.Type = "SetMepachiTime"; //or SMTIME
                            currentOffset++;

                            for (int currentArgument = 0; currentArgument < 3; currentArgument++)
                            {
                                instruction.Arguments[currentArgument] =
                                    Convert.ToString(BitConverter.ToInt32(Data, currentOffset + (currentArgument * 4)));
                            }
                            currentOffset += 12;

                            break;
                        }
                    case 0x7E:
                        {
                            instruction.Type = "EventInit";
                            currentOffset++;
                            break;
                        }
                    case 0x7F:
                        {
                            instruction.Type = "EventSet";

                            for (int currentArgument = 0; currentArgument < 6; currentArgument++)
                            {
                                instruction.Arguments[currentArgument] =
                                    Convert.ToString(BitConverter.ToInt32(Data, currentOffset + 1 + (currentArgument * 4)));
                            }
                            currentOffset += 25;
                            break;
                        }
                    case 0x80:
                        {
                            instruction.Type = "timeGetTime"; //or TimeGet
                            currentOffset++;

                            DecrypterHelper decrypterHelper = new DecrypterHelper();
                            byte[] argumentArray = new byte[5];
                            Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                            string[] argument = decrypterHelper.GetParameters(argumentArray);
                            instruction.Arguments[0] = argument[0];
                            currentOffset += Convert.ToInt32(argument[1]);
                            break;
                        }
                    case 0x81:
                        {
                            instruction.Type = "GetSEPPlayNow"; //or GSEPN
                            currentOffset++;

                            DecrypterHelper decrypterHelper = new DecrypterHelper();
                            byte[] argumentArray = new byte[5];
                            Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                            string[] argument = decrypterHelper.GetParameters(argumentArray);
                            instruction.Arguments[0] = argument[0];
                            currentOffset += Convert.ToInt32(argument[1]);
                            break;
                        }
                    case 0x8C:
                        {
                            instruction.Type = "TextInit";

                            for (int currentArgument = 0; currentArgument < 2; currentArgument++)
                            {
                                instruction.Arguments[currentArgument] =
                                    Convert.ToString(BitConverter.ToInt32(Data, currentOffset + 1 + (currentArgument * 4)));
                            }
                            currentOffset += 9;
                            break;
                        }
                    case 0x8D:
                        {
                            instruction.Type = "TextOutSet";

                            for (int currentArgument = 0; currentArgument < 4; currentArgument++)
                            {
                                instruction.Arguments[currentArgument] =
                                    Convert.ToString(BitConverter.ToInt32(Data, currentOffset + 1 + (currentArgument * 4)));
                            }
                            currentOffset += 17;
                            break;
                        }
                    case 0x8F:
                        {
                            instruction.Type = "TextOutDefault"; //or TOD
                            currentOffset++;
                            break;
                        }
                    case 0x90:
                        {
                            instruction.Type = "TextDraw";

                            for (int currentArgument = 0; currentArgument < 4; currentArgument++)
                            {
                                instruction.Arguments[currentArgument] =
                                    Convert.ToString(BitConverter.ToInt32(Data, currentOffset + 1 + (currentArgument * 4)));
                            }
                            currentOffset += 17;
                            break;
                        }
                    case 0x91:
                        {
                            instruction.Type = "TextDrawDefault"; //or TDD
                            currentOffset++;
                            break;
                        }
                    case 0x94:
                        {
                            instruction.Type = "CgUnLoad";
                            instruction.Arguments[0] =
                                    Convert.ToString(BitConverter.ToInt32(Data, currentOffset + 1));
                            currentOffset += 5;
                            break;
                        }
                    case 0x95:
                        {
                            instruction.Type = "CgDrawInit";
                            currentOffset++;
                            break;
                        }
                    case 0x96:
                        {
                            instruction.Type = "CgInitRect";
                            currentOffset++;

                            DecrypterHelper decrypterHelper = new DecrypterHelper();
                            for (int currentArgument = 0; currentArgument < 4; currentArgument++)
                            {
                                byte[] argumentArray = new byte[5];
                                Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                                string[] argument = decrypterHelper.GetParameters(argumentArray);
                                instruction.Arguments[currentArgument] = argument[0];
                                currentOffset += Convert.ToInt32(argument[1]);
                            }
                            break;
                        }
                    case 0x97:
                        {
                            instruction.Type = "CgDraw";
                            instruction.Arguments[0] =
                                    Convert.ToString(Data[currentOffset + 1]);
                            currentOffset += 2;
                            break;
                        }
                    case 0x98:
                        {
                            instruction.Type = "CgShow";
                            currentOffset++;

                            DecrypterHelper decrypterHelper = new DecrypterHelper();
                            for (int currentArgument = 0; currentArgument < 4; currentArgument++)
                            {
                                byte[] argumentArray = new byte[5];
                                Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                                string[] argument = decrypterHelper.GetParameters(argumentArray);
                                instruction.Arguments[currentArgument] = argument[0];
                                currentOffset += Convert.ToInt32(argument[1]);
                            }
                            break;
                        }
                    case 0x9A:
                        {
                            instruction.Type = "CgDrawColorDodge"; //or CgDrawCD
                            instruction.Arguments[0] =
                                    Convert.ToString(BitConverter.ToInt32(Data, currentOffset + 1));
                            currentOffset += 5;

                            DecrypterHelper decrypterHelper = new DecrypterHelper();
                            for (int currentArgument = 0; currentArgument < 6; currentArgument++)
                            {
                                byte[] argumentArray = new byte[5];
                                Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                                string[] argument = decrypterHelper.GetParameters(argumentArray);
                                instruction.Arguments[currentArgument + 1] = argument[0];
                                currentOffset += Convert.ToInt32(argument[1]);
                            }
                            break;
                        }
                    case 0x9B:
                        {
                            instruction.Type = "CgDrawBlendPattern"; //or CgDrawBP
                            instruction.Arguments[0] =
                                    Convert.ToString(BitConverter.ToInt32(Data, currentOffset + 1));
                            currentOffset += 5;

                            DecrypterHelper decrypterHelper = new DecrypterHelper();
                            for (int currentArgument = 0; currentArgument < 8; currentArgument++)
                            {
                                byte[] argumentArray = new byte[5];
                                Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                                string[] argument = decrypterHelper.GetParameters(argumentArray);
                                instruction.Arguments[currentArgument + 1] = argument[0];
                                currentOffset += Convert.ToInt32(argument[1]);
                            }
                            break;
                        }
                    case 0x9C:
                        {
                            instruction.Type = "DrawMessageWindow"; //or DrawMW
                            currentOffset++;
                            break;
                        }
                    case 0xB7:
                        {
                            instruction.Type = "EventStart";
                            currentOffset++;
                            break;
                        }
                    case 0xB8:
                        {
                            instruction.Type = "KeyWaitMovie";
                            currentOffset++;
                            break;
                        }
                    case 0xB9:
                        {
                            instruction.Type = "KeyWait";
                            currentOffset++;
                            break;
                        }
                    case 0xF0:
                        {
                            if (isTakanoScript)
                            {
                                instruction.Type = "ReturnTitle"; //or RT
                                instruction.Arguments[0] = "1";
                                instruction.Arguments[1] = "0";
                            }
                            else //Program
                            {
                                instruction.Type = "Program";

                                for (int currentArgument = 0; currentArgument < 2; currentArgument++)
                                {
                                    instruction.Arguments[currentArgument] = 
                                        Convert.ToString(BitConverter.ToInt32(Data, currentOffset + 1 + (currentArgument * 4)));
                                }
                            }
                            currentOffset += 9;
                            break;
                        }
                    default:
                        {
                            break;
                        }
                }
            }

            return instructions;
        }

        //Function that recreates and encrypts back the decrypted script
        public byte[] Encrypt(string[] Data, byte[] BinaryInstructions)
        {
            //First we initialize the header, which is always the same
            byte[] Header = { 0x00, 0x00, 0x00, 0x01 };

            //Next, we include the decryption key, which we will make it
            //just full of null bytes, because we don't need to put anything
            //specific to it, since the game's decryption process will always be
            //the same no matter what
            byte[] Key = new byte[16];
            Key.Initialize();

            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            Encoding shiftJIS = Encoding.GetEncoding("shift-jis");
            List<byte> ScriptLines = new List<byte>();

            //We change the line termination \r\n bytes for a null byte
            for (int CurrentLine = 0; CurrentLine < Data.Length; CurrentLine++)
            {
                Data[CurrentLine] = Data[CurrentLine].Replace("\r\n", "");
                byte[] LineBytes = shiftJIS.GetBytes(Data[CurrentLine]);
                ScriptLines.AddRange(LineBytes);
                ScriptLines.Add(0x00);
            }
            ScriptLines.RemoveAt(ScriptLines.LastIndexOf(0x00));

            byte[] Script = ScriptLines.ToArray();

            byte[] OffsetScript = BitConverter.GetBytes(BinaryInstructions.Length);

            int SizeFinalScript = Header.Length + Key.Length + BinaryInstructions.Length + Script.Length;

            //The script expects to end the script with a value divisible by 4,
            //so in order to do that, it adds null bytes at the footer in order
            //to comply with this requirement.
            //In case that the file size does not end up being divisible by 4, we
            //simply calculate the number of bytes necessary to create a compatible
            //script
            if (SizeFinalScript % 4 != 0)
            {
                SizeFinalScript = SizeFinalScript + (4 - ((SizeFinalScript % 4)) % 4);
            }

            byte[] UnencryptedScript = new byte[SizeFinalScript];
            UnencryptedScript.Initialize();

            Buffer.BlockCopy(Header, 0, UnencryptedScript, 0, Header.Length);
            Buffer.BlockCopy(Key, 0, UnencryptedScript, Header.Length, Key.Length);
            Buffer.BlockCopy(BinaryInstructions, 0, UnencryptedScript, Header.Length + Key.Length, BinaryInstructions.Length);
            Buffer.BlockCopy(OffsetScript, 0, UnencryptedScript, Header.Length + Key.Length + 4, OffsetScript.Length);
            Buffer.BlockCopy(Script, 0, UnencryptedScript, Header.Length + Key.Length + BinaryInstructions.Length, Script.Length);

            //The actual encryption process is a standard XOR one with the key set in place
            int EncryptionKeyIndex = 0;

            byte[] EncryptedScript = new byte[UnencryptedScript.Length];
            Buffer.BlockCopy(UnencryptedScript, 0, EncryptedScript, 0, Header.Length + Key.Length);
            for (int CurrentOffset = Header.Length + Key.Length; CurrentOffset < UnencryptedScript.Length; CurrentOffset++)
            {
                EncryptedScript[CurrentOffset] = (byte)(Key[EncryptionKeyIndex] ^ UnencryptedScript[CurrentOffset]);
                EncryptionKeyIndex++;

                //Each 16 bytes, the key gets renewed
                if (EncryptionKeyIndex == 16)
                {
                    EncryptionKeyIndex = 0;
                    Key = UpdateKey(Key, UnencryptedScript[CurrentOffset - 1]);
                }
            }

            return EncryptedScript;
        }
    }
}
