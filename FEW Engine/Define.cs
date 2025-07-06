using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FEW_Engine
{
    class Define
    {
        public static List<Instruction> Parse(byte[] Data)
        {
            List<Instruction> instructions = new List<Instruction>();

            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            Encoding shiftJIS = Encoding.GetEncoding("shift-jis");

            int CurrentOffset = 0;

            while (CurrentOffset < Data.Length)
            {
                Instruction instruction = new Instruction();

                switch (BitConverter.ToInt32(Data, CurrentOffset))
                {
                    case 2:
                        {
                            instruction.Type = "FlagCGNameSet"; //or FCGNS
                            CurrentOffset += 4;

                            CurrentOffset += 4; //The next 4 bytes is always an incrementing value starting from 0, that indicates the number of string

                            //It includes a null-terminated string
                            string String = DecompilerHelper.ReadNullTerminatedString(Data, ref CurrentOffset, shiftJIS);
                            instruction.Arguments.Add(String);
                            break;
                        }
                    case 14:
                        {
                            instruction.Type = "MemoryText";
                            CurrentOffset += 4;

                            CurrentOffset += 4; //The next 4 bytes is always an incrementing value starting from 0, that indicates the number of string

                            //It includes two null-terminated strings
                            string String = DecompilerHelper.ReadNullTerminatedString(Data, ref CurrentOffset, shiftJIS);
                            instruction.Arguments.Add(String);

                            string String2 = DecompilerHelper.ReadNullTerminatedString(Data, ref CurrentOffset, shiftJIS);
                            instruction.Arguments.Add(String2);
                            break;
                        }
                    case 19:
                        {
                            instruction.Type = "SystemMode";
                            CurrentOffset += 4;

                            //It includes a null-terminated string
                            string String = DecompilerHelper.ReadNullTerminatedString(Data, ref CurrentOffset, shiftJIS);
                            instruction.Arguments.Add(String);
                            break;
                        }
                    case 21:
                        {
                            instruction.Type = "MesInf";
                            CurrentOffset += 4;

                            for (int CurrentArgument = 0; CurrentArgument < 5; CurrentArgument++)
                            {
                                int ArgumentValue = BitConverter.ToInt32(Data, CurrentOffset);
                                instruction.Arguments.Add(ArgumentValue.ToString());
                                CurrentOffset += 4;
                            }
                            break;
                        }
                    case 23:
                        {
                            instruction.Type = "SystemMessage";
                            CurrentOffset += 4;

                            CurrentOffset += 4; //The next 4 bytes is always an incrementing value starting from 0, that indicates the number of string

                            //It includes a null-terminated string
                            string String = DecompilerHelper.ReadNullTerminatedString(Data, ref CurrentOffset, shiftJIS);
                            instruction.Arguments.Add(String);
                            break;
                        }
                    default:
                        throw new Exception($"Unknown instruction type: {BitConverter.ToInt32(Data, CurrentOffset)} at offset {CurrentOffset}");
                }

                instructions.Add(instruction);
            }
            return instructions;
        }
    }
}
