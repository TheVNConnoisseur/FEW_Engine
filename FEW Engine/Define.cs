using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Unicode;
using System.Threading.Tasks;

namespace FEW_Engine
{
    class Define
    {
        //Function that parses the decrypted script to a human readable format
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
                    case 4:
                        {
                            instruction.Type = "SetMepachiTime"; //or SMTIME
                            CurrentOffset += 4;

                            for (int CurrentArgument = 0; CurrentArgument < 3; CurrentArgument++)
                            {
                                int ArgumentValue = BitConverter.ToInt32(Data, CurrentOffset);
                                instruction.Arguments.Add(ArgumentValue.ToString());
                                CurrentOffset += 4;
                            }
                            break;
                        }
                    case 5:
                        {
                            instruction.Type = "DebugCgList";
                            CurrentOffset += 4;
                            break;
                        }
                    case 7:
                        {
                            instruction.Type = "SetKutiGroup";
                            CurrentOffset += 4;

                            CurrentOffset += 4; //The next 4 bytes is always an incrementing value starting from 0, that indicates the number of group
                            
                            //It includes a null-terminated string
                            string String = DecompilerHelper.ReadNullTerminatedString(Data, ref CurrentOffset, shiftJIS);
                            instruction.Arguments.Add(String);
                            break;
                        }
                    case 8:
                        {
                            instruction.Type = "SetFullGroup";
                            CurrentOffset += 4;

                            CurrentOffset += 4; //The next 4 bytes is always an incrementing value starting from 0, that indicates the number of group

                            //It includes a null-terminated string
                            string String = DecompilerHelper.ReadNullTerminatedString(Data, ref CurrentOffset, shiftJIS);
                            instruction.Arguments.Add(String);
                            break;
                        }
                    case 10:
                        {
                            instruction.Type = "SetLanguage";
                            CurrentOffset += 4;

                            int ArgumentValue = BitConverter.ToInt32(Data, CurrentOffset);
                            instruction.Arguments.Add(ArgumentValue.ToString());
                            CurrentOffset += 4;
                            break;
                        }
                    case 11:
                        {
                            instruction.Type = "FlowXYSet";
                            CurrentOffset += 4;

                            for (int CurrentArgument = 0; CurrentArgument < 5; CurrentArgument++)
                            {
                                int ArgumentValue = BitConverter.ToInt32(Data, CurrentOffset);
                                instruction.Arguments.Add(ArgumentValue.ToString());
                                CurrentOffset += 4;
                            }
                            break;
                        }
                    case 12:
                        {
                            instruction.Type = "FlowTextSet";
                            CurrentOffset += 4;

                            int ArgumentValue = BitConverter.ToInt32(Data, CurrentOffset);
                            instruction.Arguments.Add(ArgumentValue.ToString());
                            CurrentOffset += 4;

                            //It includes two null-terminated strings
                            string String = DecompilerHelper.ReadNullTerminatedString(Data, ref CurrentOffset, shiftJIS);
                            instruction.Arguments.Add(String);

                            string String2 = DecompilerHelper.ReadNullTerminatedString(Data, ref CurrentOffset, shiftJIS);
                            instruction.Arguments.Add(String2);
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
                    case 16:
                        {
                            instruction.Type = "SceneTest";
                            CurrentOffset += 4;

                            for (int CurrentArgument = 0; CurrentArgument < 5; CurrentArgument++)
                            {
                                int ArgumentValue = BitConverter.ToInt32(Data, CurrentOffset);
                                instruction.Arguments.Add(ArgumentValue.ToString());
                                CurrentOffset += 4;
                            }

                            //It includes two null-terminated strings
                            string String = DecompilerHelper.ReadNullTerminatedString(Data, ref CurrentOffset, shiftJIS);
                            instruction.Arguments.Add(String);
                            break;
                        }
                    case 17:
                        {
                            instruction.Type = "fCgSetGrp";
                            CurrentOffset += 4;

                            int ArgumentValue = BitConverter.ToInt32(Data, CurrentOffset);
                            instruction.Arguments.Add(ArgumentValue.ToString());
                            CurrentOffset += 4;
                            break;
                        }
                    case 18:
                        {
                            instruction.Type = "fcgSet";
                            CurrentOffset += 4;

                            //It includes a null-terminated string
                            string String = DecompilerHelper.ReadNullTerminatedString(Data, ref CurrentOffset, shiftJIS);
                            instruction.Arguments.Add(String);
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
                    case 20:
                        {
                            instruction.Type = "MessageMode";
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

        //Function that recreates the file from the decompiled instructions
        public static byte[] Compile(string JSON)
        {
            //General variables
            List<Instruction> instructions = new List<Instruction>();

            //First we need to deserialize the JSON string into a list of instructions
            var options = new JsonSerializerOptions
            {
                Encoder = JavaScriptEncoder.Create(UnicodeRanges.All)
            };
            instructions = JsonSerializer.Deserialize<List<Instruction>>(JSON, options) ?? new List<Instruction>();

            List<byte> CompiledScript = new List<byte>();

            //Some instructions have included into it the number of instruction for that type, so we need to keep track of that
            int CurrentFlagCGNameSetInstruction = 0;
            int CurrentSetKutiGroupInstruction = 0;
            int CurrentSetFullGroupInstruction = 0;
            int CurrentMemoryTextInstruction = 0;
            int CurrentSystemMessageInstruction = 0;

            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            Encoding shiftJIS = Encoding.GetEncoding("shift-jis");

            //Bytecode section
            for (int CurrentInstruction = 0; CurrentInstruction < instructions.Count; CurrentInstruction++)
            {
                switch (instructions[CurrentInstruction].Type)
                {
                    case "FlagCGNameSet":
                        {
                            CompiledScript.AddRange(BitConverter.GetBytes(2));

                            CompiledScript.AddRange(BitConverter.GetBytes(CurrentFlagCGNameSetInstruction));
                            CurrentFlagCGNameSetInstruction++;

                            //Null-terminated string
                            CompiledScript.AddRange(shiftJIS.GetBytes(instructions[CurrentInstruction].Arguments[0]));
                            CompiledScript.Add(0x00);
                            break;
                        }
                    case "SetMepachiTime":
                        {
                            CompiledScript.AddRange(BitConverter.GetBytes(4));

                            for (int CurrentArgument = 0; CurrentArgument < 3; CurrentArgument++)
                            {
                                CompiledScript.AddRange(BitConverter.GetBytes(int.Parse
                                    (instructions[CurrentInstruction].Arguments[CurrentArgument])));
                            }
                            break;
                        }
                    case "DebugCgList":
                    {
                        CompiledScript.AddRange(BitConverter.GetBytes(5));
                        break;
                    }
                    case "SetKutiGroup":
                    {
                        CompiledScript.AddRange(BitConverter.GetBytes(7));

                        CompiledScript.AddRange(BitConverter.GetBytes(CurrentSetKutiGroupInstruction));
                        CurrentSetKutiGroupInstruction++;

                        //Null-terminated string
                        CompiledScript.AddRange(shiftJIS.GetBytes(instructions[CurrentInstruction].Arguments[0]));
                        CompiledScript.Add(0x00);
                        break;
                    }
                    case "SetFullGroup":
                    {
                        CompiledScript.AddRange(BitConverter.GetBytes(8));

                        CompiledScript.AddRange(BitConverter.GetBytes(CurrentSetFullGroupInstruction));
                        CurrentSetFullGroupInstruction++;

                        //Null-terminated string
                        CompiledScript.AddRange(shiftJIS.GetBytes(instructions[CurrentInstruction].Arguments[0]));
                        CompiledScript.Add(0x00);
                        break;
                    }
                    case "SetLanguage":
                        {
                            CompiledScript.AddRange(BitConverter.GetBytes(10));

                            CompiledScript.AddRange(BitConverter.GetBytes(int.Parse
                                (instructions[CurrentInstruction].Arguments[0])));
                            break;
                        }
                    case "FlowXYSet":
                        {
                            CompiledScript.AddRange(BitConverter.GetBytes(11));

                            for (int CurrentArgument = 0; CurrentArgument < 5; CurrentArgument++)
                            {
                                CompiledScript.AddRange(BitConverter.GetBytes(int.Parse
                                    (instructions[CurrentInstruction].Arguments[CurrentArgument])));
                            }
                            break;
                        }
                    case "FlowTextSet":
                        {
                            CompiledScript.AddRange(BitConverter.GetBytes(12));

                            CompiledScript.AddRange(BitConverter.GetBytes(int.Parse
                                (instructions[CurrentInstruction].Arguments[0])));

                            //Null-terminated strings
                            CompiledScript.AddRange(shiftJIS.GetBytes(instructions[CurrentInstruction].Arguments[1]));
                            CompiledScript.Add(0x00);
                            CompiledScript.AddRange(shiftJIS.GetBytes(instructions[CurrentInstruction].Arguments[2]));
                            CompiledScript.Add(0x00);
                            break;
                        }
                    case "MemoryText":
                        {
                            CompiledScript.AddRange(BitConverter.GetBytes(14));

                            CompiledScript.AddRange(BitConverter.GetBytes(CurrentMemoryTextInstruction));
                            CurrentMemoryTextInstruction++;

                            //Null-terminated strings
                            CompiledScript.AddRange(shiftJIS.GetBytes(instructions[CurrentInstruction].Arguments[0]));
                            CompiledScript.Add(0x00);
                            CompiledScript.AddRange(shiftJIS.GetBytes(instructions[CurrentInstruction].Arguments[1]));
                            CompiledScript.Add(0x00);
                            break;
                        }
                    case "SceneTest":
                        {
                            CompiledScript.AddRange(BitConverter.GetBytes(16));

                            for (int CurrentArgument = 0; CurrentArgument < 5; CurrentArgument++)
                            {
                                CompiledScript.AddRange(BitConverter.GetBytes(int.Parse
                                    (instructions[CurrentInstruction].Arguments[CurrentArgument])));
                            }
                            //Null-terminated string
                            CompiledScript.AddRange(shiftJIS.GetBytes(instructions[CurrentInstruction].Arguments[5]));
                            CompiledScript.Add(0x00);
                            break;
                        }
                    case "fCgSetGrp":
                        {
                            CompiledScript.AddRange(BitConverter.GetBytes(17));

                            CompiledScript.AddRange(BitConverter.GetBytes(int.Parse(
                                instructions[CurrentInstruction].Arguments[0])));
                            break;
                        }
                    case "fcgSet":
                        {
                            CompiledScript.AddRange(BitConverter.GetBytes(18));

                            //Null-terminated string
                            CompiledScript.AddRange(shiftJIS.GetBytes(instructions[CurrentInstruction].Arguments[0]));
                            CompiledScript.Add(0x00);
                            break;
                        }
                    case "SystemMode":
                        {
                            CompiledScript.AddRange(BitConverter.GetBytes(19));

                            //Null-terminated string
                            CompiledScript.AddRange(shiftJIS.GetBytes(instructions[CurrentInstruction].Arguments[0]));
                            CompiledScript.Add(0x00);
                            break;
                        }
                    case "MessageMode":
                        {
                            CompiledScript.AddRange(BitConverter.GetBytes(20));

                            //Null-terminated string
                            CompiledScript.AddRange(shiftJIS.GetBytes(instructions[CurrentInstruction].Arguments[0]));
                            CompiledScript.Add(0x00);
                            break;
                        }
                    case "MesInf":
                        {
                            CompiledScript.AddRange(BitConverter.GetBytes(21));

                            for (int CurrentArgument = 0; CurrentArgument < 5; CurrentArgument++)
                            {
                                CompiledScript.AddRange(BitConverter.GetBytes(int.Parse
                                    (instructions[CurrentInstruction].Arguments[CurrentArgument])));
                            }
                            break;
                        }
                    case "SystemMessage":
                        {
                            CompiledScript.AddRange(BitConverter.GetBytes(23));

                            CompiledScript.AddRange(BitConverter.GetBytes(CurrentSystemMessageInstruction));
                            CurrentSystemMessageInstruction++;

                            //Null-terminated strings
                            CompiledScript.AddRange(shiftJIS.GetBytes(instructions[CurrentInstruction].Arguments[0]));
                            CompiledScript.Add(0x00);
                            break;
                        }
                }
            }

            return CompiledScript.ToArray();
        }
    }
}
