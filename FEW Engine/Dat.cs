using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Net;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Unicode;
using System.Threading.Tasks;

namespace FEW_Engine
{
    class Dat
    {
        List<Instruction> instructions = new List<Instruction>();
        List<String> strings = new List<String>();
        List<Label> labels = new List<Label>();
        List<Label> pendingLabels = new List<Label>();
        public Dat()
        {
            instructions.Clear();
            labels.Clear();
            pendingLabels.Clear();
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
            //Bytes from offset 1 to 3 include the offset where the labels/macro/$ names and offsets
            //for each of them are stored. Well in theory that's what they are used for, but
            //in practice they don't seem to store anything of value? Or at least the game analyzed
            //here does not use them at all from this list, since the game engine already stores the
            //offset in the bytecode itself.
            int offsetLabels = BitConverter.ToInt32(Data, 0);

            //Bytes from offset 4 to 7 include the offset where the list of strings starts
            int offsetList = BitConverter.ToInt32(Data, 4);

            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            Encoding shiftJIS = Encoding.GetEncoding("shift-jis");

            //We first parse the strings list, since those will be used to fill out the arguments for some instructions
            int currentOffset = offsetList;

            //The string list when completed, the compiler includes a null byte at the end
            while (currentOffset < Data.Length - 1)
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
            //only offered in older versions of the engine (although for simplicity purposes those are not implemented
            //here, since we can't know if those commands are used in the script or not)
            bool isTakanoScript = false;

            //The compiler adds an extra byte (0x01) at the end of the bytecode
            while (currentOffset < offsetLabels - 1)
            {
                Instruction instruction = new Instruction();

                //First we check if before the following instruction there is a label that matches the current offset,
                //because if it is the case, we will create the corresponding instruction for it
                var matchingLabel = labels.FirstOrDefault(l => l.Address == currentOffset);

                if (matchingLabel.Address == currentOffset || labels.Any(l => l.Address == 0 && currentOffset == 0))
                {
                    Instruction labelInstruction = new Instruction();
                    labelInstruction.Type = "Label"; //or Macro, or $
                    labelInstruction.Arguments.Add(matchingLabel.Name);
                    instructions.Add(labelInstruction);
                }

                switch (Data[currentOffset])
                {
                    case 0x2:
                        {
                            instruction.Type = "VideoStart"; //or VS, RecS
                            currentOffset++;

                            instruction.Arguments.Add(
                                Convert.ToString(Data[currentOffset]));
                            currentOffset++;

                            break;
                        }
                    case 0x3:
                        {
                            instruction.Type = "VideoStartAnime"; //or VSA
                            currentOffset++;

                            instruction.Arguments.Add(
                                Convert.ToString(Data[currentOffset]));
                            currentOffset++;

                            break;
                        }
                    case 0x4:
                        {
                            instruction.Type = "VideoEnd"; //or VE, RecE
                            currentOffset++;
                            break;
                        }
                    case 0xB:
                        {
                            instruction.Type = "Goto"; //or g
                            currentOffset++;

                            int labelIndex = BitConverter.ToInt32(Data, currentOffset);
                            Label label = DecrypterHelper.CreateLabel(labels, labelIndex);
                            if (label.Name == "Label_" + labels.Count()) //If the label is new, we add it to the list of labels
                            {
                                labels.Add(label);
                            }
                            instruction.Arguments.Add(label.Name);
                            currentOffset += 4;

                            break;
                        }
                    case 0xC:
                        {
                            instruction.Type = "Gosub"; //or gs (or it also can be an instruction without an explicit name type)
                            currentOffset++;

                            int labelIndex = BitConverter.ToInt32(Data, currentOffset);
                            Label label = DecrypterHelper.CreateLabel(labels, labelIndex);
                            if (label.Name == "Label_" + labels.Count()) //If the label is new, we add it to the list of labels
                            {
                                labels.Add(label);
                            }
                            instruction.Arguments.Add(label.Name);
                            currentOffset += 4;

                            break;
                        }
                    case 0xD:
                        {
                            instruction.Type = "MacroEnd"; //or Return
                            currentOffset++;
                            break;
                        }
                    case 0xE:
                        {
                            if (Data[currentOffset + 1] == 0x74 && BitConverter.ToInt16(Data, currentOffset + 2) == 0x00
                                && BitConverter.ToInt16(Data, currentOffset + 4) == 0x00
                                && BitConverter.ToInt16(Data, currentOffset + 6) == 0x00)
                            {
                                instruction.Type = "Movie"; //or MV
                                currentOffset += 2;

                                for (int currentArgument = 0; currentArgument < 5; currentArgument++)
                                {
                                    instruction.Arguments.Add(Convert.ToString(
                                        BitConverter.ToInt16(Data, currentOffset)));
                                    currentOffset += 2;
                                }

                                int stringIndex = BitConverter.ToInt32(Data, currentOffset);
                                instruction.Arguments.Add(strings[stringIndex]);
                                currentOffset += 4;

                                if (Data[currentOffset] != 0xB8 && Data[currentOffset + 1] != 0x78)
                                {
                                    throw new Exception("Movie command is missing closing bytes.");
                                }
                                currentOffset += 2;
                            }
                            else
                            {
                                instruction.Type = "SkipStop";
                                currentOffset++;
                            }
                                
                            break;
                        }
                    case 0x14:
                        {
                            instruction.Type = "SaveStatus"; //or SS
                            currentOffset++;

                            int stringIndex = BitConverter.ToInt32(Data, currentOffset);
                            instruction.Arguments.Add(strings[stringIndex]);
                            currentOffset += 4;
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

                            byte[] argumentArray = new byte[5];
                            Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                            string[] argument = DecrypterHelper.GetParameters(argumentArray);
                            instruction.Arguments.Add(argument[0]);
                            currentOffset += Convert.ToInt32(argument[1]);

                            instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt32(Data, currentOffset)));
                            currentOffset += 4;

                            break;
                        }
                    case 0x1A:
                        {
                            instruction.Type = "FlagSub";
                            currentOffset++;

                            byte[] argumentArray = new byte[5];
                            Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                            string[] argument = DecrypterHelper.GetParameters(argumentArray);
                            instruction.Arguments.Add(argument[0]);
                            currentOffset += Convert.ToInt32(argument[1]);

                            instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt32(Data, currentOffset)));
                            currentOffset += 4;

                            break;
                        }
                    case 0x1B:
                        {
                            instruction.Type = "FlagMul";
                            currentOffset++;

                            byte[] argumentArray = new byte[5];
                            Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                            string[] argument = DecrypterHelper.GetParameters(argumentArray);
                            instruction.Arguments.Add(argument[0]);
                            currentOffset += Convert.ToInt32(argument[1]);

                            instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt32(Data, currentOffset)));
                            currentOffset += 4;

                            break;
                        }
                    case 0x1C:
                        {
                            instruction.Type = "FlagDiv";
                            currentOffset++;

                            byte[] argumentArray = new byte[5];
                            Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                            string[] argument = DecrypterHelper.GetParameters(argumentArray);
                            instruction.Arguments.Add(argument[0]);
                            currentOffset += Convert.ToInt32(argument[1]);

                            instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt32(Data, currentOffset)));
                            currentOffset += 4;

                            break;
                        }
                    case 0x1D:
                        {
                            instruction.Type = "FlagExc";
                            currentOffset++;

                            byte[] argumentArray = new byte[5];
                            Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                            string[] argument = DecrypterHelper.GetParameters(argumentArray);
                            instruction.Arguments.Add(argument[0]);
                            currentOffset += Convert.ToInt32(argument[1]);

                            instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt32(Data, currentOffset)));
                            currentOffset += 4;

                            break;
                        }
                    case 0x1E:
                        {
                            instruction.Type = "Unknown 0x1E"; //We cannot know the name of this instruction, but it is related to macros
                            currentOffset++;

                            if (Data[currentOffset + 3] == 0x41)
                            {
                                instruction.Arguments.Add(
                                    Convert.ToString(Data[currentOffset]));
                                currentOffset++;

                                instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset)));
                                currentOffset += 2;

                                currentOffset++; //We skip the 0x41 byte
                            }
                            else
                            {
                                instruction.Type = "FlagSet";

                                byte[] argumentArray = new byte[5];
                                Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                                string[] argument = DecrypterHelper.GetParameters(argumentArray);
                                instruction.Arguments.Add(argument[0]);
                                currentOffset += Convert.ToInt32(argument[1]);

                                instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt32(Data, currentOffset)));
                                currentOffset += 4;
                            }

                            break;
                        }
                    case 0x1F:
                        {
                            //There is another unknown opcode related to the unknown 0x1E opcode, but since that one cannot even be understood with a compiled script, it will be ignored
                            instruction.Type = "StringSet";
                            currentOffset++;

                            byte[] argumentArray = new byte[5];
                            Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                            string[] argument = DecrypterHelper.GetStringParameters(argumentArray, 1);
                            if (Convert.ToInt32(argument[1]) == 5) //If the amount of bytes read is 5, it means that the last 4 bytes are the index of the string array
                            {
                                int stringIndex = Convert.ToInt32(argument[0]);
                                instruction.Arguments.Add(strings[stringIndex]);
                            }
                            else
                            {
                                instruction.Arguments.Add(argument[0]);
                            }
                            currentOffset += Convert.ToInt32(argument[1]);

                            int stringIndex1 = BitConverter.ToInt32(Data, currentOffset);
                            instruction.Arguments.Add(strings[stringIndex1]);
                            currentOffset += 4;

                            break;
                        }
                    case 0x20:
                        {
                            //There is another unknown opcode related to the unknown 0x1E opcode, but since that one cannot even be understood with a compiled script, it will be ignored
                            instruction.Type = "S2SSet"; //or S2SS
                            currentOffset++;

                            for (int currentArgument = 0; currentArgument < 2; currentArgument++)
                            {
                                byte[] argumentArray = new byte[5];
                                Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                                string[] argument = DecrypterHelper.GetStringParameters(argumentArray, 1);
                                if (Convert.ToInt32(argument[1]) == 5) //If the amount of bytes read is 5, it means that the last 4 bytes are the index of the string array
                                {
                                    int stringIndex = Convert.ToInt32(argument[0]);
                                    instruction.Arguments.Add(strings[stringIndex]);
                                }
                                else
                                {
                                    instruction.Arguments.Add(argument[0]);
                                }
                                currentOffset += Convert.ToInt32(argument[1]);
                            }

                            break;
                        }
                    case 0x21:
                        {
                            instruction.Type = "S2SConnect"; //or S2SC
                            currentOffset++;

                            for (int currentArgument = 0; currentArgument < 2; currentArgument++)
                            {
                                byte[] argumentArray = new byte[5];
                                Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                                string[] argument = DecrypterHelper.GetStringParameters(argumentArray, 1);
                                if (Convert.ToInt32(argument[1]) == 5) //If the amount of bytes read is 5, it means that the last 4 bytes are the index of the string array
                                {
                                    int stringIndex = Convert.ToInt32(argument[0]);
                                    instruction.Arguments.Add(strings[stringIndex]);
                                }
                                else
                                {
                                    instruction.Arguments.Add(argument[0]);
                                }
                                currentOffset += Convert.ToInt32(argument[1]);
                            }

                            break;
                        }
                    case 0x22:
                        {
                            instruction.Type = "S2TextConnect"; //or S2TC
                            currentOffset++;

                            byte[] argumentArray = new byte[5];
                            Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                            string[] argument = DecrypterHelper.GetStringParameters(argumentArray, 1);
                            if (Convert.ToInt32(argument[1]) == 5) //If the amount of bytes read is 5, it means that the last 4 bytes are the index of the string array
                            {
                                int stringIndex = Convert.ToInt32(argument[0]);
                                instruction.Arguments.Add(strings[stringIndex]);
                            }
                            else
                            {
                                instruction.Arguments.Add(argument[0]);
                            }
                            currentOffset += Convert.ToInt32(argument[1]);

                            int stringIndex1 = BitConverter.ToInt32(Data, currentOffset);
                            instruction.Arguments.Add(strings[stringIndex1]);
                            currentOffset += 4;

                            break;
                        }
                    case 0x23:
                        {
                            instruction.Type = "FlagRand";
                            currentOffset++;

                            byte[] argumentArray = new byte[5];
                            Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                            string[] argument = DecrypterHelper.GetParameters(argumentArray);
                            instruction.Arguments.Add(argument[0]);
                            currentOffset += Convert.ToInt32(argument[1]);

                            for (int currentArgument = 0; currentArgument < 2; currentArgument++)
                            {
                                instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt32(Data, currentOffset)));
                                currentOffset += 4;
                            }

                            break;
                        }
                    case 0x24:
                        {
                            instruction.Type = "FlagCg";
                            currentOffset++;

                            int stringIndex = BitConverter.ToInt32(Data, currentOffset);
                            instruction.Arguments.Add(strings[stringIndex]);
                            currentOffset += 4;
                            break;
                        }
                    case 0x25:
                        {
                            instruction.Type = "FlagCheck";
                            currentOffset++; //The first byte here it really tells us the operand used here, but
                            //since the operands are only used in this type of instruction, we can set it immediately

                            switch (Data[currentOffset])
                            {
                                case 0x3F:
                                    instruction.Arguments.Add("g");
                                    break;
                                case 0x3E:
                                    instruction.Arguments.Add("f");
                                    break;
                                case 0x42:
                                    instruction.Arguments.Add("c");
                                    break;
                                case 0x43:
                                    //Check to see if the code is done correctly, because when the flag is not supposed
                                    //to have any kind of special flag, it has this opcode
                                    break;
                                default:
                                    throw new Exception("Unknown flag check value: " + Data[currentOffset]);
                            }
                            currentOffset++;

                            //The first argument is the flag, and we have to ensure that it is not a special flag (as checked before)
                            if (instruction.Arguments.Count == 0)
                            {
                                instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset)));
                            }
                            else
                            {
                                instruction.Arguments[0] = instruction.Arguments[0] + 
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset));
                            }
                            currentOffset += 2;

                            instruction.Arguments.Add("=="); //or =

                            //The third argument is the value to compare against
                            instruction.Arguments.Add(
                                Convert.ToString(BitConverter.ToInt32(Data, currentOffset)));
                            currentOffset += 4;

                            int labelIndex = BitConverter.ToInt32(Data, currentOffset);
                            Label label = DecrypterHelper.CreateLabel(labels, labelIndex);
                            if (label.Name == "Label_" + labels.Count()) //If the label is new, we add it to the list of labels
                            {
                                labels.Add(label);
                            }
                            instruction.Arguments.Add(label.Name);
                            currentOffset += 4;

                            break;
                        }
                    case 0x26:
                        {
                            instruction.Type = "FlagCheck";
                            currentOffset++; //The first byte here it really tells us the operand used here, but
                            //since the operands are only used in this type of instruction, we can set it immediately

                            switch (Data[currentOffset])
                            {
                                case 0x3F:
                                    instruction.Arguments.Add("g");
                                    break;
                                case 0x3E:
                                    instruction.Arguments.Add("f");
                                    break;
                                case 0x42:
                                    instruction.Arguments.Add("c");
                                    break;
                                case 0x43:
                                    //Check to see if the code is done correctly, because when the flag is not supposed
                                    //to have any kind of special flag, it has this opcode
                                    break;
                                default:
                                    throw new Exception("Unknown flag check value: " + Data[currentOffset]);
                            }
                            currentOffset++;

                            //The first argument is the flag, and we have to ensure that it is not a special flag (as checked before)
                            if (instruction.Arguments.Count == 0)
                            {
                                instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset)));
                            }
                            else
                            {
                                instruction.Arguments[0] = instruction.Arguments[0] +
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset));
                            }
                            currentOffset += 2;

                            instruction.Arguments.Add("!=");

                            instruction.Arguments.Add(
                                Convert.ToString(BitConverter.ToInt32(Data, currentOffset)));
                            currentOffset += 4;

                            int labelIndex = BitConverter.ToInt32(Data, currentOffset);
                            Label label = DecrypterHelper.CreateLabel(labels, labelIndex);
                            if (label.Name == "Label_" + labels.Count()) //If the label is new, we add it to the list of labels
                            {
                                labels.Add(label);
                            }
                            instruction.Arguments.Add(label.Name);
                            currentOffset += 4;

                            break;
                        }
                    case 0x27:
                        {
                            instruction.Type = "FlagCheck";
                            currentOffset++; //The first byte here it really tells us the operand used here, but
                            //since the operands are only used in this type of instruction, we can set it immediately

                            switch (Data[currentOffset])
                            {
                                case 0x3F:
                                    instruction.Arguments.Add("g");
                                    break;
                                case 0x3E:
                                    instruction.Arguments.Add("f");
                                    break;
                                case 0x42:
                                    instruction.Arguments.Add("c");
                                    break;
                                case 0x43:
                                    //Check to see if the code is done correctly, because when the flag is not supposed
                                    //to have any kind of special flag, it has this opcode
                                    break;
                                default:
                                    throw new Exception("Unknown flag check value: " + Data[currentOffset]);
                            }
                            currentOffset++;

                            //The first argument is the flag, and we have to ensure that it is not a special flag (as checked before)
                            if (instruction.Arguments.Count == 0)
                            {
                                instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset)));
                            }
                            else
                            {
                                instruction.Arguments[0] = instruction.Arguments[0] +
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset));
                            }
                            currentOffset += 2;

                            instruction.Arguments.Add("<");

                            instruction.Arguments.Add(
                                Convert.ToString(BitConverter.ToInt32(Data, currentOffset)));
                            currentOffset += 4;

                            int labelIndex = BitConverter.ToInt32(Data, currentOffset);
                            Label label = DecrypterHelper.CreateLabel(labels, labelIndex);
                            if (label.Name == "Label_" + labels.Count()) //If the label is new, we add it to the list of labels
                            {
                                labels.Add(label);
                            }
                            instruction.Arguments.Add(label.Name);
                            currentOffset += 4;

                            break;
                        }
                    case 0x28:
                        {
                            instruction.Type = "FlagCheck";
                            currentOffset++; //The first byte here it really tells us the operand used here, but
                            //since the operands are only used in this type of instruction, we can set it immediately

                            switch (Data[currentOffset])
                            {
                                case 0x3F:
                                    instruction.Arguments.Add("g");
                                    break;
                                case 0x3E:
                                    instruction.Arguments.Add("f");
                                    break;
                                case 0x42:
                                    instruction.Arguments.Add("c");
                                    break;
                                case 0x43:
                                    //Check to see if the code is done correctly, because when the flag is not supposed
                                    //to have any kind of special flag, it has this opcode
                                    break;
                                default:
                                    throw new Exception("Unknown flag check value: " + Data[currentOffset]);
                            }
                            currentOffset++;

                            //The first argument is the flag, and we have to ensure that it is not a special flag (as checked before)
                            if (instruction.Arguments.Count == 0)
                            {
                                instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset)));
                            }
                            else
                            {
                                instruction.Arguments[0] = instruction.Arguments[0] +
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset));
                            }
                            currentOffset += 2;

                            instruction.Arguments.Add(">");

                            instruction.Arguments.Add(
                                Convert.ToString(BitConverter.ToInt32(Data, currentOffset)));
                            currentOffset += 4;

                            int labelIndex = BitConverter.ToInt32(Data, currentOffset);
                            Label label = DecrypterHelper.CreateLabel(labels, labelIndex);
                            if (label.Name == "Label_" + labels.Count()) //If the label is new, we add it to the list of labels
                            {
                                labels.Add(label);
                            }
                            instruction.Arguments.Add(label.Name);
                            currentOffset += 4;

                            break;
                        }
                    case 0x29:
                        {
                            instruction.Type = "FlagCheck";
                            currentOffset++; //The first byte here it really tells us the operand used here, but
                            //since the operands are only used in this type of instruction, we can set it immediately

                            switch (Data[currentOffset])
                            {
                                case 0x3F:
                                    instruction.Arguments.Add("g");
                                    break;
                                case 0x3E:
                                    instruction.Arguments.Add("f");
                                    break;
                                case 0x42:
                                    instruction.Arguments.Add("c");
                                    break;
                                case 0x43:
                                    //Check to see if the code is done correctly, because when the flag is not supposed
                                    //to have any kind of special flag, it has this opcode
                                    break;
                                default:
                                    throw new Exception("Unknown flag check value: " + Data[currentOffset]);
                            }
                            currentOffset++;

                            //The first argument is the flag, and we have to ensure that it is not a special flag (as checked before)
                            if (instruction.Arguments.Count == 0)
                            {
                                instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset)));
                            }
                            else
                            {
                                instruction.Arguments[0] = instruction.Arguments[0] +
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset));
                            }
                            currentOffset += 2;

                            instruction.Arguments.Add("<=");

                            instruction.Arguments.Add(
                                Convert.ToString(BitConverter.ToInt32(Data, currentOffset)));
                            currentOffset += 4;

                            int labelIndex = BitConverter.ToInt32(Data, currentOffset);
                            Label label = DecrypterHelper.CreateLabel(labels, labelIndex);
                            if (label.Name == "Label_" + labels.Count()) //If the label is new, we add it to the list of labels
                            {
                                labels.Add(label);
                            }
                            instruction.Arguments.Add(label.Name);
                            currentOffset += 4;

                            break;
                        }
                    case 0x2A:
                        {
                            instruction.Type = "FlagCheck";
                            currentOffset++; //The first byte here it really tells us the operand used here, but
                            //since the operands are only used in this type of instruction, we can set it immediately

                            switch(Data[currentOffset])
                                {
                                case 0x3F:
                                    instruction.Arguments.Add("g");
                                    break;
                                case 0x3E:
                                    instruction.Arguments.Add("f");
                                    break;
                                case 0x42:
                                    instruction.Arguments.Add("c");
                                    break;
                                case 0x43:
                                    //Check to see if the code is done correctly, because when the flag is not supposed
                                    //to have any kind of special flag, it has this opcode
                                    break;
                                default:
                                    throw new Exception("Unknown flag check value: " + Data[currentOffset]);
                            }
                            currentOffset++;

                            //The first argument is the flag, and we have to ensure that it is not a special flag (as checked before)
                            if (instruction.Arguments.Count == 0)
                            {
                                instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset)));
                            }
                            else
                            {
                                instruction.Arguments[0] = instruction.Arguments[0] +
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset));
                            }
                            currentOffset += 2;

                            instruction.Arguments.Add(">=");

                            instruction.Arguments.Add(
                                Convert.ToString(BitConverter.ToInt32(Data, currentOffset)));
                            currentOffset += 4;

                            int labelIndex = BitConverter.ToInt32(Data, currentOffset);
                            Label label = DecrypterHelper.CreateLabel(labels, labelIndex);
                            if (label.Name == "Label_" + labels.Count()) //If the label is new, we add it to the list of labels
                            {
                                labels.Add(label);
                            }
                            instruction.Arguments.Add(label.Name);
                            currentOffset += 4;

                            break;
                        }
                    case 0x2B:
                        {
                            instruction.Type = "FlagCheckGosub"; //or FlagCheckG
                            currentOffset++; //The first byte here it really tells us the operand used here, but
                            //since the operands are only used in this type of instruction, we can set it immediately

                            switch (Data[currentOffset])
                            {
                                case 0x3F:
                                    instruction.Arguments.Add("g");
                                    break;
                                case 0x3E:
                                    instruction.Arguments.Add("f");
                                    break;
                                case 0x42:
                                    instruction.Arguments.Add("c");
                                    break;
                                case 0x43:
                                    //Check to see if the code is done correctly, because when the flag is not supposed
                                    //to have any kind of special flag, it has this opcode
                                    break;
                                default:
                                    throw new Exception("Unknown flag check value: " + Data[currentOffset]);
                            }
                            currentOffset++;

                            //The first argument is the flag, and we have to ensure that it is not a special flag (as checked before)
                            if (instruction.Arguments.Count == 0)
                            {
                                instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset)));
                            }
                            else
                            {
                                instruction.Arguments[0] = instruction.Arguments[0] +
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset));
                            }
                            currentOffset += 2;

                            instruction.Arguments.Add("=="); //or =

                            instruction.Arguments.Add(
                                Convert.ToString(BitConverter.ToInt32(Data, currentOffset)));
                            currentOffset += 4;

                            int labelIndex = BitConverter.ToInt32(Data, currentOffset);
                            Label label = DecrypterHelper.CreateLabel(labels, labelIndex);
                            if (label.Name == "Label_" + labels.Count()) //If the label is new, we add it to the list of labels
                            {
                                labels.Add(label);
                            }
                            instruction.Arguments.Add(label.Name);
                            currentOffset += 4;

                            break;
                        }
                    case 0x2C:
                        {
                            instruction.Type = "FlagCheckGosub"; //or FlagCheckG
                            currentOffset++; //The first byte here it really tells us the operand used here, but
                            //since the operands are only used in this type of instruction, we can set it immediately

                            switch (Data[currentOffset])
                            {
                                case 0x3F:
                                    instruction.Arguments.Add("g");
                                    break;
                                case 0x3E:
                                    instruction.Arguments.Add("f");
                                    break;
                                case 0x42:
                                    instruction.Arguments.Add("c");
                                    break;
                                case 0x43:
                                    //Check to see if the code is done correctly, because when the flag is not supposed
                                    //to have any kind of special flag, it has this opcode
                                    break;
                                default:
                                    throw new Exception("Unknown flag check value: " + Data[currentOffset]);
                            }
                            currentOffset++;

                            //The first argument is the flag, and we have to ensure that it is not a special flag (as checked before)
                            if (instruction.Arguments.Count == 0)
                            {
                                instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset)));
                            }
                            else
                            {
                                instruction.Arguments[0] = instruction.Arguments[0] +
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset));
                            }
                            currentOffset += 2;

                            instruction.Arguments.Add("!=");

                            instruction.Arguments.Add(
                                Convert.ToString(BitConverter.ToInt32(Data, currentOffset)));
                            currentOffset += 4;

                            int labelIndex = BitConverter.ToInt32(Data, currentOffset);
                            Label label = DecrypterHelper.CreateLabel(labels, labelIndex);
                            if (label.Name == "Label_" + labels.Count()) //If the label is new, we add it to the list of labels
                            {
                                labels.Add(label);
                            }
                            instruction.Arguments.Add(label.Name);
                            currentOffset += 4;

                            break;
                        }
                    case 0x2D:
                        {
                            instruction.Type = "FlagCheckGosub"; //or FlagCheckG
                            currentOffset++; //The first byte here it really tells us the operand used here, but
                            //since the operands are only used in this type of instruction, we can set it immediately

                            switch (Data[currentOffset])
                            {
                                case 0x3F:
                                    instruction.Arguments.Add("g");
                                    break;
                                case 0x3E:
                                    instruction.Arguments.Add("f");
                                    break;
                                case 0x42:
                                    instruction.Arguments.Add("c");
                                    break;
                                case 0x43:
                                    //Check to see if the code is done correctly, because when the flag is not supposed
                                    //to have any kind of special flag, it has this opcode
                                    break;
                                default:
                                    throw new Exception("Unknown flag check value: " + Data[currentOffset]);
                            }
                            currentOffset++;

                            //The first argument is the flag, and we have to ensure that it is not a special flag (as checked before)
                            if (instruction.Arguments.Count == 0)
                            {
                                instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset)));
                            }
                            else
                            {
                                instruction.Arguments[0] = instruction.Arguments[0] +
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset));
                            }
                            currentOffset += 2;

                            instruction.Arguments.Add("<");

                            instruction.Arguments.Add(
                                Convert.ToString(BitConverter.ToInt32(Data, currentOffset)));
                            currentOffset += 4;

                            int labelIndex = BitConverter.ToInt32(Data, currentOffset);
                            Label label = DecrypterHelper.CreateLabel(labels, labelIndex);
                            if (label.Name == "Label_" + labels.Count()) //If the label is new, we add it to the list of labels
                            {
                                labels.Add(label);
                            }
                            instruction.Arguments.Add(label.Name);
                            currentOffset += 4;

                            break;
                        }
                    case 0x2E:
                        {
                            instruction.Type = "FlagCheckGosub"; //or FlagCheckG
                            currentOffset++; //The first byte here it really tells us the operand used here, but
                            //since the operands are only used in this type of instruction, we can set it immediately

                            switch (Data[currentOffset])
                            {
                                case 0x3F:
                                    instruction.Arguments.Add("g");
                                    break;
                                case 0x3E:
                                    instruction.Arguments.Add("f");
                                    break;
                                case 0x42:
                                    instruction.Arguments.Add("c");
                                    break;
                                case 0x43:
                                    //Check to see if the code is done correctly, because when the flag is not supposed
                                    //to have any kind of special flag, it has this opcode
                                    break;
                                default:
                                    throw new Exception("Unknown flag check value: " + Data[currentOffset]);
                            }
                            currentOffset++;

                            //The first argument is the flag, and we have to ensure that it is not a special flag (as checked before)
                            if (instruction.Arguments.Count == 0)
                            {
                                instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset)));
                            }
                            else
                            {
                                instruction.Arguments[0] = instruction.Arguments[0] +
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset));
                            }
                            currentOffset += 2;

                            instruction.Arguments.Add(">");

                            instruction.Arguments.Add(
                                Convert.ToString(BitConverter.ToInt32(Data, currentOffset)));
                            currentOffset += 4;

                            int labelIndex = BitConverter.ToInt32(Data, currentOffset);
                            Label label = DecrypterHelper.CreateLabel(labels, labelIndex);
                            if (label.Name == "Label_" + labels.Count()) //If the label is new, we add it to the list of labels
                            {
                                labels.Add(label);
                            }
                            instruction.Arguments.Add(label.Name);
                            currentOffset += 4;

                            break;
                        }
                    case 0x2F:
                        {
                            instruction.Type = "FlagCheckGosub"; //or FlagCheckG
                            currentOffset++; //The first byte here it really tells us the operand used here, but
                            //since the operands are only used in this type of instruction, we can set it immediately

                            switch (Data[currentOffset])
                            {
                                case 0x3F:
                                    instruction.Arguments.Add("g");
                                    break;
                                case 0x3E:
                                    instruction.Arguments.Add("f");
                                    break;
                                case 0x42:
                                    instruction.Arguments.Add("c");
                                    break;
                                case 0x43:
                                    //Check to see if the code is done correctly, because when the flag is not supposed
                                    //to have any kind of special flag, it has this opcode
                                    break;
                                default:
                                    throw new Exception("Unknown flag check value: " + Data[currentOffset]);
                            }
                            currentOffset++;

                            //The first argument is the flag, and we have to ensure that it is not a special flag (as checked before)
                            if (instruction.Arguments.Count == 0)
                            {
                                instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset)));
                            }
                            else
                            {
                                instruction.Arguments[0] = instruction.Arguments[0] +
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset));
                            }
                            currentOffset += 2;

                            instruction.Arguments.Add("<=");

                            instruction.Arguments.Add(
                                Convert.ToString(BitConverter.ToInt32(Data, currentOffset)));
                            currentOffset += 4;

                            int labelIndex = BitConverter.ToInt32(Data, currentOffset);
                            Label label = DecrypterHelper.CreateLabel(labels, labelIndex);
                            if (label.Name == "Label_" + labels.Count()) //If the label is new, we add it to the list of labels
                            {
                                labels.Add(label);
                            }
                            instruction.Arguments.Add(label.Name);
                            currentOffset += 4;

                            break;
                        }
                    case 0x30:
                        {
                            instruction.Type = "FlagCheckGosub"; //or FlagCheckG
                            currentOffset++; //The first byte here it really tells us the operand used here, but
                            //since the operands are only used in this type of instruction, we can set it immediately

                            switch (Data[currentOffset])
                            {
                                case 0x3F:
                                    instruction.Arguments.Add("g");
                                    break;
                                case 0x3E:
                                    instruction.Arguments.Add("f");
                                    break;
                                case 0x42:
                                    instruction.Arguments.Add("c");
                                    break;
                                case 0x43:
                                    //Check to see if the code is done correctly, because when the flag is not supposed
                                    //to have any kind of special flag, it has this opcode
                                    break;
                                default:
                                    throw new Exception("Unknown flag check value: " + Data[currentOffset]);
                            }
                            currentOffset++;

                            //The first argument is the flag, and we have to ensure that it is not a special flag (as checked before)
                            if (instruction.Arguments.Count == 0)
                            {
                                instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset)));
                            }
                            else
                            {
                                instruction.Arguments[0] = instruction.Arguments[0] +
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset));
                            }
                            currentOffset += 2;

                            instruction.Arguments.Add(">=");

                            instruction.Arguments.Add(
                                Convert.ToString(BitConverter.ToInt32(Data, currentOffset)));
                            currentOffset += 4;

                            int labelIndex = BitConverter.ToInt32(Data, currentOffset);
                            Label label = DecrypterHelper.CreateLabel(labels, labelIndex);
                            if (label.Name == "Label_" + labels.Count()) //If the label is new, we add it to the list of labels
                            {
                                labels.Add(label);
                            }
                            instruction.Arguments.Add(label.Name);
                            currentOffset += 4;

                            break;
                        }
                    case 0x31:
                        {
                            instruction.Type = "F2FAdd";
                            currentOffset++;

                            for (int currentArgument = 0; currentArgument < 2; currentArgument++)
                            {
                                byte[] argumentArray = new byte[5];
                                Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                                string[] argument = DecrypterHelper.GetParameters(argumentArray);
                                instruction.Arguments.Add(argument[0]);
                                currentOffset += Convert.ToInt32(argument[1]);
                            }
                            break;
                        }
                    case 0x32:
                        {
                            instruction.Type = "F2FSub";
                            currentOffset++;

                            for (int currentArgument = 0; currentArgument < 2; currentArgument++)
                            {
                                byte[] argumentArray = new byte[5];
                                Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                                string[] argument = DecrypterHelper.GetParameters(argumentArray);
                                instruction.Arguments.Add(argument[0]);
                                currentOffset += Convert.ToInt32(argument[1]);
                            }
                            break;
                        }
                    case 0x33:
                        {
                            instruction.Type = "F2FMul";
                            currentOffset++;

                            for (int currentArgument = 0; currentArgument < 2; currentArgument++)
                            {
                                byte[] argumentArray = new byte[5];
                                Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                                string[] argument = DecrypterHelper.GetParameters(argumentArray);
                                instruction.Arguments.Add(argument[0]);
                                currentOffset += Convert.ToInt32(argument[1]);
                            }
                            break;
                        }
                    case 0x34:
                        {
                            instruction.Type = "F2FDiv";
                            currentOffset++;

                            for (int currentArgument = 0; currentArgument < 2; currentArgument++)
                            {
                                byte[] argumentArray = new byte[5];
                                Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                                string[] argument = DecrypterHelper.GetParameters(argumentArray);
                                instruction.Arguments.Add(argument[0]);
                                currentOffset += Convert.ToInt32(argument[1]);
                            }
                            break;
                        }
                    case 0x35:
                        {
                            instruction.Type = "F2FExc";
                            currentOffset++;

                            for (int currentArgument = 0; currentArgument < 2; currentArgument++)
                            {
                                byte[] argumentArray = new byte[5];
                                Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                                string[] argument = DecrypterHelper.GetParameters(argumentArray);
                                instruction.Arguments.Add(argument[0]);
                                currentOffset += Convert.ToInt32(argument[1]);
                            }
                            break;
                        }
                    case 0x36:
                        {
                            instruction.Type = "F2FSet"; //There is another unknown opcode related to the unknown 0x1E opcode, but since that one cannot even be understood with a compiled script, it will be ignored
                            currentOffset++;

                            for (int currentArgument = 0; currentArgument < 2; currentArgument++)
                            {
                                byte[] argumentArray = new byte[5];
                                Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                                string[] argument = DecrypterHelper.GetParameters(argumentArray);
                                instruction.Arguments.Add(argument[0]);
                                currentOffset += Convert.ToInt32(argument[1]);
                            }
                            break;
                        }
                    case 0x37:
                        {
                            instruction.Type = "F2FRand";
                            currentOffset++;

                            byte[] argumentArray = new byte[5];
                            Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                            string[] argument = DecrypterHelper.GetParameters(argumentArray);
                            instruction.Arguments.Add(argument[0]);
                            currentOffset += Convert.ToInt32(argument[1]);

                            instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt32(Data, currentOffset)));

                            argumentArray.Initialize();
                            Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                            argument = DecrypterHelper.GetParameters(argumentArray);
                            instruction.Arguments.Add(argument[0]);
                            currentOffset += Convert.ToInt32(argument[1]);

                            break;
                        }
                    case 0x38:
                        {
                            instruction.Type = "F2FCheck";
                            currentOffset++; //The first byte here it really tells us the operand used here, but
                            //since the operands are only used in this type of instruction, we can set it immediately

                            //We obtain the first flag
                            switch (Data[currentOffset])
                            {
                                case 0x3F:
                                    instruction.Arguments.Add("g");
                                    break;
                                case 0x3E:
                                    //Check to see if the code is done correctly, because when the flag is not supposed
                                    //to have any kind of special flag, it has this opcode
                                    break;
                                default:
                                    throw new Exception("Unknown flag check value: " + Data[currentOffset]);
                            }
                            currentOffset++;

                            //The first argument is the flag, and we have to ensure that it is not a special flag (as checked before)
                            if (instruction.Arguments.Count == 0)
                            {
                                instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset)));
                            }
                            else
                            {
                                instruction.Arguments[0] = instruction.Arguments[0] +
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset));
                            }
                            currentOffset += 2;

                            //We add the comparator
                            instruction.Arguments.Add("=="); //or =

                            bool addedFlag = false;

                            //Now we do the second flag
                            switch (Data[currentOffset])
                            {
                                case 0x3F:
                                    instruction.Arguments.Add("g");
                                    addedFlag = true;
                                    break;
                                case 0x3E:
                                    //Check to see if the code is done correctly, because when the flag is not supposed
                                    //to have any kind of special flag, it has this opcode
                                    break;
                                default:
                                    throw new Exception("Unknown flag check value: " + Data[currentOffset]);
                            }
                            currentOffset++;

                            //The first argument is the flag, and we have to ensure that it is not a special flag (as checked before)
                            if (!addedFlag)
                            {
                                instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset)));
                            }
                            else
                            {
                                instruction.Arguments[2] = instruction.Arguments[2] +
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset));
                            }
                            currentOffset += 2;

                            int labelIndex = BitConverter.ToInt32(Data, currentOffset);
                            Label label = DecrypterHelper.CreateLabel(labels, labelIndex);
                            if (label.Name == "Label_" + labels.Count()) //If the label is new, we add it to the list of labels
                            {
                                labels.Add(label);
                            }
                            instruction.Arguments.Add(label.Name);
                            currentOffset += 4;

                            break;
                        }
                    case 0x39:
                        {
                            instruction.Type = "F2FCheck";
                            currentOffset++; //The first byte here it really tells us the operand used here, but
                            //since the operands are only used in this type of instruction, we can set it immediately

                            //We obtain the first flag
                            switch (Data[currentOffset])
                            {
                                case 0x3F:
                                    instruction.Arguments.Add("g");
                                    break;
                                case 0x3E:
                                    //Check to see if the code is done correctly, because when the flag is not supposed
                                    //to have any kind of special flag, it has this opcode
                                    break;
                                default:
                                    throw new Exception("Unknown flag check value: " + Data[currentOffset]);
                            }
                            currentOffset++;

                            //The first argument is the flag, and we have to ensure that it is not a special flag (as checked before)
                            if (instruction.Arguments.Count == 0)
                            {
                                instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset)));
                            }
                            else
                            {
                                instruction.Arguments[0] = instruction.Arguments[0] +
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset));
                            }
                            currentOffset += 2;

                            //We add the comparator
                            instruction.Arguments.Add("!=");

                            bool addedFlag = false;

                            //Now we do the second flag
                            switch (Data[currentOffset])
                            {
                                case 0x3F:
                                    instruction.Arguments.Add("g");
                                    addedFlag = true;
                                    break;
                                case 0x3E:
                                    //Check to see if the code is done correctly, because when the flag is not supposed
                                    //to have any kind of special flag, it has this opcode
                                    break;
                                default:
                                    throw new Exception("Unknown flag check value: " + Data[currentOffset]);
                            }
                            currentOffset++;

                            //The first argument is the flag, and we have to ensure that it is not a special flag (as checked before)
                            if (!addedFlag)
                            {
                                instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset)));
                            }
                            else
                            {
                                instruction.Arguments[2] = instruction.Arguments[2] +
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset));
                            }
                            currentOffset += 2;

                            int labelIndex = BitConverter.ToInt32(Data, currentOffset);
                            Label label = DecrypterHelper.CreateLabel(labels, labelIndex);
                            if (label.Name == "Label_" + labels.Count()) //If the label is new, we add it to the list of labels
                            {
                                labels.Add(label);
                            }
                            instruction.Arguments.Add(label.Name);
                            currentOffset += 4;

                            break;
                        }
                    case 0x3A:
                        {
                            instruction.Type = "F2FCheck";
                            currentOffset++; //The first byte here it really tells us the operand used here, but
                            //since the operands are only used in this type of instruction, we can set it immediately

                            //We obtain the first flag
                            switch (Data[currentOffset])
                            {
                                case 0x3F:
                                    instruction.Arguments.Add("g");
                                    break;
                                case 0x3E:
                                    //Check to see if the code is done correctly, because when the flag is not supposed
                                    //to have any kind of special flag, it has this opcode
                                    break;
                                default:
                                    throw new Exception("Unknown flag check value: " + Data[currentOffset]);
                            }
                            currentOffset++;

                            //The first argument is the flag, and we have to ensure that it is not a special flag (as checked before)
                            if (instruction.Arguments.Count == 0)
                            {
                                instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset)));
                            }
                            else
                            {
                                instruction.Arguments[0] = instruction.Arguments[0] +
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset));
                            }
                            currentOffset += 2;

                            //We add the comparator
                            instruction.Arguments.Add("<");

                            bool addedFlag = false;

                            //Now we do the second flag
                            switch (Data[currentOffset])
                            {
                                case 0x3F:
                                    instruction.Arguments.Add("g");
                                    addedFlag = true;
                                    break;
                                case 0x3E:
                                    //Check to see if the code is done correctly, because when the flag is not supposed
                                    //to have any kind of special flag, it has this opcode
                                    break;
                                default:
                                    throw new Exception("Unknown flag check value: " + Data[currentOffset]);
                            }
                            currentOffset++;

                            //The first argument is the flag, and we have to ensure that it is not a special flag (as checked before)
                            if (!addedFlag)
                            {
                                instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset)));
                            }
                            else
                            {
                                instruction.Arguments[2] = instruction.Arguments[2] +
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset));
                            }
                            currentOffset += 2;

                            int labelIndex = BitConverter.ToInt32(Data, currentOffset);
                            Label label = DecrypterHelper.CreateLabel(labels, labelIndex);
                            if (label.Name == "Label_" + labels.Count()) //If the label is new, we add it to the list of labels
                            {
                                labels.Add(label);
                            }
                            instruction.Arguments.Add(label.Name);
                            currentOffset += 4;

                            break;
                        }
                    case 0x3B:
                        {
                            instruction.Type = "F2FCheck";
                            currentOffset++; //The first byte here it really tells us the operand used here, but
                            //since the operands are only used in this type of instruction, we can set it immediately

                            //We obtain the first flag
                            switch (Data[currentOffset])
                            {
                                case 0x3F:
                                    instruction.Arguments.Add("g");
                                    break;
                                case 0x3E:
                                    //Check to see if the code is done correctly, because when the flag is not supposed
                                    //to have any kind of special flag, it has this opcode
                                    break;
                                default:
                                    throw new Exception("Unknown flag check value: " + Data[currentOffset]);
                            }
                            currentOffset++;

                            //The first argument is the flag, and we have to ensure that it is not a special flag (as checked before)
                            if (instruction.Arguments.Count == 0)
                            {
                                instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset)));
                            }
                            else
                            {
                                instruction.Arguments[0] = instruction.Arguments[0] +
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset));
                            }
                            currentOffset += 2;

                            //We add the comparator
                            instruction.Arguments.Add(">");

                            bool addedFlag = false;

                            //Now we do the second flag
                            switch (Data[currentOffset])
                            {
                                case 0x3F:
                                    instruction.Arguments.Add("g");
                                    addedFlag = true;
                                    break;
                                case 0x3E:
                                    //Check to see if the code is done correctly, because when the flag is not supposed
                                    //to have any kind of special flag, it has this opcode
                                    break;
                                default:
                                    throw new Exception("Unknown flag check value: " + Data[currentOffset]);
                            }
                            currentOffset++;

                            //The first argument is the flag, and we have to ensure that it is not a special flag (as checked before)
                            if (!addedFlag)
                            {
                                instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset)));
                            }
                            else
                            {
                                instruction.Arguments[2] = instruction.Arguments[2] +
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset));
                            }
                            currentOffset += 2;

                            int labelIndex = BitConverter.ToInt32(Data, currentOffset);
                            Label label = DecrypterHelper.CreateLabel(labels, labelIndex);
                            if (label.Name == "Label_" + labels.Count()) //If the label is new, we add it to the list of labels
                            {
                                labels.Add(label);
                            }
                            instruction.Arguments.Add(label.Name);
                            currentOffset += 4;

                            break;
                        }
                    case 0x3C:
                        {
                            instruction.Type = "F2FCheck";
                            currentOffset++; //The first byte here it really tells us the operand used here, but
                            //since the operands are only used in this type of instruction, we can set it immediately

                            //We obtain the first flag
                            switch (Data[currentOffset])
                            {
                                case 0x3F:
                                    instruction.Arguments.Add("g");
                                    break;
                                case 0x3E:
                                    //Check to see if the code is done correctly, because when the flag is not supposed
                                    //to have any kind of special flag, it has this opcode
                                    break;
                                default:
                                    throw new Exception("Unknown flag check value: " + Data[currentOffset]);
                            }
                            currentOffset++;

                            //The first argument is the flag, and we have to ensure that it is not a special flag (as checked before)
                            if (instruction.Arguments.Count == 0)
                            {
                                instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset)));
                            }
                            else
                            {
                                instruction.Arguments[0] = instruction.Arguments[0] +
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset));
                            }
                            currentOffset += 2;

                            //We add the comparator
                            instruction.Arguments.Add("<=");

                            bool addedFlag = false;

                            //Now we do the second flag
                            switch (Data[currentOffset])
                            {
                                case 0x3F:
                                    instruction.Arguments.Add("g");
                                    addedFlag = true;
                                    break;
                                case 0x3E:
                                    //Check to see if the code is done correctly, because when the flag is not supposed
                                    //to have any kind of special flag, it has this opcode
                                    break;
                                default:
                                    throw new Exception("Unknown flag check value: " + Data[currentOffset]);
                            }
                            currentOffset++;

                            //The first argument is the flag, and we have to ensure that it is not a special flag (as checked before)
                            if (!addedFlag)
                            {
                                instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset)));
                            }
                            else
                            {
                                instruction.Arguments[2] = instruction.Arguments[2] +
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset));
                            }
                            currentOffset += 2;

                            int labelIndex = BitConverter.ToInt32(Data, currentOffset);
                            Label label = DecrypterHelper.CreateLabel(labels, labelIndex);
                            if (label.Name == "Label_" + labels.Count()) //If the label is new, we add it to the list of labels
                            {
                                labels.Add(label);
                            }
                            instruction.Arguments.Add(label.Name);
                            currentOffset += 4;

                            break;
                        }
                    case 0x3D:
                        {
                            instruction.Type = "F2FCheck";
                            currentOffset++; //The first byte here it really tells us the operand used here, but
                            //since the operands are only used in this type of instruction, we can set it immediately

                            //We obtain the first flag
                            switch (Data[currentOffset])
                            {
                                case 0x3F:
                                    instruction.Arguments.Add("g");
                                    break;
                                case 0x3E:
                                    //Check to see if the code is done correctly, because when the flag is not supposed
                                    //to have any kind of special flag, it has this opcode
                                    break;
                                default:
                                    throw new Exception("Unknown flag check value: " + Data[currentOffset]);
                            }
                            currentOffset++;

                            //The first argument is the flag, and we have to ensure that it is not a special flag (as checked before)
                            if (instruction.Arguments.Count == 0)
                            {
                                instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset)));
                            }
                            else
                            {
                                instruction.Arguments[0] = instruction.Arguments[0] +
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset));
                            }
                            currentOffset += 2;

                            //We add the comparator
                            instruction.Arguments.Add(">=");

                            bool addedFlag = false;

                            //Now we do the second flag
                            switch (Data[currentOffset])
                            {
                                case 0x3F:
                                    instruction.Arguments.Add("g");
                                    addedFlag = true;
                                    break;
                                case 0x3E:
                                    //Check to see if the code is done correctly, because when the flag is not supposed
                                    //to have any kind of special flag, it has this opcode
                                    break;
                                default:
                                    throw new Exception("Unknown flag check value: " + Data[currentOffset]);
                            }
                            currentOffset++;

                            //The first argument is the flag, and we have to ensure that it is not a special flag (as checked before)
                            if (!addedFlag)
                            {
                                instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset)));
                            }
                            else
                            {
                                instruction.Arguments[2] = instruction.Arguments[2] +
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset));
                            }
                            currentOffset += 2;

                            int labelIndex = BitConverter.ToInt32(Data, currentOffset);
                            Label label = DecrypterHelper.CreateLabel(labels, labelIndex);
                            if (label.Name == "Label_" + labels.Count()) //If the label is new, we add it to the list of labels
                            {
                                labels.Add(label);
                            }
                            instruction.Arguments.Add(label.Name);
                            currentOffset += 4;

                            break;
                        }
                    case 0x46:
                        {
                            instruction.Type = "CgFull"; //or CF
                            currentOffset++;

                            int stringIndex = BitConverter.ToInt32(Data, currentOffset);
                            instruction.Arguments.Add(strings[stringIndex]);
                            currentOffset += 4;
                            break;
                        }
                    case 0x47:
                        {
                            instruction.Type = "CgFullClear"; //or CFC
                            currentOffset++;
                            break;
                        }
                    case 0x48:
                        {
                            instruction.Type = "CgMid"; //or CM
                            currentOffset++;

                            instruction.Arguments.Add(
                                Convert.ToString(Data[currentOffset]));
                            currentOffset++;

                            instruction.Arguments.Add(
                                Convert.ToString(BitConverter.ToInt32(Data, currentOffset)));
                            currentOffset += 4;

                            int stringIndex = BitConverter.ToInt32(Data, currentOffset);
                            instruction.Arguments.Add(strings[stringIndex]);
                            currentOffset += 4;
                            break;
                        }
                    case 0x49:
                        {
                            instruction.Type = "CgMidAuto";
                            currentOffset++;

                            instruction.Arguments.Add(
                                Convert.ToString(Data[currentOffset]));
                            currentOffset++;

                            int stringIndex = BitConverter.ToInt32(Data, currentOffset);
                            instruction.Arguments.Add(strings[stringIndex]);
                            currentOffset += 4;
                            break;
                        }
                    case 0x4A:
                        {
                            instruction.Type = "CgMidMove";
                            currentOffset++;

                            instruction.Arguments.Add(
                                    Convert.ToString(Data[currentOffset]));
                            currentOffset++;

                            instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt32(Data, currentOffset)));
                            currentOffset += 4;

                            break;
                        }
                    case 0x4B:
                        {
                            instruction.Type = "CgMidXY"; //or CMXY
                            currentOffset++;

                            instruction.Arguments.Add(
                                    Convert.ToString(Data[currentOffset]));
                            currentOffset++;

                            for (int currentArgument = 0; currentArgument < 2; currentArgument++)
                            {
                                instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt32(Data, currentOffset)));
                                currentOffset += 4;
                            }

                            break;
                        }
                    case 0x4C:
                        {
                            instruction.Type = "GetMiddlePos"; //or GetMidPos, GMPos
                            currentOffset++;

                            instruction.Arguments.Add(
                                   Convert.ToString(Data[currentOffset]));
                            currentOffset++;

                            byte[] argumentArray = new byte[5];
                            Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                            string[] argument = DecrypterHelper.GetParameters(argumentArray);
                            instruction.Arguments.Add(argument[0]);
                            currentOffset += Convert.ToInt32(argument[1]);

                            break;
                        }
                    case 0x4D:
                        {
                            if (Data[currentOffset + 1] == 0x00 && Data[currentOffset + 2] == 0x4D &&
                                Data[currentOffset + 3] == 0x01 && Data[currentOffset + 4] == 0x4D &&
                                Data[currentOffset + 5] == 0x02 && Data[currentOffset + 6] == 0x4D &&
                                Data[currentOffset + 7] == 0x03 && Data[currentOffset + 8] == 0x4D &&
                                Data[currentOffset + 9] == 0x04 && Data[currentOffset + 10] == 0x4D &&
                                Data[currentOffset + 11] == 0x05 && Data[currentOffset + 12] == 0x4D &&
                                Data[currentOffset + 13] == 0x06 && Data[currentOffset + 14] == 0x4D &&
                                Data[currentOffset + 15] == 0x07 && Data[currentOffset + 16] == 0x4D &&
                                Data[currentOffset + 17] == 0x08 && Data[currentOffset + 18] == 0x4D &&
                                Data[currentOffset + 19] == 0x09)
                            {
                                if (Data[currentOffset + 20] == 0x46)
                                {
                                    instruction.Type = "CgFullMidClear"; //or CFMC
                                    currentOffset += 21;

                                    int stringIndex = BitConverter.ToInt32(Data, currentOffset);
                                    instruction.Arguments.Add(strings[stringIndex]);
                                    currentOffset += 4;
                                }
                                else
                                {
                                    instruction.Type = "CgMidClearAll"; //or CMCA
                                    currentOffset += 20;
                                }
                            }
                            else
                            {
                                instruction.Type = "CgMidClear"; //or CMC
                                currentOffset++;

                                instruction.Arguments.Add(
                                        Convert.ToString(Data[currentOffset]));
                                currentOffset++;
                            }

                            break;
                        }
                    case 0x4E:
                        {
                            instruction.Type = "Effect"; //or EF
                            currentOffset++;

                            instruction.Arguments.Add(
                                    Convert.ToString(Data[currentOffset]));
                            currentOffset++;
                            break;
                        }
                    case 0x4F:
                        {
                            currentOffset++;

                            for (int currentArgument = 0; currentArgument < 7; currentArgument++)
                            {
                                instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt32(Data, currentOffset)));
                                currentOffset += 4;
                            }

                            if (instruction.Arguments[0] == "0" && instruction.Arguments[1] == "0"
                                && instruction.Arguments[2] == "0" && instruction.Arguments[3] == "220"
                                && instruction.Arguments[4] == "220" && instruction.Arguments[5] == "220")
                            {
                                instruction.Type = "Effect"; //or EF
                                
                                if (instruction.Arguments[6] == "200" && Data[currentOffset] == 0x4E
                                    && Data[currentOffset + 1] == 0x17)
                                {
                                    instruction.Arguments.Clear();
                                    instruction.Arguments.Add("Z");
                                    currentOffset += 2;
                                }
                                else if (instruction.Arguments[6] == "10" && Data[currentOffset] == 0x4E
                                    && Data[currentOffset + 1] == 0x15)
                                {
                                    instruction.Arguments.Clear();
                                    instruction.Arguments.Add("]");
                                    currentOffset += 2;
                                }
                            }
                            else
                            {
                                instruction.Type = "CModeFlash";
                            }
                            
                            break;
                        }
                    case 0x50:
                        {
                            instruction.Type = "EffectFlash"; //or EFF
                            currentOffset++;

                            instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset)));
                            currentOffset += 2;
                            break;
                        }
                    case 0x51:
                        {
                            currentOffset++;

                            for (int currentArgument = 0; currentArgument < 4; currentArgument++)
                            {
                                instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset)));
                                currentOffset += 2;
                            }

                            if (instruction.Arguments[0] == "0" && instruction.Arguments[1] == "30"
                                && instruction.Arguments[2] == "80" && instruction.Arguments[3] == "400")
                            {
                                instruction.Type = "Effect"; //or EF
                                instruction.Arguments.Clear();
                                instruction.Arguments.Add("[");
                            }
                            else if (instruction.Arguments[0] == "30" && instruction.Arguments[1] == "0"
                                && instruction.Arguments[2] == "80" && instruction.Arguments[3] == "400")
                            {
                                instruction.Type = "Effect"; //or EF
                                instruction.Arguments.Clear();
                                instruction.Arguments.Add("\\");
                            }
                            else
                            {
                                instruction.Type = "EffectShake";
                            }

                            break;
                        }
                    case 0x52:
                        {
                            currentOffset++;

                            int stringIndex = BitConverter.ToInt32(Data, currentOffset);
                            instruction.Arguments.Add(strings[stringIndex]);
                            currentOffset += 4;
                            
                            switch (instruction.Arguments[0])
                            {
                                case "pef_clo":
                                    {
                                        instruction.Type = "Effect"; //or EF
                                        instruction.Arguments[0] = "^";
                                        break;
                                    }
                                case "pef_cir":
                                    {
                                        instruction.Type = "Effect"; //or EF
                                        instruction.Arguments[0] = "_";
                                        break;
                                    }
                                default:
                                    {
                                        instruction.Type = "EffectPattern"; //or EFSCR
                                        break;
                                    }
                            }
                            break;
                        }
                    case 0x53:
                        {
                            instruction.Type = "EffectScroll"; //or EFSCR
                            currentOffset++;

                            instruction.Arguments.Add(
                                Convert.ToString(Data[currentOffset]));
                            currentOffset++;

                            int stringIndex = BitConverter.ToInt32(Data, currentOffset);
                            instruction.Arguments.Add(strings[stringIndex]);
                            currentOffset += 4;
                            break;
                        }
                    case 0x54:
                        {
                            instruction.Type = "EFE";
                            currentOffset++;

                            instruction.Arguments.Add(
                                Convert.ToString(Data[currentOffset]));
                            currentOffset++;
                            break;
                        }
                    case 0x55:
                        {
                            instruction.Type = "EffectEnvStop"; //or EFES
                            currentOffset++;
                            break;
                        }
                    case 0x56:
                        {
                            instruction.Type = "EffectEnvStopNoCreate"; //or EFESNC
                            currentOffset++;
                            break;
                        }
                    case 0x57:
                        {
                            instruction.Type = "ColorFill"; //or CFill
                            currentOffset++;

                            for (int currentArgument = 0; currentArgument < 3; currentArgument++)
                            {
                                instruction.Arguments.Add(
                                    Convert.ToString(Data[currentOffset]));
                                currentOffset++;
                            }

                            for (int currentArgument = 0; currentArgument < 2; currentArgument++)
                            {
                                instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset)));
                                currentOffset += 2;
                            }

                            break;
                        }
                    case 0x58:
                        {
                            currentOffset++;

                            instruction.Arguments.Add(Convert.ToString
                                (BitConverter.ToInt32(Data, currentOffset)));
                            currentOffset += 4;

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
                            
                            for (int currentArgument = 1; currentArgument < 4; currentArgument++)
                            {
                                instruction.Arguments.Add(
                                    Convert.ToString(Data[currentOffset]));
                                currentOffset++;
                            }

                            break;
                        }
                    case 0x59:
                        {
                            instruction.Type = "EffectEnvLoadAlpha"; //or EFELA
                            currentOffset++;

                            int stringIndex = BitConverter.ToInt32(Data, currentOffset);
                            instruction.Arguments.Add(strings[stringIndex]);
                            currentOffset += 4;
                            break;
                        }
                    case 0x5A:
                        {
                            instruction.Type = "MusicPlay"; //or MP
                            currentOffset++;

                            instruction.Arguments.Add(
                                    Convert.ToString(Data[currentOffset]));
                            currentOffset++;

                            break;
                        }
                    case 0x5B:
                        {
                            instruction.Type = "MusicStop"; //or MM, MS
                            currentOffset++;
                            break;
                        }
                    case 0x5C:
                        {
                            instruction.Type = "MusicStopFade"; //or MSF
                            currentOffset++;

                            instruction.Arguments.Add( 
                                Convert.ToString(BitConverter.ToInt16(Data, currentOffset)));
                            currentOffset += 2;
                            break;
                        }
                    case 0x5D:
                        {
                            instruction.Type = "SoundEffectPlay"; //or SEP, WavePlayDirect, WPD
                            currentOffset++;

                            int stringIndex = BitConverter.ToInt32(Data, currentOffset);
                            instruction.Arguments.Add(strings[stringIndex]);
                            currentOffset += 4;
                            break;
                        }
                    case 0x5E:
                        {
                            instruction.Type = "SoundEffectPlayLoop"; //or SEPL, WavePlayLoop, WPL
                            currentOffset++;

                            int stringIndex = BitConverter.ToInt32(Data, currentOffset);
                            instruction.Arguments.Add(strings[stringIndex]);
                            currentOffset += 4;
                            break;
                        }
                    case 0x5F:
                        {
                            instruction.Type = "SoundEffectPlayLoopStop"; //or SEPLS, WaveStop, WS
                            currentOffset++;
                            break;
                        }
                    case 0x60:
                        {
                            instruction.Type = "SoundEffectPlayLoopABCD"; //or SEPLAD
                            currentOffset++;

                            instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset)));
                            currentOffset += 2;

                            int stringIndex = BitConverter.ToInt32(Data, currentOffset);
                            instruction.Arguments.Add(strings[stringIndex]);
                            currentOffset += 4;
                            break;
                        }
                    case 0x61:
                        {
                            instruction.Type = "SoundEffectPlayLoopStopABCD"; //or SEPLSAD
                            currentOffset++;

                            instruction.Arguments.Add(
                                Convert.ToString(BitConverter.ToInt16(Data, currentOffset)));
                            currentOffset += 2;
                            break;
                        }
                    case 0x62:
                        {
                            instruction.Type = "SoundEffectPlayLoopStopABCDALL"; //or SEPLSADALL
                            currentOffset++;
                            break;
                        }
                    case 0x63:
                        {
                            instruction.Type = "SoundEffectPitch"; //or SETPITCH, SEPITCH
                            currentOffset++;

                            instruction.Arguments.Add(
                                Convert.ToString(BitConverter.ToInt32(Data, currentOffset)));
                            currentOffset += 4;
                            break;
                        }
                    case 0x64:
                        {
                            instruction.Type = "SoundEffectPitchDefault"; //or SETPITCHD, SEPITCHD
                            currentOffset++;

                            instruction.Arguments.Add(
                                Convert.ToString( BitConverter.ToInt32(Data, currentOffset)));
                            currentOffset += 4;
                            break;
                        }
                    case 0x69:
                        {
                            instruction.Type = "Sleep";
                            currentOffset++;

                            byte[] argumentArray = new byte[5];
                            Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                            string[] argument = DecrypterHelper.GetParameters(argumentArray);
                            instruction.Arguments.Add(argument[0]);
                            currentOffset += Convert.ToInt32(argument[1]);

                            break;
                        }
                    case 0x6A:
                        {
                            instruction.Type = "AnimeFullOn";
                            currentOffset++;
                            break;
                        }
                    case 0x6B:
                        {
                            instruction.Type = "AnimeFullOff";
                            currentOffset++;
                            break;
                        }
                    case 0x6C:
                        {
                            instruction.Type = "AnimeMepachiOn";
                            currentOffset++;
                            break;
                        }
                    case 0x6D:
                        {
                            instruction.Type = "AnimeMepachiOff";
                            currentOffset++;
                            break;
                        }
                    case 0x6E:
                        {
                            instruction.Type = "AnimeKutiOn";
                            currentOffset++;
                            break;
                        }
                    case 0x6F:
                        {
                            instruction.Type = "AnimeKutiOff";
                            currentOffset++;
                            break;
                        }
                    case 0x70:
                        {
                            instruction.Type = "FontSize";
                            currentOffset++;

                            instruction.Arguments.Add(Convert.ToString(Data[currentOffset]));
                            currentOffset++;
                            break;
                        }
                    case 0x71:
                        {
                            instruction.Type = "FontChange";
                            currentOffset++;

                            int stringIndex = BitConverter.ToInt32(Data, currentOffset);
                            instruction.Arguments.Add(strings[stringIndex]);
                            currentOffset += 4;
                            break;
                        }
                    case 0x72:
                        {
                            instruction.Type = "FontSetName";
                            currentOffset++;

                            int stringIndex = BitConverter.ToInt32(Data, currentOffset);
                            instruction.Arguments.Add(strings[stringIndex]);
                            currentOffset += 4;
                            break;
                        }
                    case 0x73:
                        {
                            instruction.Type = "FontReset";
                            currentOffset++;
                            break;
                        }
                    case 0x74:
                        {
                            instruction.Type = "PlayCutMovie";
                            currentOffset++;

                            for (int currentInstruction = 0; currentInstruction < 5; currentInstruction++)
                            {
                                instruction.Arguments.Add(Convert.ToString(
                                    BitConverter.ToInt16(Data, currentOffset)));
                                currentOffset += 2;
                            }

                            int stringIndex = BitConverter.ToInt32(Data, currentOffset);
                            instruction.Arguments.Add(strings[stringIndex]);
                            currentOffset += 4;
                            break;
                        }
                    case 0x75:
                        {
                            instruction.Type = "PlayCutMovieLoop";
                            currentOffset++;

                            for (int currentArgument = 0; currentArgument < 5; currentArgument++)
                            {
                                instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt16(Data, currentOffset)));
                                currentOffset += 2;
                            }

                            int stringIndex = BitConverter.ToInt32(Data, currentOffset);
                            instruction.Arguments.Add(strings[stringIndex]);
                            currentOffset += 4;
                            break;
                        }
                    case 0x76:
                        {
                            instruction.Type = "PlayMovieRateSet";
                            currentOffset++;

                            instruction.Arguments.Add(Convert.ToString(
                                BitConverter.ToInt16(Data, currentOffset)));
                            currentOffset += 2;

                            instruction.Arguments.Add(Convert.ToString(
                                BitConverter.ToInt32(Data, currentOffset)));
                            currentOffset += 4;
                            break;
                        }
                    case 0x77:
                        {
                            instruction.Type = "PlayMoviePause";
                            currentOffset++;

                            instruction.Arguments.Add(Convert.ToString(
                                BitConverter.ToInt16(Data, currentOffset)));
                            currentOffset += 2;
                            break;
                        }
                    case 0x78:
                        {
                            instruction.Type = "ReleaseMovie";
                            currentOffset++;
                            break;
                        }
                    case 0x7B:
                        {
                            instruction.Type = "AntiAliasSet";
                            currentOffset++;

                            instruction.Arguments.Add(Convert.ToString(Data[currentOffset]));
                            currentOffset++;
                            break;
                        }
                    case 0x7C:
                        {
                            instruction.Type = "MessageWindowSet";
                            currentOffset++;

                            instruction.Arguments.Add(Convert.ToString(Data[currentOffset]));
                            currentOffset++;
                            break;
                        }
                    case 0x7D:
                        {
                            instruction.Type = "SetMepachiTime"; //or SMTIME
                            currentOffset++;

                            for (int currentArgument = 0; currentArgument < 3; currentArgument++)
                            {
                                instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt32(Data, currentOffset)));
                                currentOffset += 4;
                            }

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
                            currentOffset++;

                            for (int currentArgument = 0; currentArgument < 6; currentArgument++)
                            {
                                instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt32(Data, currentOffset)));
                                currentOffset += 4;
                            }
                            break;
                        }
                    case 0x80:
                        {
                            instruction.Type = "timeGetTime"; //or TimeGet
                            currentOffset++;

                            byte[] argumentArray = new byte[5];
                            Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                            string[] argument = DecrypterHelper.GetParameters(argumentArray);
                            instruction.Arguments.Add(argument[0]);
                            currentOffset += Convert.ToInt32(argument[1]);
                            break;
                        }
                    case 0x81:
                        {
                            instruction.Type = "GetSEPPlayNow"; //or GSEPN
                            currentOffset++;

                            byte[] argumentArray = new byte[5];
                            Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                            string[] argument = DecrypterHelper.GetParameters(argumentArray);
                            instruction.Arguments.Add(argument[0]);
                            currentOffset += Convert.ToInt32(argument[1]);
                            break;
                        }
                    case 0x8C:
                        {
                            instruction.Type = "TextInit";
                            currentOffset++;

                            for (int currentArgument = 0; currentArgument < 2; currentArgument++)
                            {
                                instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt32(Data, currentOffset)));
                                currentOffset += 4;
                            }
                            break;
                        }
                    case 0x8D:
                        {
                            instruction.Type = "TextOutSet";
                            currentOffset++;

                            for (int currentArgument = 0; currentArgument < 4; currentArgument++)
                            {
                                instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt32(Data, currentOffset)));
                                currentOffset += 4;
                            }
                            break;
                        }
                    case 0x8E:
                        {
                            instruction.Type = "TextOut";
                            currentOffset++;

                            for (int currentArgument = 0; currentArgument < 4; currentArgument++)
                            {
                                instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt32(Data, currentOffset)));
                                currentOffset += 4;
                            }

                            byte[] argumentArray = new byte[5];
                            Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                            string[] argument = DecrypterHelper.GetStringParameters(argumentArray, 0);
                            if (Convert.ToInt32(argument[1]) == 5) //If the amount of bytes read is 5, it means that the last 4 bytes are the index of the string array
                            {
                                int stringIndex = Convert.ToInt32(argument[0]);
                                instruction.Arguments.Add(strings[stringIndex]);
                            }
                            else
                            {
                                instruction.Arguments.Add(argument[0]);
                            }
                            currentOffset += Convert.ToInt32(argument[1]);

                            break;
                        }
                    case 0x8F:
                        {
                            instruction.Type = "TextOutDefault"; //or TOD
                            currentOffset++;

                            int stringIndex = BitConverter.ToInt32(Data, currentOffset);
                            instruction.Arguments.Add(strings[stringIndex]);
                            currentOffset += 4;
                            break;
                        }
                    case 0x90:
                        {
                            instruction.Type = "TextDraw";
                            currentOffset++;

                            for (int currentArgument = 0; currentArgument < 4; currentArgument++)
                            {
                                instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt32(Data, currentOffset)));
                                currentOffset += 4;
                            }
                            break;
                        }
                    case 0x91:
                        {
                            instruction.Type = "TextDrawDefault"; //or TDD
                            currentOffset++;
                            break;
                        }
                    case 0x92:
                        {
                            instruction.Type = "TextDrawFlag";
                            currentOffset++;

                            byte[] argumentArray = new byte[5];
                            for (int currentArgument = 0; currentArgument < 2; currentArgument++)
                            {
                                Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                                string[] argument = DecrypterHelper.GetParameters(argumentArray);
                                instruction.Arguments.Add(argument[0]);
                                currentOffset += Convert.ToInt32(argument[1]);
                            }

                            for (int currentArgument = 0; currentArgument < 2; currentArgument++)
                            {
                                instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt32(Data, currentOffset)));
                                currentOffset += 4;
                            }

                            break;
                        }
                    case 0x93:
                        {
                            instruction.Type = "CgLoad";
                            currentOffset++;

                            instruction.Arguments.Add(
                                Convert.ToString(BitConverter.ToInt32(Data, currentOffset)));
                            currentOffset += 4;

                            int stringIndex = BitConverter.ToInt32(Data, currentOffset);
                            instruction.Arguments.Add(strings[stringIndex]);
                            currentOffset += 4;
                            break;
                        }
                    case 0x94:
                        {
                            instruction.Type = "CgUnLoad";
                            currentOffset++;

                            instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt32(Data, currentOffset)));
                            currentOffset += 4;
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

                            for (int currentArgument = 0; currentArgument < 4; currentArgument++)
                            {
                                byte[] argumentArray = new byte[5];
                                Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                                string[] argument = DecrypterHelper.GetParameters(argumentArray);
                                instruction.Arguments.Add(argument[0]);
                                currentOffset += Convert.ToInt32(argument[1]);
                            }
                            break;
                        }
                    case 0x97:
                        {
                            instruction.Type = "CgDraw";
                            currentOffset++;

                            instruction.Arguments.Add(
                                    Convert.ToString(Data[currentOffset]));
                            currentOffset++;
                            break;
                        }
                    case 0x98:
                        {
                            instruction.Type = "CgShow";
                            currentOffset++;

                            for (int currentArgument = 0; currentArgument < 4; currentArgument++)
                            {
                                byte[] argumentArray = new byte[5];
                                Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                                string[] argument = DecrypterHelper.GetParameters(argumentArray);
                                instruction.Arguments.Add(argument[0]);
                                currentOffset += Convert.ToInt32(argument[1]);
                            }
                            break;
                        }
                    case 0x99:
                        {
                            instruction.Type = "CgDrawKey";
                            currentOffset++;

                            instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt32(Data, currentOffset)));
                            currentOffset += 4;

                            byte[] argumentArray = new byte[5];
                            for (int currentArgument = 0; currentArgument < 6; currentArgument++)
                            {
                                Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                                string[] argument = DecrypterHelper.GetParameters(argumentArray);
                                instruction.Arguments.Add(argument[0]);
                                currentOffset += Convert.ToInt32(argument[1]);
                            }

                            break;
                        }
                    case 0x9A:
                        {
                            instruction.Type = "CgDrawColorDodge"; //or CgDrawCD
                            currentOffset++;

                            instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt32(Data, currentOffset)));
                            currentOffset += 4;

                            for (int currentArgument = 0; currentArgument < 6; currentArgument++)
                            {
                                byte[] argumentArray = new byte[5];
                                Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                                string[] argument = DecrypterHelper.GetParameters(argumentArray);
                                instruction.Arguments.Add(argument[0]);
                                currentOffset += Convert.ToInt32(argument[1]);
                            }
                            break;
                        }
                    case 0x9B:
                        {
                            instruction.Type = "CgDrawBlendPattern"; //or CgDrawBP
                            currentOffset++;

                            instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt32(Data, currentOffset)));
                            currentOffset += 4;

                            for (int currentArgument = 0; currentArgument < 8; currentArgument++)
                            {
                                byte[] argumentArray = new byte[5];
                                Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                                string[] argument = DecrypterHelper.GetParameters(argumentArray);
                                instruction.Arguments.Add(argument[0]);
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
                    case 0x9D:
                        {
                            instruction.Type = "SaveGetDate";
                            currentOffset++;

                            byte[] argumentArray = new byte[5];
                            Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                            string[] argument = DecrypterHelper.GetStringParameters(argumentArray, 1);
                            if (Convert.ToInt32(argument[1]) == 5) //If the amount of bytes read is 5, it means that the last 4 bytes are the index of the string array
                            {
                                int stringIndex = Convert.ToInt32(argument[0]);
                                instruction.Arguments.Add(strings[stringIndex]);
                            }
                            else
                            {
                                instruction.Arguments.Add(argument[0]);
                            }
                            currentOffset += Convert.ToInt32(argument[1]);

                            instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt32(Data, currentOffset)));
                            currentOffset += 4;

                            break;
                        }
                    case 0x9E:
                        {
                            instruction.Type = "SaveGetTitle";
                            currentOffset++;

                            byte[] argumentArray = new byte[5];
                            Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                            string[] argument = DecrypterHelper.GetStringParameters(argumentArray, 1);
                            if (Convert.ToInt32(argument[1]) == 5) //If the amount of bytes read is 5, it means that the last 4 bytes are the index of the string array
                            {
                                int stringIndex = Convert.ToInt32(argument[0]);
                                instruction.Arguments.Add(strings[stringIndex]);
                            }
                            else
                            {
                                instruction.Arguments.Add(argument[0]);
                            }
                            currentOffset += Convert.ToInt32(argument[1]);

                            instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt32(Data, currentOffset)));
                            currentOffset += 4;

                            break;
                        }
                    case 0x9F:
                        {
                            instruction.Type = "SaveGetMemo";
                            currentOffset++;

                            byte[] argumentArray = new byte[5];
                            Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                            string[] argument = DecrypterHelper.GetStringParameters(argumentArray, 1);
                            if (Convert.ToInt32(argument[1]) == 5) //If the amount of bytes read is 5, it means that the last 4 bytes are the index of the string array
                            {
                                int stringIndex = Convert.ToInt32(argument[0]);
                                instruction.Arguments.Add(strings[stringIndex]);
                            }
                            else
                            {
                                instruction.Arguments.Add(argument[0]);
                            }
                            currentOffset += Convert.ToInt32(argument[1]);

                            instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt32(Data, currentOffset)));
                            currentOffset += 4;

                            break;
                        }
                    case 0xA0:
                        {
                            instruction.Type = "ConfigGetEffect";
                            currentOffset++;

                            byte[] argumentArray = new byte[5];
                            Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                            string[] argument = DecrypterHelper.GetParameters(argumentArray);
                            instruction.Arguments.Add(argument[0]);
                            currentOffset += Convert.ToInt32(argument[1]);

                            break;
                        }
                    case 0xA1:
                        {
                            instruction.Type = "SkipGet";
                            currentOffset++;

                            byte[] argumentArray = new byte[5];
                            Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                            string[] argument = DecrypterHelper.GetParameters(argumentArray);
                            instruction.Arguments.Add(argument[0]);
                            currentOffset += Convert.ToInt32(argument[1]);

                            break;
                        }
                    case 0xA2:
                        {
                            instruction.Type = "CtrlGet";
                            currentOffset++;

                            byte[] argumentArray = new byte[5];
                            Buffer.BlockCopy(Data, currentOffset, argumentArray, 0, 5);
                            string[] argument = DecrypterHelper.GetParameters(argumentArray);
                            instruction.Arguments.Add(argument[0]);
                            currentOffset += Convert.ToInt32(argument[1]);

                            break;
                        }
                    case 0xA3:
                        {
                            instruction.Type = "MemoryLoad";
                            currentOffset++;
                            break;
                        }
                    case 0xB5:
                        {
                            instruction.Type = "CharEvent";
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
                    case 0xC8:
                        {
                            instruction.Type = "SelectPrint"; //or SP
                            currentOffset++;

                            //This value will be either 8 or the amount of instructions before reaching one
                            //that is "end" (including that one)
                            int totalArguments = Data[currentOffset];
                            currentOffset++;

                            for (int currentArgument = 0; currentArgument < totalArguments; currentArgument++)
                            {
                                int stringIndex = BitConverter.ToInt32(Data, currentOffset);
                                instruction.Arguments.Add(strings[stringIndex]);
                                currentOffset += 4;
                            }

                            break;
                        }
                    case 0xC9:
                        {
                            instruction.Type = "SelectDefault"; //or SD, case
                            currentOffset++;

                            instruction.Arguments.Add(
                                Convert.ToString(Data[currentOffset]));
                            currentOffset++;
                            break;
                        }
                    case 0xF0:
                        {
                            if (isTakanoScript)
                            {
                                instruction.Type = "ReturnTitle"; //or RT
                                instruction.Arguments.Add("1");
                                instruction.Arguments.Add("0");

                                currentOffset += 9;
                            }
                            else
                            {
                                instruction.Type = "Program";
                                currentOffset++;

                                for (int currentArgument = 0; currentArgument < 2; currentArgument++)
                                {
                                    instruction.Arguments.Add(
                                        Convert.ToString(BitConverter.ToInt32(Data, currentOffset)));
                                    currentOffset += 4;
                                }
                            }
                            break;
                        }
                    case 0xE6:
                        {
                            instruction.Type = "Dialogue"; //Unofficial name
                            currentOffset++; //There is no name for some instructions apparently, so we cannot name it

                            instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt32(Data, currentOffset)));
                            currentOffset += 4;

                            int stringIndex = BitConverter.ToInt32(Data, currentOffset);
                            instruction.Arguments.Add(strings[stringIndex]);
                            currentOffset += 4;

                            int stringIndex1 = BitConverter.ToInt32(Data, currentOffset);
                            instruction.Arguments.Add(strings[stringIndex1]);
                            currentOffset += 4;

                            int stringIndex2 = BitConverter.ToInt32(Data, currentOffset);
                            instruction.Arguments.Add(strings[stringIndex2]);
                            currentOffset += 4;

                            currentOffset += 4; //These last 4 bytes are always an incrementing value, starting from 0

                            break;
                        }
                    case 0xE7:
                        {
                            instruction.Type = "Dialogue"; //Unofficial name
                            currentOffset++; //There is no name for some instructions apparently, so we cannot name it

                            instruction.Arguments.Add(
                                    Convert.ToString(BitConverter.ToInt32(Data, currentOffset)));
                            currentOffset += 4;

                            int stringIndex = BitConverter.ToInt32(Data, currentOffset);
                            instruction.Arguments.Add(strings[stringIndex]);
                            currentOffset += 4;

                            int stringIndex1 = BitConverter.ToInt32(Data, currentOffset);
                            instruction.Arguments.Add(strings[stringIndex1]);
                            currentOffset += 4;

                            currentOffset += 4; //These last 4 bytes are always an incrementing value, starting from 0

                            break;
                        }
                    case 0xE8:
                        {
                            instruction.Type = "Dialogue"; //Unofficial name
                            currentOffset++; //There is no name for some instructions apparently, so we cannot name it

                            int stringIndex = BitConverter.ToInt32(Data, currentOffset);
                            instruction.Arguments.Add(strings[stringIndex]);
                            currentOffset += 4;

                            int stringIndex1 = BitConverter.ToInt32(Data, currentOffset);
                            instruction.Arguments.Add(strings[stringIndex1]);
                            currentOffset += 4;

                            currentOffset += 4; //These last 4 bytes are always an incrementing value, starting from 0

                            break;
                        }
                    case 0xE9:
                        {
                            instruction.Type = "Dialogue"; //Unofficial name
                            currentOffset++; //There is no name for some instructions apparently, so we cannot name it

                            int stringIndex = BitConverter.ToInt32(Data, currentOffset);
                            instruction.Arguments.Add(strings[stringIndex]);
                            currentOffset += 4;

                            currentOffset += 4; //These last 4 bytes are always an incrementing value, starting from 0

                            break;
                        }
                    default:
                        {
                            break;
                        }
                }

                instructions.Add(instruction);
            }

            return instructions;
        }

        public byte[] Compile(string JSON)
        {
            //First we need to deserialize the JSON string into a list of instructions
            var options = new JsonSerializerOptions
            {
                Encoder = JavaScriptEncoder.Create(UnicodeRanges.All)
            };
            instructions = JsonSerializer.Deserialize<List<Instruction>>(JSON, options) ?? new List<Instruction>();

            List<byte> CompiledScript = new List<byte>();

            //The instructions that are dialogue related do keep track of their number, and it starts from number 0, incrementing by 1
            //each time a new instruction of dialogue is added.
            int CurrentDialogueInstruction = 0;

            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            Encoding shiftJIS = Encoding.GetEncoding("shift-jis");

            for (int CurrentInstruction = 0; CurrentInstruction < instructions.Count; CurrentInstruction++)
            {
                switch (instructions[CurrentInstruction].Type)
                {
                    case "VideoStart":
                        {
                            CompiledScript.Add(0x02);
                            CompiledScript.Add(byte.Parse(instructions[CurrentInstruction].Arguments[0]));
                            break;
                        }
                    case "VideoStartAnime":
                        {
                            CompiledScript.Add(0x03);
                            CompiledScript.Add(byte.Parse(instructions[CurrentInstruction].Arguments[0]));
                            break;
                        }
                    case "VideoEnd":
                        {
                            CompiledScript.Add(0x04);
                            break;
                        }
                    case "Goto":
                        {
                            CompiledScript.Add(0xB);

                            bool hasAddress = CompilerHelper.ExistsLabel(labels, instructions[CurrentInstruction].Arguments[0]);

                            if (hasAddress)
                            {
                                var existingLabel = CompilerHelper.GetLabel(labels, instructions[CurrentInstruction].Arguments[0]);
                                CompiledScript.AddRange(BitConverter.GetBytes(existingLabel.Address));
                            }
                            else if (!hasAddress)
                            {
                                var newLabel = new Label
                                {
                                    Name = instructions[CurrentInstruction].Arguments[0],
                                    Address = CompiledScript.Count
                                };
                                pendingLabels.Add(newLabel);
                                CompiledScript.AddRange(new byte[4]); //Placeholder of 4 bytes
                            }
                            break;
                        }
                    case "Gosub":
                        {
                            CompiledScript.Add(0xC);

                            bool hasAddress = CompilerHelper.ExistsLabel(labels, instructions[CurrentInstruction].Arguments[0]);

                            if (hasAddress)
                            {
                                var existingLabel = CompilerHelper.GetLabel(labels, instructions[CurrentInstruction].Arguments[0]);
                                CompiledScript.AddRange(BitConverter.GetBytes(existingLabel.Address));
                            }
                            else if (!hasAddress)
                            {
                                var newLabel = new Label
                                {
                                    Name = instructions[CurrentInstruction].Arguments[0],
                                    Address = CompiledScript.Count
                                };
                                pendingLabels.Add(newLabel);
                                CompiledScript.AddRange(new byte[4]); //Placeholder of 4 bytes
                            }
                            break;
                        }
                    case "MacroEnd":
                        {
                            CompiledScript.Add(0xD);
                            break;
                        }
                    case "Movie":
                        {
                            CompiledScript.Add(0xE);
                            CompiledScript.Add(0x74);

                            for (int CurrentArgument = 0; CurrentArgument < 5; CurrentArgument++)
                            {
                                CompiledScript.AddRange(BitConverter.GetBytes(short.Parse(instructions[CurrentInstruction].Arguments[CurrentArgument])));
                            }

                            //We check to see if the string is already in the list of strings
                            int StringPosition = CompilerHelper.GetPositionStringList(strings,
                                instructions[CurrentInstruction].Arguments[5]);

                            //If it is not, we add it to the list of strings and add the position of the string in the list
                            if (StringPosition != -1)
                            {
                                strings.Add(instructions[CurrentInstruction].Arguments[5]);
                                CompiledScript.AddRange(BitConverter.GetBytes(strings.Count - 1));
                            }
                            else
                            {
                                CompiledScript.AddRange(BitConverter.GetBytes(StringPosition));
                            }

                            CompiledScript.Add(0xB8);
                            CompiledScript.Add(0x78);
                            break;
                        }
                    case "SkipStop":
                        {
                            CompiledScript.Add(0xE);
                            break;
                        }
                    case "SaveStatus":
                        {
                            CompiledScript.Add(0x14);

                            //We check to see if the string is already in the list of strings
                            int StringPosition = CompilerHelper.GetPositionStringList(strings,
                                instructions[CurrentInstruction].Arguments[0]);

                            //If it is not, we add it to the list of strings and add the position of the string in the list
                            if (StringPosition != -1)
                            {
                                strings.Add(instructions[CurrentInstruction].Arguments[0]);
                                CompiledScript.AddRange(BitConverter.GetBytes(strings.Count - 1));
                            }
                            else
                            {
                                CompiledScript.AddRange(BitConverter.GetBytes(StringPosition));
                            }
                            break;
                        }
                    case "AutoSave":
                        {
                            CompiledScript.Add(0x15);
                            break;
                        }
                    case "FlagAdd":
                        {
                            CompiledScript.Add(0x19);

                            CompiledScript.AddRange(CompilerHelper.EncodeParameters
                                    (instructions[CurrentInstruction].Arguments[0]));
                            CompiledScript.AddRange(BitConverter.GetBytes(int.Parse(
                                instructions[CurrentInstruction].Arguments[1])));
                            break;
                        }
                    case "FlagSub":
                        {
                            CompiledScript.Add(0x1A);

                            CompiledScript.AddRange(CompilerHelper.EncodeParameters
                                    (instructions[CurrentInstruction].Arguments[0]));
                            CompiledScript.AddRange(BitConverter.GetBytes(int.Parse(
                                instructions[CurrentInstruction].Arguments[1])));
                            break;
                        }
                    case "FlagMul":
                        {
                            CompiledScript.Add(0x1B);

                            CompiledScript.AddRange(CompilerHelper.EncodeParameters
                                    (instructions[CurrentInstruction].Arguments[0]));
                            CompiledScript.AddRange(BitConverter.GetBytes(int.Parse(
                                instructions[CurrentInstruction].Arguments[1])));
                            break;
                        }
                    case "FlagDiv":
                        {
                            CompiledScript.Add(0x1C);

                            CompiledScript.AddRange(CompilerHelper.EncodeParameters
                                    (instructions[CurrentInstruction].Arguments[0]));
                            CompiledScript.AddRange(BitConverter.GetBytes(int.Parse(
                                instructions[CurrentInstruction].Arguments[1])));
                            break;
                        }
                    case "FlagExc":
                        {
                            CompiledScript.Add(0x1D);

                            CompiledScript.AddRange(CompilerHelper.EncodeParameters
                                    (instructions[CurrentInstruction].Arguments[0]));
                            CompiledScript.AddRange(BitConverter.GetBytes(int.Parse(
                                instructions[CurrentInstruction].Arguments[1])));
                            break;
                        }
                    case "FlagSet":
                        {
                            CompiledScript.Add(0x1E);

                            CompiledScript.AddRange(CompilerHelper.EncodeParameters
                                    (instructions[CurrentInstruction].Arguments[0]));
                            CompiledScript.AddRange(BitConverter.GetBytes(int.Parse(
                                instructions[CurrentInstruction].Arguments[1])));
                            break;
                        }
                    case "StringSet":
                        {
                            CompiledScript.Add(0x1F);

                            byte[] result = CompilerHelper.EncodeStringParameters
                                    (instructions[CurrentInstruction].Arguments[0], 1);
                            CompiledScript.AddRange(result);
                            if (result[0] == 0x45)
                            {

                                //We check to see if the string is already in the list of strings
                                int StringPosition = CompilerHelper.GetPositionStringList(strings,
                                    instructions[CurrentInstruction].Arguments[0]);

                                //If it is not, we add it to the list of strings and add the position of the string in the list
                                if (StringPosition != -1)
                                {
                                    strings.Add(instructions[CurrentInstruction].Arguments[0]);
                                    CompiledScript.AddRange(BitConverter.GetBytes(strings.Count - 1));
                                }
                                else
                                {
                                    CompiledScript.AddRange(BitConverter.GetBytes(StringPosition));
                                }
                            }

                            //We check to see if the string is already in the list of strings
                            int StringPosition1 = CompilerHelper.GetPositionStringList(strings,
                                instructions[CurrentInstruction].Arguments[1]);

                            //If it is not, we add it to the list of strings and add the position of the string in the list
                            if (StringPosition1 != -1)
                            {
                                strings.Add(instructions[CurrentInstruction].Arguments[1]);
                                CompiledScript.AddRange(BitConverter.GetBytes(strings.Count - 1));
                            }
                            else
                            {
                                CompiledScript.AddRange(BitConverter.GetBytes(StringPosition1));
                            }
                            break;
                        }
                    case "S2SSet":
                        {
                            CompiledScript.Add(0x20);

                            for (int CurrentArgument = 0; CurrentArgument < 2; CurrentArgument++)
                            {
                                byte[] result = CompilerHelper.EncodeStringParameters
                                    (instructions[CurrentInstruction].Arguments[CurrentArgument], 1);
                                CompiledScript.AddRange(result);
                                if (result[0] == 0x45)
                                {
                                    //We check to see if the string is already in the list of strings
                                    int StringPosition = CompilerHelper.GetPositionStringList(strings,
                                        instructions[CurrentInstruction].Arguments[CurrentArgument]);

                                    //If it is not, we add it to the list of strings and add the position of the string in the list
                                    if (StringPosition != -1)
                                    {
                                        strings.Add(instructions[CurrentInstruction].Arguments[CurrentArgument]);
                                        CompiledScript.AddRange(BitConverter.GetBytes(strings.Count - 1));
                                    }
                                    else
                                    {
                                        CompiledScript.AddRange(BitConverter.GetBytes(StringPosition));
                                    }
                                }
                            }
                            break;
                        }
                    case "S2SConnect":
                        {
                            CompiledScript.Add(0x21);

                            for (int CurrentArgument = 0; CurrentArgument < 2; CurrentArgument++)
                            {
                                byte[] result = CompilerHelper.EncodeStringParameters
                                    (instructions[CurrentInstruction].Arguments[CurrentArgument], 1);
                                CompiledScript.AddRange(result);
                                if (result[0] == 0x45)
                                {
                                    //We check to see if the string is already in the list of strings
                                    int StringPosition = CompilerHelper.GetPositionStringList(strings,
                                        instructions[CurrentInstruction].Arguments[CurrentArgument]);

                                    //If it is not, we add it to the list of strings and add the position of the string in the list
                                    if (StringPosition != -1)
                                    {
                                        strings.Add(instructions[CurrentInstruction].Arguments[CurrentArgument]);
                                        CompiledScript.AddRange(BitConverter.GetBytes(strings.Count - 1));
                                    }
                                    else
                                    {
                                        CompiledScript.AddRange(BitConverter.GetBytes(StringPosition));
                                    }
                                }
                            }
                            break;
                        }
                    case "S2TextConnect":
                        {
                            CompiledScript.Add(0x22);

                            byte[] result = CompilerHelper.EncodeStringParameters
                                    (instructions[CurrentInstruction].Arguments[0], 1);
                            CompiledScript.AddRange(result);
                            if (result[0] == 0x45)
                            {
                                //We check to see if the string is already in the list of strings
                                int StringPosition = CompilerHelper.GetPositionStringList(strings,
                                    instructions[CurrentInstruction].Arguments[0]);

                                //If it is not, we add it to the list of strings and add the position of the string in the list
                                if (StringPosition != -1)
                                {
                                    strings.Add(instructions[CurrentInstruction].Arguments[0]);
                                    CompiledScript.AddRange(BitConverter.GetBytes(strings.Count - 1));
                                }
                                else
                                {
                                    CompiledScript.AddRange(BitConverter.GetBytes(StringPosition));
                                }
                            }

                            //We check to see if the string is already in the list of strings
                            int StringPosition1 = CompilerHelper.GetPositionStringList(strings,
                                instructions[CurrentInstruction].Arguments[1]);

                            //If it is not, we add it to the list of strings and add the position of the string in the list
                            if (StringPosition1 != -1)
                            {
                                strings.Add(instructions[CurrentInstruction].Arguments[1]);
                                CompiledScript.AddRange(BitConverter.GetBytes(strings.Count - 1));
                            }
                            else
                            {
                                CompiledScript.AddRange(BitConverter.GetBytes(StringPosition1));
                            }
                            break;
                        }
                    case "FlagRand":
                        {
                            CompiledScript.Add(0x23);

                            CompiledScript.AddRange(CompilerHelper.EncodeParameters
                                    (instructions[CurrentInstruction].Arguments[0]));

                            for (int CurrentArgument = 1; CurrentArgument < 3; CurrentArgument++)
                            {
                                CompiledScript.AddRange(BitConverter.GetBytes(int.Parse(
                                    instructions[CurrentInstruction].Arguments[CurrentArgument])));
                            }
                            break;
                        }
                    case "FlagCg":
                        {
                            CompiledScript.Add(0x24);

                            //We check to see if the string is already in the list of strings
                            int StringPosition = CompilerHelper.GetPositionStringList(strings,
                                instructions[CurrentInstruction].Arguments[0]);

                            //If it is not, we add it to the list of strings and add the position of the string in the list
                            if (StringPosition != -1)
                            {
                                strings.Add(instructions[CurrentInstruction].Arguments[0]);
                                CompiledScript.AddRange(BitConverter.GetBytes(strings.Count - 1));
                            }
                            else
                            {
                                CompiledScript.AddRange(BitConverter.GetBytes(StringPosition));
                            }
                            break;
                        }
                    case "FlagCheck":
                        {
                            //First we add the operand by looking at the second argument
                            switch (instructions[CurrentInstruction].Arguments[1])
                            {
                                case "==":
                                    {
                                        CompiledScript.Add(0x25);
                                        break;
                                    }
                                case "!=":
                                    {
                                        CompiledScript.Add(0x26);
                                        break;
                                    }
                                case "<":
                                    {
                                        CompiledScript.Add(0x27);
                                        break;
                                    }
                                case ">":
                                    {
                                        CompiledScript.Add(0x28);
                                        break;
                                    }
                                case "<=":
                                    {
                                        CompiledScript.Add(0x29);
                                        break;
                                    }
                                case ">=":
                                    {
                                        CompiledScript.Add(0x2A);
                                        break;
                                    }
                            }

                            //Now we add the type of flag by reading the first character of the first argument, and then we add the numbers
                            //that follow it, or the number itself if it is not a flag
                            switch (instructions[CurrentInstruction].Arguments[0][0])
                            {
                                case 'g':
                                    {
                                        CompiledScript.Add(0x3F);
                                        CompiledScript.AddRange(BitConverter.GetBytes(short.Parse(
                                            instructions[CurrentInstruction].Arguments[0].Substring(1))));
                                        break;
                                    }
                                case 'f':
                                    {
                                        CompiledScript.Add(0x3E);
                                        CompiledScript.AddRange(BitConverter.GetBytes(short.Parse(
                                            instructions[CurrentInstruction].Arguments[0].Substring(1))));
                                        break;
                                    }
                                case 'c':
                                    {
                                        CompiledScript.Add(0x42);
                                        CompiledScript.AddRange(BitConverter.GetBytes(short.Parse(
                                            instructions[CurrentInstruction].Arguments[0].Substring(1))));
                                        break;
                                    }
                                default:
                                    {
                                        CompiledScript.Add(0x43);
                                        CompiledScript.AddRange(BitConverter.GetBytes(short.Parse(
                                            instructions[CurrentInstruction].Arguments[0])));
                                        break;
                                    }
                            }

                            CompiledScript.AddRange(BitConverter.GetBytes(int.Parse(
                                instructions[CurrentInstruction].Arguments[2])));

                            bool hasAddress = CompilerHelper.ExistsLabel(labels, instructions[CurrentInstruction].Arguments[3]);

                            if (hasAddress)
                            {
                                var existingLabel = CompilerHelper.GetLabel(labels, instructions[CurrentInstruction].Arguments[3]);
                                CompiledScript.AddRange(BitConverter.GetBytes(existingLabel.Address));
                            }
                            else if (!hasAddress)
                            {
                                var newLabel = new Label
                                {
                                    Name = instructions[CurrentInstruction].Arguments[3],
                                    Address = CompiledScript.Count
                                };
                                pendingLabels.Add(newLabel);
                                CompiledScript.AddRange(new byte[4]); //Placeholder of 4 bytes
                            }
                            break;
                        }
                    case "FlagCheckGosub":
                        {
                            //First we add the operand by looking at the second argument
                            switch (instructions[CurrentInstruction].Arguments[1])
                            {
                                case "==":
                                    {
                                        CompiledScript.Add(0x2B);
                                        break;
                                    }
                                case "!=":
                                    {
                                        CompiledScript.Add(0x2C);
                                        break;
                                    }
                                case "<":
                                    {
                                        CompiledScript.Add(0x2D);
                                        break;
                                    }
                                case ">":
                                    {
                                        CompiledScript.Add(0x2E);
                                        break;
                                    }
                                case "<=":
                                    {
                                        CompiledScript.Add(0x2F);
                                        break;
                                    }
                                case ">=":
                                    {
                                        CompiledScript.Add(0x30);
                                        break;
                                    }
                            }

                            //Now we add the type of flag by reading the first character of the first argument, and then we add the numbers
                            //that follow it, or the number itself if it is not a flag
                            switch (instructions[CurrentInstruction].Arguments[0][0])
                            {
                                case 'g':
                                    {
                                        CompiledScript.Add(0x3F);
                                        CompiledScript.AddRange(BitConverter.GetBytes(short.Parse(
                                            instructions[CurrentInstruction].Arguments[0].Substring(1))));
                                        break;
                                    }
                                case 'f':
                                    {
                                        CompiledScript.Add(0x3E);
                                        CompiledScript.AddRange(BitConverter.GetBytes(short.Parse(
                                            instructions[CurrentInstruction].Arguments[0].Substring(1))));
                                        break;
                                    }
                                case 'c':
                                    {
                                        CompiledScript.Add(0x42);
                                        CompiledScript.AddRange(BitConverter.GetBytes(short.Parse(
                                            instructions[CurrentInstruction].Arguments[0].Substring(1))));
                                        break;
                                    }
                                default:
                                    {
                                        CompiledScript.Add(0x43);
                                        CompiledScript.AddRange(BitConverter.GetBytes(short.Parse(
                                            instructions[CurrentInstruction].Arguments[0])));
                                        break;
                                    }
                            }

                            CompiledScript.AddRange(BitConverter.GetBytes(int.Parse(
                                instructions[CurrentInstruction].Arguments[2])));

                            bool hasAddress = CompilerHelper.ExistsLabel(labels, instructions[CurrentInstruction].Arguments[3]);

                            if (hasAddress)
                            {
                                var existingLabel = CompilerHelper.GetLabel(labels, instructions[CurrentInstruction].Arguments[3]);
                                CompiledScript.AddRange(BitConverter.GetBytes(existingLabel.Address));
                            }
                            else if (!hasAddress)
                            {
                                var newLabel = new Label
                                {
                                    Name = instructions[CurrentInstruction].Arguments[3],
                                    Address = CompiledScript.Count
                                };
                                pendingLabels.Add(newLabel);
                                CompiledScript.AddRange(new byte[4]); //Placeholder of 4 bytes
                            }
                            break;
                        }
                    case "F2FAdd":
                        {
                            CompiledScript.Add(0x31);

                            for (int CurrentArgument = 0; CurrentArgument < 2; CurrentArgument++)
                            {
                                CompiledScript.AddRange(CompilerHelper.EncodeParameters
                                    (instructions[CurrentInstruction].Arguments[CurrentArgument]));
                            }
                            break;
                        }
                    case "F2FSub":
                        {
                            CompiledScript.Add(0x32);

                            for (int CurrentArgument = 0; CurrentArgument < 2; CurrentArgument++)
                            {
                                CompiledScript.AddRange(CompilerHelper.EncodeParameters
                                    (instructions[CurrentInstruction].Arguments[CurrentArgument]));
                            }
                            break;
                        }
                    case "F2FMul":
                        {
                            CompiledScript.Add(0x33);

                            for (int CurrentArgument = 0; CurrentArgument < 2; CurrentArgument++)
                            {
                                CompiledScript.AddRange(CompilerHelper.EncodeParameters
                                    (instructions[CurrentInstruction].Arguments[CurrentArgument]));
                            }
                            break;
                        }
                    case "F2FDiv":
                        {
                            CompiledScript.Add(0x34);

                            for (int CurrentArgument = 0; CurrentArgument < 2; CurrentArgument++)
                            {
                                CompiledScript.AddRange(CompilerHelper.EncodeParameters
                                    (instructions[CurrentInstruction].Arguments[CurrentArgument]));
                            }
                            break;
                        }
                    case "F2FExc":
                        {
                            CompiledScript.Add(0x35);

                            for (int CurrentArgument = 0; CurrentArgument < 2; CurrentArgument++)
                            {
                                CompiledScript.AddRange(CompilerHelper.EncodeParameters
                                    (instructions[CurrentInstruction].Arguments[CurrentArgument]));
                            }
                            break;
                        }
                    case "F2FSet":
                        {
                            CompiledScript.Add(0x36);

                            for (int CurrentArgument = 0; CurrentArgument < 2; CurrentArgument++)
                            {
                                CompiledScript.AddRange(CompilerHelper.EncodeParameters
                                    (instructions[CurrentInstruction].Arguments[CurrentArgument]));
                            }
                            break;
                        }
                    case "F2FRand":
                        {
                            CompiledScript.Add(0x37);

                            CompiledScript.AddRange(CompilerHelper.EncodeParameters
                                    (instructions[CurrentInstruction].Arguments[0]));
                            CompiledScript.AddRange(BitConverter.GetBytes(int.Parse(
                                    instructions[CurrentInstruction].Arguments[1])));
                            CompiledScript.AddRange(CompilerHelper.EncodeParameters
                                    (instructions[CurrentInstruction].Arguments[2]));
                            break;
                        }
                    case "F2FCheck":
                        {
                            //First we add the operand by looking at the second argument
                            switch (instructions[CurrentInstruction].Arguments[1])
                            {
                                case "==":
                                    {
                                        CompiledScript.Add(0x38);
                                        break;
                                    }
                                case "!=":
                                    {
                                        CompiledScript.Add(0x39);
                                        break;
                                    }
                                case "<":
                                    {
                                        CompiledScript.Add(0x3A);
                                        break;
                                    }
                                case ">":
                                    {
                                        CompiledScript.Add(0x3B);
                                        break;
                                    }
                                case "<=":
                                    {
                                        CompiledScript.Add(0x3C);
                                        break;
                                    }
                                case ">=":
                                    {
                                        CompiledScript.Add(0x3D);
                                        break;
                                    }
                            }

                            //Now we add the type of flag by reading the first character of the first argument, and then we add the numbers
                            //that follow it, or the number itself if it is not a flag
                            switch (instructions[CurrentInstruction].Arguments[0][0])
                            {
                                case 'g':
                                    {
                                        CompiledScript.Add(0x3F);
                                        CompiledScript.AddRange(BitConverter.GetBytes(short.Parse(
                                            instructions[CurrentInstruction].Arguments[0].Substring(1))));
                                        break;
                                    }
                                default:
                                    {
                                        CompiledScript.Add(0x3E);
                                        CompiledScript.AddRange(BitConverter.GetBytes(short.Parse(
                                            instructions[CurrentInstruction].Arguments[0])));
                                        break;
                                    }
                            }

                            //Now we add the type of flag by reading the first character of the first argument, and then we add the numbers
                            //that follow it, or the number itself if it is not a flag
                            switch (instructions[CurrentInstruction].Arguments[2][0])
                            {
                                case 'g':
                                    {
                                        CompiledScript.Add(0x3F);
                                        CompiledScript.AddRange(BitConverter.GetBytes(short.Parse(
                                            instructions[CurrentInstruction].Arguments[2].Substring(1))));
                                        break;
                                    }
                                default:
                                    {
                                        CompiledScript.Add(0x3E);
                                        CompiledScript.AddRange(BitConverter.GetBytes(short.Parse(
                                            instructions[CurrentInstruction].Arguments[2])));
                                        break;
                                    }
                            }

                            bool hasAddress = CompilerHelper.ExistsLabel(labels, instructions[CurrentInstruction].Arguments[3]);

                            if (hasAddress)
                            {
                                var existingLabel = CompilerHelper.GetLabel(labels, instructions[CurrentInstruction].Arguments[3]);
                                CompiledScript.AddRange(BitConverter.GetBytes(existingLabel.Address));
                            }
                            else if (!hasAddress)
                            {
                                var newLabel = new Label
                                {
                                    Name = instructions[CurrentInstruction].Arguments[3],
                                    Address = CompiledScript.Count
                                };
                                pendingLabels.Add(newLabel);
                                CompiledScript.AddRange(new byte[4]); //Placeholder of 4 bytes
                            }
                            break;
                        }
                    case "CgFull":
                        {
                            CompiledScript.Add(0x46);

                            //We check to see if the string is already in the list of strings
                            int StringPosition = CompilerHelper.GetPositionStringList(strings,
                                instructions[CurrentInstruction].Arguments[0]);

                            //If it is not, we add it to the list of strings and add the position of the string in the list
                            if (StringPosition != -1)
                            {
                                strings.Add(instructions[CurrentInstruction].Arguments[0]);
                                CompiledScript.AddRange(BitConverter.GetBytes(strings.Count - 1));
                            }
                            else
                            {
                                CompiledScript.AddRange(BitConverter.GetBytes(StringPosition));
                            }
                            break;
                        }
                    case "CgFullClear":
                        {
                            CompiledScript.Add(0x47);
                            break;
                        }
                    case "CgMid":
                        {
                            CompiledScript.Add(0x48);

                            CompiledScript.Add(byte.Parse(instructions[CurrentInstruction].Arguments[0]));
                            CompiledScript.AddRange(BitConverter.GetBytes(int.Parse(instructions[CurrentInstruction].Arguments[1])));

                            //We check to see if the string is already in the list of strings
                            int StringPosition = CompilerHelper.GetPositionStringList(strings,
                                instructions[CurrentInstruction].Arguments[2]);

                            //If it is not, we add it to the list of strings and add the position of the string in the list
                            if (StringPosition != -1)
                            {
                                strings.Add(instructions[CurrentInstruction].Arguments[2]);
                                CompiledScript.AddRange(BitConverter.GetBytes(strings.Count - 1));
                            }
                            else
                            {
                                CompiledScript.AddRange(BitConverter.GetBytes(StringPosition));
                            }
                            break;
                        }
                    case "CgMidAuto":
                        {
                            CompiledScript.Add(0x49);

                            CompiledScript.Add(byte.Parse(instructions[CurrentInstruction].Arguments[0]));

                            //We check to see if the string is already in the list of strings
                            int StringPosition = CompilerHelper.GetPositionStringList(strings,
                                instructions[CurrentInstruction].Arguments[1]);

                            //If it is not, we add it to the list of strings and add the position of the string in the list
                            if (StringPosition != -1)
                            {
                                strings.Add(instructions[CurrentInstruction].Arguments[1]);
                                CompiledScript.AddRange(BitConverter.GetBytes(strings.Count - 1));
                            }
                            else
                            {
                                CompiledScript.AddRange(BitConverter.GetBytes(StringPosition));
                            }
                            break;
                        }
                    case "CgMidMove":
                        {
                            CompiledScript.Add(0x4A);

                            CompiledScript.Add(byte.Parse(instructions[CurrentInstruction].Arguments[0]));
                            CompiledScript.AddRange(BitConverter.GetBytes(int.Parse(instructions[CurrentInstruction].Arguments[1])));
                            break;
                        }
                    case "CgMidXY":
                        {
                            CompiledScript.Add(0x4B);

                            CompiledScript.Add(byte.Parse(instructions[CurrentInstruction].Arguments[0]));
                            CompiledScript.AddRange(BitConverter.GetBytes(int.Parse(instructions[CurrentInstruction].Arguments[1])));
                            CompiledScript.AddRange(BitConverter.GetBytes(int.Parse(instructions[CurrentInstruction].Arguments[2])));
                            break;
                        }
                    case "GetMiddlePos":
                        {
                            CompiledScript.Add(0x4C);

                            CompiledScript.Add(byte.Parse(instructions[CurrentInstruction].Arguments[0]));
                            CompiledScript.AddRange(CompilerHelper.EncodeParameters
                                    (instructions[CurrentInstruction].Arguments[1]));
                            break;
                        }
                    case "CgFullMidClear":
                        {
                            CompiledScript.Add(0x4D);
                            CompiledScript.AddRange(new byte[] { 0x00, 0x4D, 0x01, 0x4D, 0x02, 0x4D, 0x03, 0x4D, 0x05,
                                0x4D, 0x06, 0x4D, 0x07, 0x4D, 0x08, 0x4D, 0x09, 0x46 });

                            //We check to see if the string is already in the list of strings
                            int StringPosition = CompilerHelper.GetPositionStringList(strings,
                                instructions[CurrentInstruction].Arguments[0]);

                            //If it is not, we add it to the list of strings and add the position of the string in the list
                            if (StringPosition != -1)
                            {
                                strings.Add(instructions[CurrentInstruction].Arguments[0]);
                                CompiledScript.AddRange(BitConverter.GetBytes(strings.Count - 1));
                            }
                            else
                            {
                                CompiledScript.AddRange(BitConverter.GetBytes(StringPosition));
                            }
                            break;
                        }
                    case "CgMidClearAll":
                        {
                            CompiledScript.Add(0x4D);
                            CompiledScript.AddRange(new byte[] { 0x00, 0x4D, 0x01, 0x4D, 0x02, 0x4D, 0x03, 0x4D, 0x05,
                                0x4D, 0x06, 0x4D, 0x07, 0x4D, 0x08, 0x4D, 0x09 });
                            break;
                        }
                    case "CgMidClear":
                        {
                            CompiledScript.Add(0x4D);

                            CompiledScript.Add(byte.Parse(instructions[CurrentInstruction].Arguments[0]));
                            break;
                        }
                    //TO DO (0x4E is done correctly, but EFFECT uses more opcodes)
                    case "Effect":
                        {
                            CompiledScript.Add(0x4E);

                            CompiledScript.Add(byte.Parse(instructions[CurrentInstruction].Arguments[0]));
                            break;
                        }
                    case "CModeFlash":
                        {
                            CompiledScript.Add(0x4F);

                            for (int CurrentArgument = 0; CurrentArgument < 7; CurrentArgument++)
                            {
                                CompiledScript.AddRange(BitConverter.GetBytes(
                                    int.Parse(instructions[CurrentInstruction].Arguments[CurrentArgument])));
                            }
                            break;
                        }
                    case "EffectFlash":
                        {
                            CompiledScript.Add(0x50);

                            CompiledScript.AddRange(BitConverter.GetBytes(
                                short.Parse(instructions[CurrentInstruction].Arguments[0])));
                            break;
                        }
                    case "EffectShake":
                        {
                            CompiledScript.Add(0x51);

                            for (int CurrentArgument = 0; CurrentArgument < 4; CurrentArgument++)
                            {
                                CompiledScript.AddRange(BitConverter.GetBytes(short.Parse(instructions[CurrentInstruction].Arguments[CurrentArgument])));
                            }
                            break;
                        }
                    case "EffectPattern":
                        {
                            CompiledScript.Add(0x52);

                            //We check to see if the string is already in the list of strings
                            int StringPosition = CompilerHelper.GetPositionStringList(strings,
                                instructions[CurrentInstruction].Arguments[0]);

                            //If it is not, we add it to the list of strings and add the position of the string in the list
                            if (StringPosition != -1)
                            {
                                strings.Add(instructions[CurrentInstruction].Arguments[0]);
                                CompiledScript.AddRange(BitConverter.GetBytes(strings.Count - 1));
                            }
                            else
                            {
                                CompiledScript.AddRange(BitConverter.GetBytes(StringPosition));
                            }
                            break;
                        }
                    case "EffectScroll":
                        {
                            CompiledScript.Add(0x53);

                            CompiledScript.AddRange(BitConverter.GetBytes(
                                short.Parse(instructions[CurrentInstruction].Arguments[0])));

                            //We check to see if the string is already in the list of strings
                            int StringPosition = CompilerHelper.GetPositionStringList(strings,
                                instructions[CurrentInstruction].Arguments[1]);

                            //If it is not, we add it to the list of strings and add the position of the string in the list
                            if (StringPosition != -1)
                            {
                                strings.Add(instructions[CurrentInstruction].Arguments[1]);
                                CompiledScript.AddRange(BitConverter.GetBytes(strings.Count - 1));
                            }
                            else
                            {
                                CompiledScript.AddRange(BitConverter.GetBytes(StringPosition));
                            }
                            break;
                        }
                    case "EFE":
                        {
                            CompiledScript.Add(0x54);

                            CompiledScript.Add(byte.Parse(instructions[CurrentInstruction].Arguments[0]));
                            break;
                        }
                    case "EffectEnvStop":
                        {
                            CompiledScript.Add(0x55);
                            break;
                        }
                    case "EffectEnvStopNoCreate":
                        {
                            CompiledScript.Add(0x56);
                            break;
                        }
                    case "ColorFill":
                        {
                            CompiledScript.Add(0x57);

                            for (int CurrentArgument = 0; CurrentArgument < 3; CurrentArgument++)
                            {
                                CompiledScript.Add(byte.Parse(instructions[CurrentInstruction].Arguments[CurrentArgument]));
                            }
                            for (int CurrentArgument = 3; CurrentArgument < 5; CurrentArgument++)
                            {
                                CompiledScript.AddRange(BitConverter.GetBytes(short.Parse(instructions[CurrentInstruction].Arguments[CurrentArgument])));
                            }
                            break;
                        }
                    case "ColorModeNone":
                        {
                            CompiledScript.Add(0x58);

                            CompiledScript.AddRange(BitConverter.GetBytes(int.Parse(instructions[CurrentInstruction].Arguments[0])));
                            CompiledScript.Add(byte.Parse(instructions[CurrentInstruction].Arguments[1]));
                            CompiledScript.Add(byte.Parse(instructions[CurrentInstruction].Arguments[2]));
                            CompiledScript.Add(byte.Parse(instructions[CurrentInstruction].Arguments[3]));
                            break;
                        }
                    case "ColorModeDark":
                        {
                            CompiledScript.Add(0x58);

                            CompiledScript.AddRange(BitConverter.GetBytes(int.Parse(instructions[CurrentInstruction].Arguments[0])));
                            CompiledScript.Add(byte.Parse(instructions[CurrentInstruction].Arguments[1]));
                            CompiledScript.Add(byte.Parse(instructions[CurrentInstruction].Arguments[2]));
                            CompiledScript.Add(byte.Parse(instructions[CurrentInstruction].Arguments[3]));
                            break;
                        }
                    case "ColorModeLight":
                        {
                            CompiledScript.Add(0x58);

                            CompiledScript.AddRange(BitConverter.GetBytes(int.Parse(instructions[CurrentInstruction].Arguments[0])));
                            CompiledScript.Add(byte.Parse(instructions[CurrentInstruction].Arguments[1]));
                            CompiledScript.Add(byte.Parse(instructions[CurrentInstruction].Arguments[2]));
                            CompiledScript.Add(byte.Parse(instructions[CurrentInstruction].Arguments[3]));
                            break;
                        }
                    case "ColorModeSepia":
                        {
                            CompiledScript.Add(0x58);

                            CompiledScript.AddRange(BitConverter.GetBytes(int.Parse(instructions[CurrentInstruction].Arguments[0])));
                            CompiledScript.Add(byte.Parse(instructions[CurrentInstruction].Arguments[1]));
                            CompiledScript.Add(byte.Parse(instructions[CurrentInstruction].Arguments[2]));
                            CompiledScript.Add(byte.Parse(instructions[CurrentInstruction].Arguments[3]));
                            break;
                        }
                    case "ColorModeMono":
                        {
                            CompiledScript.Add(0x58);

                            CompiledScript.AddRange(BitConverter.GetBytes(int.Parse(instructions[CurrentInstruction].Arguments[0])));
                            CompiledScript.Add(byte.Parse(instructions[CurrentInstruction].Arguments[1]));
                            CompiledScript.Add(byte.Parse(instructions[CurrentInstruction].Arguments[2]));
                            CompiledScript.Add(byte.Parse(instructions[CurrentInstruction].Arguments[3]));
                            break;
                        }
                    case "ColorMode":
                        {
                            CompiledScript.Add(0x58);

                            CompiledScript.AddRange(BitConverter.GetBytes(int.Parse(instructions[CurrentInstruction].Arguments[0])));
                            CompiledScript.Add(byte.Parse(instructions[CurrentInstruction].Arguments[1]));
                            CompiledScript.Add(byte.Parse(instructions[CurrentInstruction].Arguments[2]));
                            CompiledScript.Add(byte.Parse(instructions[CurrentInstruction].Arguments[3]));
                            break;
                        }
                    case "EffectEnvLoadAlpha":
                        {
                            CompiledScript.Add(0x59);

                            //We check to see if the string is already in the list of strings
                            int StringPosition = CompilerHelper.GetPositionStringList(strings,
                                instructions[CurrentInstruction].Arguments[0]);

                            //If it is not, we add it to the list of strings and add the position of the string in the list
                            if (StringPosition != -1)
                            {
                                strings.Add(instructions[CurrentInstruction].Arguments[0]);
                                CompiledScript.AddRange(BitConverter.GetBytes(strings.Count - 1));
                            }
                            else
                            {
                                CompiledScript.AddRange(BitConverter.GetBytes(StringPosition));
                            }
                            break;
                        }
                    case "MusicPlay":
                        {
                            CompiledScript.Add(0x5A);

                            CompiledScript.Add(byte.Parse(instructions[CurrentInstruction].Arguments[0]));
                            break;
                        }
                    case "MusicStop":
                        {
                            CompiledScript.Add(0x5B);
                            break;
                        }
                    case "MusicStopFade":
                        {
                            CompiledScript.Add(0x5C);

                            CompiledScript.AddRange(BitConverter.GetBytes(short.Parse(instructions[CurrentInstruction].Arguments[0])));
                            break;
                        }
                    case "SoundEffectPlay":
                        {
                            CompiledScript.Add(0x5D);

                            //We check to see if the string is already in the list of strings
                            int StringPosition = CompilerHelper.GetPositionStringList(strings,
                                instructions[CurrentInstruction].Arguments[0]);

                            //If it is not, we add it to the list of strings and add the position of the string in the list
                            if (StringPosition != -1)
                            {
                                strings.Add(instructions[CurrentInstruction].Arguments[0]);
                                CompiledScript.AddRange(BitConverter.GetBytes(strings.Count - 1));
                            }
                            else
                            {
                                CompiledScript.AddRange(BitConverter.GetBytes(StringPosition));
                            }
                            break;
                        }
                    case "SoundEffectPlayLoop":
                        {
                            CompiledScript.Add(0x5E);

                            //We check to see if the string is already in the list of strings
                            int StringPosition = CompilerHelper.GetPositionStringList(strings,
                                instructions[CurrentInstruction].Arguments[0]);

                            //If it is not, we add it to the list of strings and add the position of the string in the list
                            if (StringPosition != -1)
                            {
                                strings.Add(instructions[CurrentInstruction].Arguments[0]);
                                CompiledScript.AddRange(BitConverter.GetBytes(strings.Count - 1));
                            }
                            else
                            {
                                CompiledScript.AddRange(BitConverter.GetBytes(StringPosition));
                            }
                            break;
                        }
                    case "SoundEffectPlayLoopStop":
                        {
                            CompiledScript.Add(0x5F);
                            break;
                        }
                    case "SoundEffectPlayLoopABCD":
                        {
                            CompiledScript.Add(0x60);

                            CompiledScript.AddRange(BitConverter.GetBytes(short.Parse(instructions[CurrentInstruction].Arguments[0])));

                            //We check to see if the string is already in the list of strings
                            int StringPosition = CompilerHelper.GetPositionStringList(strings,
                                instructions[CurrentInstruction].Arguments[1]);

                            //If it is not, we add it to the list of strings and add the position of the string in the list
                            if (StringPosition != -1)
                            {
                                strings.Add(instructions[CurrentInstruction].Arguments[1]);
                                CompiledScript.AddRange(BitConverter.GetBytes(strings.Count - 1));
                            }
                            else
                            {
                                CompiledScript.AddRange(BitConverter.GetBytes(StringPosition));
                            }
                            break;
                        }
                    case "SoundEffectPlayLoopStopABCD":
                        {
                            CompiledScript.Add(0x61);

                            CompiledScript.AddRange(BitConverter.GetBytes(short.Parse(instructions[CurrentInstruction].Arguments[0])));
                            break;
                        }
                    case "SoundEffectPlayLoopStopABCDALL":
                        {
                            CompiledScript.Add(0x62);
                            break;
                        }
                    case "SoundEffectPitch":
                        {
                            CompiledScript.Add(0x63);

                            //We check to see if the string is already in the list of strings
                            int StringPosition = CompilerHelper.GetPositionStringList(strings,
                                instructions[CurrentInstruction].Arguments[0]);

                            //If it is not, we add it to the list of strings and add the position of the string in the list
                            if (StringPosition != -1)
                            {
                                strings.Add(instructions[CurrentInstruction].Arguments[0]);
                                CompiledScript.AddRange(BitConverter.GetBytes(strings.Count - 1));
                            }
                            else
                            {
                                CompiledScript.AddRange(BitConverter.GetBytes(StringPosition));
                            }
                            break;
                        }
                    case "SoundEffectPitchDefault":
                        {
                            CompiledScript.Add(0x64);

                            //We check to see if the string is already in the list of strings
                            int StringPosition = CompilerHelper.GetPositionStringList(strings,
                                instructions[CurrentInstruction].Arguments[0]);

                            //If it is not, we add it to the list of strings and add the position of the string in the list
                            if (StringPosition != -1)
                            {
                                strings.Add(instructions[CurrentInstruction].Arguments[0]);
                                CompiledScript.AddRange(BitConverter.GetBytes(strings.Count - 1));
                            }
                            else
                            {
                                CompiledScript.AddRange(BitConverter.GetBytes(StringPosition));
                            }
                            break;
                        }
                    case "Sleep":
                        {
                            CompiledScript.Add(0x69);

                            CompiledScript.AddRange(CompilerHelper.EncodeParameters
                                    (instructions[CurrentInstruction].Arguments[0]));
                            break;
                        }
                    case "AnimeFullOn":
                        {
                            CompiledScript.Add(0x6A);
                            break;
                        }
                    case "AnimeFullOff":
                        {
                            CompiledScript.Add(0x6B);
                            break;
                        }
                    case "AnimeMepachiOn":
                        {
                            CompiledScript.Add(0x6C);
                            break;
                        }
                    case "AnimeMepachiOff":
                        {
                            CompiledScript.Add(0x6D);
                            break;
                        }
                    case "AnimeKutiOn":
                        {
                            CompiledScript.Add(0x6E);
                            break;
                        }
                    case "AnimeKutiOff":
                        {
                            CompiledScript.Add(0x6F);
                            break;
                        }
                    case "FontSize":
                        {
                            CompiledScript.Add(0x70);

                            CompiledScript.Add(byte.Parse(instructions[CurrentInstruction].Arguments[0]));
                            break;
                        }
                    case "FontChange":
                        {
                            CompiledScript.Add(0x71);

                            //We check to see if the string is already in the list of strings
                            int StringPosition = CompilerHelper.GetPositionStringList(strings,
                                instructions[CurrentInstruction].Arguments[0]);

                            //If it is not, we add it to the list of strings and add the position of the string in the list
                            if (StringPosition != -1)
                            {
                                strings.Add(instructions[CurrentInstruction].Arguments[0]);
                                CompiledScript.AddRange(BitConverter.GetBytes(strings.Count - 1));
                            }
                            else
                            {
                                CompiledScript.AddRange(BitConverter.GetBytes(StringPosition));
                            }
                            break;
                        }
                    case "FontSetName":
                        {
                            CompiledScript.Add(0x72);

                            //We check to see if the string is already in the list of strings
                            int StringPosition = CompilerHelper.GetPositionStringList(strings,
                                instructions[CurrentInstruction].Arguments[0]);

                            //If it is not, we add it to the list of strings and add the position of the string in the list
                            if (StringPosition != -1)
                            {
                                strings.Add(instructions[CurrentInstruction].Arguments[0]);
                                CompiledScript.AddRange(BitConverter.GetBytes(strings.Count - 1));
                            }
                            else
                            {
                                CompiledScript.AddRange(BitConverter.GetBytes(StringPosition));
                            }
                            break;
                        }
                    case "FontReset":
                        {
                            CompiledScript.Add(0x73);
                            break;
                        }
                    case "PlayCutMovie":
                        {
                            CompiledScript.Add(0x74);

                            for (int CurrentArgument = 0; CurrentArgument < 5; CurrentArgument++)
                            {
                                CompiledScript.AddRange(BitConverter.GetBytes(
                                    short.Parse(instructions[CurrentInstruction].Arguments[CurrentArgument])));
                            }

                            //We check to see if the string is already in the list of strings
                            int StringPosition = CompilerHelper.GetPositionStringList(strings,
                                instructions[CurrentInstruction].Arguments[5]);

                            //If it is not, we add it to the list of strings and add the position of the string in the list
                            if (StringPosition != -1)
                            {
                                strings.Add(instructions[CurrentInstruction].Arguments[5]);
                                CompiledScript.AddRange(BitConverter.GetBytes(strings.Count - 1));
                            }
                            else
                            {
                                CompiledScript.AddRange(BitConverter.GetBytes(StringPosition));
                            }
                            break;
                        }
                    case "PlayCutMovieLoop":
                        {
                            CompiledScript.Add(0x75);

                            for (int CurrentArgument = 0; CurrentArgument < 5; CurrentArgument++)
                            {
                                CompiledScript.AddRange(BitConverter.GetBytes(
                                    short.Parse(instructions[CurrentInstruction].Arguments[CurrentArgument])));
                            }

                            //We check to see if the string is already in the list of strings
                            int StringPosition = CompilerHelper.GetPositionStringList(strings,
                                instructions[CurrentInstruction].Arguments[5]);

                            //If it is not, we add it to the list of strings and add the position of the string in the list
                            if (StringPosition != -1)
                            {
                                strings.Add(instructions[CurrentInstruction].Arguments[5]);
                                CompiledScript.AddRange(BitConverter.GetBytes(strings.Count - 1));
                            }
                            else
                            {
                                CompiledScript.AddRange(BitConverter.GetBytes(StringPosition));
                            }
                            break;
                        }
                    case "PlayMovieRateSet":
                        {
                            CompiledScript.Add(0x76);

                            CompiledScript.AddRange(BitConverter.GetBytes(
                                    short.Parse(instructions[CurrentInstruction].Arguments[0])));
                            CompiledScript.AddRange(BitConverter.GetBytes(
                                    int.Parse(instructions[CurrentInstruction].Arguments[1])));
                            break;
                        }
                    case "PlayMoviePause":
                        {
                            CompiledScript.Add(0x77);

                            CompiledScript.AddRange(BitConverter.GetBytes(
                                    short.Parse(instructions[CurrentInstruction].Arguments[0])));
                            break;
                        }
                    case "ReleaseMovie":
                        {
                            CompiledScript.Add(0x78);
                            break;
                        }
                    case "AntiAliasSet":
                        {
                            CompiledScript.Add(0x7B);

                            CompiledScript.Add(byte.Parse(instructions[CurrentInstruction].Arguments[0]));
                            break;
                        }
                    case "MessageWindowSet":
                        {
                            CompiledScript.Add(0x7C);

                            CompiledScript.Add(byte.Parse(instructions[CurrentInstruction].Arguments[0]));
                            break;
                        }
                    case "SetMepachiTime":
                        {
                            CompiledScript.Add(0x7D);

                            for (int CurrentArgument = 0; CurrentArgument < 3; CurrentArgument++)
                            {
                                CompiledScript.AddRange(BitConverter.GetBytes(
                                    int.Parse(instructions[CurrentInstruction].Arguments[CurrentArgument])));
                            }
                            break;
                        }
                    case "EventInit":
                        {
                            CompiledScript.Add(0x7E);
                            break;
                        }
                    case "EventSet":
                        {
                            CompiledScript.Add(0x7F);

                            for (int CurrentArgument = 0; CurrentArgument < 6; CurrentArgument++)
                            {
                                CompiledScript.AddRange(BitConverter.GetBytes(
                                    int.Parse(instructions[CurrentInstruction].Arguments[CurrentArgument])));
                            }
                            break;
                        }
                    case "timeGetTime":
                        {
                            CompiledScript.Add(0x80);

                            CompiledScript.AddRange(CompilerHelper.EncodeParameters
                                    (instructions[CurrentInstruction].Arguments[0]));
                            break;
                        }
                    case "GetSEPPlayNow":
                        {
                            CompiledScript.Add(0x81);

                            CompiledScript.AddRange(CompilerHelper.EncodeParameters
                                    (instructions[CurrentInstruction].Arguments[0]));
                            break;
                        }
                    case "TextInit":
                        {
                            CompiledScript.Add(0x8C);

                            for (int CurrentArgument = 0; CurrentArgument < 2; CurrentArgument++)
                            {
                                CompiledScript.AddRange(BitConverter.GetBytes(
                                    int.Parse(instructions[CurrentInstruction].Arguments[CurrentArgument])));
                            }
                            break;
                        }
                    case "TextOutSet":
                        {
                            CompiledScript.Add(0x8D);

                            for (int CurrentArgument = 0; CurrentArgument < 4; CurrentArgument++)
                            {
                                CompiledScript.AddRange(BitConverter.GetBytes(
                                    int.Parse(instructions[CurrentInstruction].Arguments[CurrentArgument])));
                            }
                            break;
                        }
                    case "TextOut":
                        {
                            CompiledScript.Add(0x8E);

                            for (int CurrentArgument = 0; CurrentArgument < 4; CurrentArgument++)
                            {
                                CompiledScript.AddRange(BitConverter.GetBytes(
                                    int.Parse(instructions[CurrentInstruction].Arguments[CurrentArgument])));
                            }

                            byte[] result = CompilerHelper.EncodeStringParameters
                                    (instructions[CurrentInstruction].Arguments[4], 0);
                            CompiledScript.AddRange(result);
                            if (result[0] == 0x45)
                            {

                                //We check to see if the string is already in the list of strings
                                int StringPosition = CompilerHelper.GetPositionStringList(strings,
                                    instructions[CurrentInstruction].Arguments[4]);

                                //If it is not, we add it to the list of strings and add the position of the string in the list
                                if (StringPosition != -1)
                                {
                                    strings.Add(instructions[CurrentInstruction].Arguments[4]);
                                    CompiledScript.AddRange(BitConverter.GetBytes(strings.Count - 1));
                                }
                                else
                                {
                                    CompiledScript.AddRange(BitConverter.GetBytes(StringPosition));
                                }
                            }
                            break;
                        }
                    case "TextOutDefault":
                        {
                            CompiledScript.Add(0x8F);

                            //We check to see if the string is already in the list of strings
                            int StringPosition = CompilerHelper.GetPositionStringList(strings,
                                instructions[CurrentInstruction].Arguments[0]);

                            //If it is not, we add it to the list of strings and add the position of the string in the list
                            if (StringPosition != -1)
                            {
                                strings.Add(instructions[CurrentInstruction].Arguments[0]);
                                CompiledScript.AddRange(BitConverter.GetBytes(strings.Count - 1));
                            }
                            else
                            {
                                CompiledScript.AddRange(BitConverter.GetBytes(StringPosition));
                            }
                            break;
                        }
                    case "TextDraw":
                        {
                            CompiledScript.Add(0x90);

                            for (int CurrentArgument = 0; CurrentArgument < 4; CurrentArgument++)
                            {
                                CompiledScript.AddRange(BitConverter.GetBytes(
                                    int.Parse(instructions[CurrentInstruction].Arguments[CurrentArgument])));
                            }
                            break;
                        }
                    case "TextDrawDefault":
                        {
                            CompiledScript.Add(0x91);
                            break;
                        }
                    case "TextDrawFlag":
                        {
                            CompiledScript.Add(0x92);

                            for (int CurrentArgument = 0; CurrentArgument < 2; CurrentArgument++)
                            {
                                CompiledScript.AddRange(CompilerHelper.EncodeParameters
                                    (instructions[CurrentInstruction].Arguments[CurrentArgument]));
                            }

                            for (int CurrentArgument = 2; CurrentArgument < 4; CurrentArgument++)
                            {
                                CompiledScript.AddRange(BitConverter.GetBytes(
                                    int.Parse(instructions[CurrentInstruction].Arguments[CurrentArgument])));
                            }
                            break;
                        }
                    case "CgLoad":
                        {
                            CompiledScript.Add(0x93);

                            CompiledScript.AddRange(BitConverter.GetBytes(
                                int.Parse(instructions[CurrentInstruction].Arguments[0])));

                            //We check to see if the string is already in the list of strings
                            int StringPosition = CompilerHelper.GetPositionStringList(strings,
                                instructions[CurrentInstruction].Arguments[1]);

                            //If it is not, we add it to the list of strings and add the position of the string in the list
                            if (StringPosition != -1)
                            {
                                strings.Add(instructions[CurrentInstruction].Arguments[1]);
                                CompiledScript.AddRange(BitConverter.GetBytes(strings.Count - 1));
                            }
                            else
                            {
                                CompiledScript.AddRange(BitConverter.GetBytes(StringPosition));
                            }
                            break;
                        }
                    case "CgUnLoad":
                        {
                            CompiledScript.Add(0x94);

                            CompiledScript.AddRange(BitConverter.GetBytes(
                                int.Parse(instructions[CurrentInstruction].Arguments[0])));
                            break;
                        }
                    case "CgDrawInit":
                        {
                            CompiledScript.Add(0x95);
                            break;
                        }
                    case "CgInitRect":
                        {
                            CompiledScript.Add(0x96);

                            for (int CurrentArgument = 0; CurrentArgument < 4; CurrentArgument++)
                            {
                                CompiledScript.AddRange(CompilerHelper.EncodeParameters
                                    (instructions[CurrentInstruction].Arguments[CurrentArgument]));
                            }
                            break;
                        }
                    case "CgDraw":
                        {
                            CompiledScript.Add(0x97);

                            CompiledScript.Add(byte.Parse(instructions[CurrentInstruction].Arguments[0]));
                            break;
                        }
                    case "CgShow":
                        {
                            CompiledScript.Add(0x98);

                            for (int CurrentArgument = 0; CurrentArgument < 4; CurrentArgument++)
                            {
                                CompiledScript.AddRange(CompilerHelper.EncodeParameters
                                    (instructions[CurrentInstruction].Arguments[CurrentArgument]));
                            }
                            break;
                        }
                    case "CgDrawKey":
                        {
                            CompiledScript.Add(0x99);

                            CompiledScript.AddRange(BitConverter.GetBytes(int.Parse(instructions[CurrentInstruction].Arguments[0])));

                            for (int CurrentArgument = 1; CurrentArgument < 7; CurrentArgument++)
                            {
                                CompiledScript.AddRange(CompilerHelper.EncodeParameters
                                    (instructions[CurrentInstruction].Arguments[CurrentArgument]));
                            }
                            break;
                        }
                    case "CgDrawColorDodge":
                        {
                            CompiledScript.Add(0x9A);

                            CompiledScript.AddRange(BitConverter.GetBytes(int.Parse(instructions[CurrentInstruction].Arguments[0])));

                            for (int CurrentArgument = 1; CurrentArgument < 7; CurrentArgument++)
                            {
                                CompiledScript.AddRange(CompilerHelper.EncodeParameters
                                    (instructions[CurrentInstruction].Arguments[CurrentArgument]));
                            }
                            break;
                        }
                    case "CgDrawBlendPattern":
                        {
                            CompiledScript.Add(0x9B);

                            CompiledScript.AddRange(BitConverter.GetBytes(int.Parse(instructions[CurrentInstruction].Arguments[0])));

                            for (int CurrentArgument = 1; CurrentArgument < 9; CurrentArgument++)
                            {
                                CompiledScript.AddRange(CompilerHelper.EncodeParameters
                                    (instructions[CurrentInstruction].Arguments[CurrentArgument]));
                            }
                            break;
                        }
                    case "DrawMessageWindow":
                        {
                            CompiledScript.Add(0x9C);
                            break;
                        }
                    case "SaveGetDate":
                        {
                            CompiledScript.Add(0x9D);

                            byte[] result = CompilerHelper.EncodeStringParameters
                                    (instructions[CurrentInstruction].Arguments[0], 1);
                            CompiledScript.AddRange(result);
                            if (result[0] == 0x45)
                            {

                                //We check to see if the string is already in the list of strings
                                int StringPosition = CompilerHelper.GetPositionStringList(strings,
                                    instructions[CurrentInstruction].Arguments[0]);

                                //If it is not, we add it to the list of strings and add the position of the string in the list
                                if (StringPosition != -1)
                                {
                                    strings.Add(instructions[CurrentInstruction].Arguments[0]);
                                    CompiledScript.AddRange(BitConverter.GetBytes(strings.Count - 1));
                                }
                                else
                                {
                                    CompiledScript.AddRange(BitConverter.GetBytes(StringPosition));
                                }
                            }
                            
                            CompiledScript.AddRange(BitConverter.GetBytes(
                                    int.Parse(instructions[CurrentInstruction].Arguments[1])));
                            break;
                        }
                    case "SaveGetTitle":
                        {
                            CompiledScript.Add(0x9E);

                            byte[] result = CompilerHelper.EncodeStringParameters
                                    (instructions[CurrentInstruction].Arguments[0], 1);
                            CompiledScript.AddRange(result);
                            if (result[0] == 0x45)
                            {

                                //We check to see if the string is already in the list of strings
                                int StringPosition = CompilerHelper.GetPositionStringList(strings,
                                    instructions[CurrentInstruction].Arguments[0]);

                                //If it is not, we add it to the list of strings and add the position of the string in the list
                                if (StringPosition != -1)
                                {
                                    strings.Add(instructions[CurrentInstruction].Arguments[0]);
                                    CompiledScript.AddRange(BitConverter.GetBytes(strings.Count - 1));
                                }
                                else
                                {
                                    CompiledScript.AddRange(BitConverter.GetBytes(StringPosition));
                                }
                            }

                            CompiledScript.AddRange(BitConverter.GetBytes(
                                    int.Parse(instructions[CurrentInstruction].Arguments[1])));
                            break;
                        }
                    case "SaveGetMemo":
                        {
                            CompiledScript.Add(0x9F);

                            byte[] result = CompilerHelper.EncodeStringParameters
                                    (instructions[CurrentInstruction].Arguments[0], 1);
                            CompiledScript.AddRange(result);
                            if (result[0] == 0x45)
                            {

                                //We check to see if the string is already in the list of strings
                                int StringPosition = CompilerHelper.GetPositionStringList(strings,
                                    instructions[CurrentInstruction].Arguments[0]);

                                //If it is not, we add it to the list of strings and add the position of the string in the list
                                if (StringPosition != -1)
                                {
                                    strings.Add(instructions[CurrentInstruction].Arguments[0]);
                                    CompiledScript.AddRange(BitConverter.GetBytes(strings.Count - 1));
                                }
                                else
                                {
                                    CompiledScript.AddRange(BitConverter.GetBytes(StringPosition));
                                }
                            }

                            CompiledScript.AddRange(BitConverter.GetBytes(
                                    int.Parse(instructions[CurrentInstruction].Arguments[1])));
                            break;
                        }
                    case "ConfigGetEffect":
                        {
                            CompiledScript.Add(0xA0);

                            CompiledScript.AddRange(CompilerHelper.EncodeParameters(instructions[CurrentInstruction].Arguments[0]));
                            break;
                        }
                    case "SkipGet":
                        {
                            CompiledScript.Add(0xA1);

                            CompiledScript.AddRange(CompilerHelper.EncodeParameters(instructions[CurrentInstruction].Arguments[0]));
                            break;
                        }
                    case "CtrlGet":
                        {
                            CompiledScript.Add(0xA2);

                            CompiledScript.AddRange(CompilerHelper.EncodeParameters(instructions[CurrentInstruction].Arguments[0]));
                            break;
                        }
                    case "MemoryLoad":
                        {
                            CompiledScript.Add(0xA3);
                            break;
                        }
                    case "CharEvent":
                        {
                            CompiledScript.Add(0xB5);
                            break;
                        }
                    case "EventStart":
                        {
                            CompiledScript.Add(0xB7);
                            break;
                        }
                    case "KeyWaitMovie":
                        {
                            CompiledScript.Add(0xB8);
                            break;
                        }
                    case "KeyWait":
                        {
                            CompiledScript.Add(0xB9);
                            break;
                        }
                    case "SelectPrint":
                        {
                            CompiledScript.Add(0xC8);

                            CompiledScript.Add((byte)instructions[CurrentInstruction].Arguments.Count);
                            for (int CurrentArgument = 0; CurrentArgument < instructions[CurrentInstruction].Arguments.Count; CurrentArgument++)
                            {
                                //We check to see if the string is already in the list of strings
                                int StringPosition = CompilerHelper.GetPositionStringList(strings,
                                    instructions[CurrentInstruction].Arguments[CurrentArgument]);
                                //If it is not, we add it to the list of strings and add the position of the string in the list
                                if (StringPosition != -1)
                                {
                                    strings.Add(instructions[CurrentInstruction].Arguments[CurrentArgument]);
                                    CompiledScript.AddRange(BitConverter.GetBytes(strings.Count - 1));
                                }
                                else
                                {
                                    CompiledScript.AddRange(BitConverter.GetBytes(StringPosition));
                                }
                            }

                            break;
                        }
                    case "SelectDefault":
                        {
                            CompiledScript.Add(0xC9);

                            CompiledScript.Add(byte.Parse(instructions[CurrentInstruction].Arguments[0]));
                            break;
                        }
                    case "Program":
                        {
                            CompiledScript.Add(0xF0);

                            for (int CurrentArgument = 0; CurrentArgument < 2; CurrentArgument++)
                            {
                                CompiledScript.AddRange(BitConverter.GetBytes(
                                    int.Parse(instructions[CurrentInstruction].Arguments[CurrentArgument])));
                            }
                            break;
                        }
                    case "Dialogue":
                        {
                            switch (instructions[CurrentInstruction].Arguments.Count)
                            {
                                case 1:
                                    {
                                        CompiledScript.Add(0xE9);

                                        //We check to see if the string is already in the list of strings
                                        int StringPosition = CompilerHelper.GetPositionStringList(strings,
                                            instructions[CurrentInstruction].Arguments[0]);

                                        //If it is not, we add it to the list of strings and add the position of the string in the list
                                        if (StringPosition != -1)
                                        {
                                            strings.Add(instructions[CurrentInstruction].Arguments[0]);
                                            CompiledScript.AddRange(BitConverter.GetBytes(strings.Count - 1));
                                        }
                                        else
                                        {
                                            CompiledScript.AddRange(BitConverter.GetBytes(StringPosition));
                                        }
                                        break;
                                    }
                                case 2:
                                    {
                                        CompiledScript.Add(0xE8);

                                        for (int CurrentArgument = 0; CurrentArgument < 2; CurrentArgument++)
                                        {
                                            //We check to see if the string is already in the list of strings
                                            int StringPosition = CompilerHelper.GetPositionStringList(strings,
                                                instructions[CurrentInstruction].Arguments[CurrentArgument]);

                                            //If it is not, we add it to the list of strings and add the position of the string in the list
                                            if (StringPosition != -1)
                                            {
                                                strings.Add(instructions[CurrentInstruction].Arguments[CurrentArgument]);
                                                CompiledScript.AddRange(BitConverter.GetBytes(strings.Count - 1));
                                            }
                                            else
                                            {
                                                CompiledScript.AddRange(BitConverter.GetBytes(StringPosition));
                                            }
                                        }
                                        break;
                                    }
                                case 3:
                                    {
                                        CompiledScript.Add(0xE7);

                                        CompiledScript.AddRange(BitConverter.GetBytes(
                                            int.Parse(instructions[CurrentInstruction].Arguments[0])));

                                        for (int CurrentArgument = 1; CurrentArgument < 3; CurrentArgument++)
                                        {
                                            //We check to see if the string is already in the list of strings
                                            int StringPosition = CompilerHelper.GetPositionStringList(strings,
                                                instructions[CurrentInstruction].Arguments[CurrentArgument]);

                                            //If it is not, we add it to the list of strings and add the position of the string in the list
                                            if (StringPosition != -1)
                                            {
                                                strings.Add(instructions[CurrentInstruction].Arguments[CurrentArgument]);
                                                CompiledScript.AddRange(BitConverter.GetBytes(strings.Count - 1));
                                            }
                                            else
                                            {
                                                CompiledScript.AddRange(BitConverter.GetBytes(StringPosition));
                                            }
                                        }
                                        break;
                                    }
                                case 4:
                                    {
                                        CompiledScript.Add(0xE6);

                                        CompiledScript.AddRange(BitConverter.GetBytes(
                                            int.Parse(instructions[CurrentInstruction].Arguments[0])));

                                        for (int CurrentArgument = 1; CurrentArgument < 4; CurrentArgument++)
                                        {
                                            //We check to see if the string is already in the list of strings
                                            int StringPosition = CompilerHelper.GetPositionStringList(strings,
                                                instructions[CurrentInstruction].Arguments[CurrentArgument]);

                                            //If it is not, we add it to the list of strings and add the position of the string in the list
                                            if (StringPosition != -1)
                                            {
                                                strings.Add(instructions[CurrentInstruction].Arguments[CurrentArgument]);
                                                CompiledScript.AddRange(BitConverter.GetBytes(strings.Count - 1));
                                            }
                                            else
                                            {
                                                CompiledScript.AddRange(BitConverter.GetBytes(StringPosition));
                                            }
                                        }
                                        break;
                                    }
                            }

                            CompiledScript.AddRange(BitConverter.GetBytes(CurrentDialogueInstruction));
                            CurrentDialogueInstruction++;
                            break;
                        }
                }
            }

            return CompiledScript.ToArray();
        }

        //Function that recreates and encrypts back the decrypted script
        public byte[] Encrypt(byte[] UnencryptedScript)
        {
            //The actual encryption process is a standard XOR one with the key set in place
            int EncryptionKeyIndex = 0;

            //First we create the magic signature array, which is always the same
            byte[] MagicSignature = { 0x00, 0x00, 0x00, 0x01 };

            //Next, we include the decryption key, which we will make it
            //just full of null bytes, because we don't need to put anything
            //specific to it, since the game's decryption process will always be
            //the same no matter what
            byte[] Key = new byte[16];
            Key.Initialize();

            //We now create the final unencrypted script, which will contain the magic signature, encryption key, and the unencrypted script
            byte[] FinalUnencryptedScript = new byte[MagicSignature.Length + Key.Length + UnencryptedScript.Length];
            Buffer.BlockCopy(MagicSignature, 0, FinalUnencryptedScript, 0, MagicSignature.Length);
            Buffer.BlockCopy(Key, 0, FinalUnencryptedScript, MagicSignature.Length, Key.Length);
            Buffer.BlockCopy(UnencryptedScript, 0, FinalUnencryptedScript, MagicSignature.Length + Key.Length, UnencryptedScript.Length);

            //Now we can start the encryption process, which will be done by XORing the unencrypted script with the key
            byte[] EncryptedScript = new byte[FinalUnencryptedScript.Length];
            Buffer.BlockCopy(FinalUnencryptedScript, 0, EncryptedScript, 0, FinalUnencryptedScript.Length);

            //The encryption process will start at the beginning of the unencrypted script
            for (int CurrentOffset = MagicSignature.Length + Key.Length; CurrentOffset < EncryptedScript.Length; CurrentOffset++)
            {
                EncryptedScript[CurrentOffset] = (byte)(Key[EncryptionKeyIndex] ^ FinalUnencryptedScript[CurrentOffset]);
                EncryptionKeyIndex++;

                //Each 16 bytes, the key gets renewed
                if (EncryptionKeyIndex == 16)
                {
                    EncryptionKeyIndex = 0;
                    Key = UpdateKey(Key, FinalUnencryptedScript[CurrentOffset - 1]);
                }
            }

            return EncryptedScript;
        }
    }
}
