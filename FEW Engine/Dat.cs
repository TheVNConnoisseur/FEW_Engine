using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FEW_Engine
{
    class Dat
    {
        public Dat()
        {
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
        public string Parse(byte[] Data)
        {
            //Bytes from offset 4 to 7 include the offset where the script
            //starts in the original file (when decrypted)
            int OffsetScript = BitConverter.ToInt32(Data, 4);
            byte[] UnparsedScript = new byte[Data.Length - OffsetScript];
            Buffer.BlockCopy(Data, OffsetScript, UnparsedScript, 0, UnparsedScript.Length);

            //Since the script file is designed to always have 32-bit integers,
            //when creating exported script file it might leave some empty lines.
            //In order to do a performance-efficient wise approach to this problem,
            //we just check how many empty null bytes are at the end together.
            int BytestoOmit = 0;
            for (int CurrentOffset = Data.Length - 1; CurrentOffset > 0; CurrentOffset--)
            {
                if (Data[CurrentOffset] == 0x00)
                {
                    BytestoOmit++;
                }
                else
                {
                    break;
                }
            }

            //We remove 1 from the value obtained before because the first null
            //byte at the end has still to be taken into consideration in order
            //to detect the last string, but only if there's a byte detected,
            //to avoid an out of bounds exception
            if (BytestoOmit > 0)
            {
                BytestoOmit--;
            }

            int LastByteCopied = 0;
            List<string> ParsedLines = new List<string>();
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            Encoding shiftJIS = Encoding.GetEncoding("shift-jis");

            for (int CurrentOffset = 0; CurrentOffset < UnparsedScript.Length - BytestoOmit; CurrentOffset++)
            {
                if (UnparsedScript[CurrentOffset] == 0x00)
                {
                    //First we need to ensure that there is not a null byte right
                    //at the beginning, causing an exception
                    if (CurrentOffset > LastByteCopied)
                    {
                        byte[] LineBytes = new byte[CurrentOffset - LastByteCopied];
                        Buffer.BlockCopy(UnparsedScript, LastByteCopied, LineBytes, 0, CurrentOffset - LastByteCopied);
                        string LineString = shiftJIS.GetString(LineBytes);
                        ParsedLines.Add(LineString);

                        //We add 1 byte to the last byte copied value because
                        //we want to skip the 0x00 byte when we obtain the next string
                        LastByteCopied = CurrentOffset + 1;
                    }
                }
            }

            //Join all lines with the appropriate line ending, to avoid the new line generated by WriteAllLines function
            string ParsedScript = string.Join("\r\n", ParsedLines);

            return ParsedScript;
        }

        //Function that obtains the binary data that comes after the human readable part after being decrypted.
        //This part still needs to be documented properly in order to be parsed correctly instead of being copied
        //and pasted from each script's original version
        public byte[] ObtainBinaryInstructions(byte[] Data)
        {
            //The part that we do not understand starts after the magic signature (4 bytes) and
            //the encryption key (16 bytes), and ends when the actual script starts. Since here
            //we have already eliminated those first 20 bytes, we just need to take out the script
            //from the original byte array and set to 0 the offset for the actual script
            int OffsetScript = BitConverter.ToInt32(Data, 4);
            byte[] BinaryInstructions = new byte[OffsetScript];

            //Copy the part of the entire script file that we are interested into
            Buffer.BlockCopy(Data, 0, BinaryInstructions, 0, OffsetScript);

            //Setting the offset's script to 0
            BinaryInstructions[4] = 0x00;
            BinaryInstructions[5] = 0x00;
            BinaryInstructions[6] = 0x00;
            BinaryInstructions[7] = 0x00;

            return BinaryInstructions;
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
