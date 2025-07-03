using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FEW_Engine
{
    //The game uses a label list to make the game go around certain parts of the script (branching paths),
    //so what the game does when compiling the game is first leave a placeholder of 4 bytes at whatever point
    //it wants to jump to, and then it will fill that placeholder with the offset of the instruction
    public class Label
    {
        public string Name { get; set; } //The name of the label, only used for making the code more
                                         //readable (not kept in the compiled script)
        public int Address { get; set; } //The address of the label, which is the offset from the start of the script
    }

    //While the game doesn't necessarily has to abide by this format, generally speaking, all instructions follow the same pattern:
    //a type that defines what said instruction should do, and its arguments which will determine how said instruction should act.
    public class Instruction
    {
        public string Type { get; set; }
        public List<string> Arguments { get; set; }

        public Instruction()
        {
            Arguments = new List<string>();
        }
    }
}
