using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using System.Windows.Data;
using System.Windows.Media.Animation;

namespace FEW_Engine
{
    public class Instruction
    {
        public string Type { get; set; }
        public string[] Arguments { get; set; }

        public Instruction()
        {
        }
    }
}
