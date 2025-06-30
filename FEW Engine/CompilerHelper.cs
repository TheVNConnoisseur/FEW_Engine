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
    }
}
