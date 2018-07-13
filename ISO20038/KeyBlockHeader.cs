using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ConsoleApp1
{
    public class KeyBlockHeader
    {
        public string KeyBlockVersionID { get; set; }
        public int KeyBlockLength { get; set; }
        public string KeyUsage { get; set; }
        public string Algorithm { get; set; }
        public string ModeofUse { get; set; }
        public string KeyVersionNumber { get; set; }
        public string Exportability { get; set; }
        public int NumberofOptionalBlocks { get; set; }
        public string Reserved { get; set; }

        public string FirstOptionalBlockID { get; set; }
        public string OptionalBlockLength { get; set; }
        public string OptionalBlockData { get; set; }

    }
}
