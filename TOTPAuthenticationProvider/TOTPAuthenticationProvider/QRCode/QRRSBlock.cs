namespace TOTPAuthenticationProvider.QRCodeGenerator
{
    using System.Collections.Generic;

    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]

    internal struct QRRSBlock
    {
        private static readonly int[][] RS_BLOCK_TABLE = new int[][] {
                new int [] {1, 26, 19},
                new int [] {1, 44, 34},
                new int [] {1, 70, 55},
                new int [] {1, 100, 80},
                new int [] {1, 134, 108},
                new int [] {2, 86, 68},
                new int [] {2, 98, 78},
                new int [] {2, 121, 97},
                new int [] {2, 146, 116},
                new int [] {2, 86, 68, 2, 87, 69},
                };


        public int DataCount { get; private set; }
        public int TotalCount { get; set; }

        public QRRSBlock(int totalCount, int dataCount)
            : this()
        {
            TotalCount = totalCount;
            DataCount = dataCount;
        }

        public static List<QRRSBlock> GetRSBlocks(int typeNumber)
        {
            var rsBlock = QRRSBlock.RS_BLOCK_TABLE[typeNumber - 1];

            var length = rsBlock.Length / 3;
            var list = new List<QRRSBlock>();

            for (var i = 0; i < length; i++)
            {
                var count = rsBlock[i * 3 + 0];
                var totalCount = rsBlock[i * 3 + 1];
                var dataCount = rsBlock[i * 3 + 2];

                for (var j = 0; j < count; j++)
                {
                    list.Add(new QRRSBlock(totalCount, dataCount));
                }
            }

            return list;
        }

        private static int[] GetRsBlockTable(int typeNumber)
        {
            return QRRSBlock.RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 0];
        }
    }
}
