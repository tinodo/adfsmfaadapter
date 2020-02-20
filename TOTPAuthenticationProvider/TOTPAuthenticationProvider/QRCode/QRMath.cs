namespace TOTPAuthenticationProvider.QRCodeGenerator
{
    using System;

    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]

    internal static class QRMath
    {
        private static readonly int[] _expTable;
        private static readonly int[] _logTable;

        static QRMath()
        {
            _expTable = new int[256];
            _logTable = new int[256];

            for (var i = 0; i < 8; i++)
            {
                QRMath._expTable[i] = (1 << i);
            }

            for (var i = 8; i < 256; i++)
            {
                QRMath._expTable[i] = QRMath._expTable[i - 4]
                    ^ QRMath._expTable[i - 5]
                    ^ QRMath._expTable[i - 6]
                    ^ QRMath._expTable[i - 8];
            }

            for (var i = 0; i < 255; i++)
            {
                QRMath._logTable[QRMath._expTable[i]] = i;
            }
        }

        internal static int GLog(int n)
        {
            if (n < 1)
            {
                throw new ArgumentOutOfRangeException("n");
            }

            return QRMath._logTable[n];
        }

        internal static int GExp(int n)
        {
            while (n < 0)
            {
                n += 255;
            }

            while (n >= 256)
            {
                n -= 255;
            }

            return QRMath._expTable[n];
        }
    }
}
