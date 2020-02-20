namespace TOTPAuthenticationProvider.QRCodeGenerator
{
    using System;

    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]

    internal static class QRUtil
    {
        internal const int G15 = (1 << 10) | (1 << 8) | (1 << 5) | (1 << 4) | (1 << 2) | (1 << 1) | (1 << 0);
        internal const int G18 = (1 << 12) | (1 << 11) | (1 << 10) | (1 << 9) | (1 << 8) | (1 << 5) | (1 << 2) | (1 << 0);
        internal const int G15_MASK = (1 << 14) | (1 << 12) | (1 << 10) | (1 << 4) | (1 << 1);
        internal static readonly int[][] PATTERN_POSITION_TABLE = new int[][] {
            new int[] {},
            new int [] {6, 18},
            new int [] {6, 22},
            new int [] {6, 26},
            new int [] {6, 30},
            new int [] {6, 34},
            new int [] {6, 22, 38},
            new int [] {6, 24, 42},
            new int [] {6, 26, 46},
            new int [] {6, 28, 50},
            new int [] {6, 30, 54},
            new int [] {6, 32, 58},
            new int [] {6, 34, 62},
            new int [] {6, 26, 46, 66},
            new int [] {6, 26, 48, 70},
            new int [] {6, 26, 50, 74},
            new int [] {6, 30, 54, 78},
            new int [] {6, 30, 56, 82},
            new int [] {6, 30, 58, 86},
            new int [] {6, 34, 62, 90},
            new int [] {6, 28, 50, 72, 94},
            new int [] {6, 26, 50, 74, 98},
            new int [] {6, 30, 54, 78, 102},
            new int [] {6, 28, 54, 80, 106},
            new int [] {6, 32, 58, 84, 110},
            new int [] {6, 30, 58, 86, 114},
            new int [] {6, 34, 62, 90, 118},
            new int [] {6, 26, 50, 74, 98, 122},
            new int [] {6, 30, 54, 78, 102, 126},
            new int [] {6, 26, 52, 78, 104, 130},
            new int [] {6, 30, 56, 82, 108, 134},
            new int [] {6, 34, 60, 86, 112, 138},

            new int [] {6, 30, 58, 86, 114, 142},
            new int [] {6, 34, 62, 90, 118, 146},
            new int [] {6, 30, 54, 78, 102, 126, 150},
            new int [] {6, 24, 50, 76, 102, 128, 154},
            new int [] {6, 28, 54, 80, 106, 132, 158},
            new int [] {6, 32, 58, 84, 110, 136, 162},
            new int [] {6, 26, 54, 82, 110, 138, 166},
            new int [] {6, 30, 58, 86, 114, 142, 170}
        };
        internal static int GetLengthInBits(int type)
        {
            if (1 <= type && type < 10)
            {
                // 1 - 9
                return 8;
            }
            else if (type < 27)
            {
                // 10 - 26
                return 16;
            }
            else if (type < 41)
            {
                // 27 - 40
                return 16;
            }

            throw new Exception("type:" + type);
        }

        internal static double GetLostPoint(QRCode qrCode)
        {
            var moduleCount = qrCode.ModuleCount;
            var lostPoint = 0.0;

            for (var row = 0; row < moduleCount; row++)
            {
                for (var col = 0; col < moduleCount; col++)
                {

                    var sameCount = 0;
                    var dark = qrCode.IsDark(row, col);

                    for (var r = -1; r <= 1; r++)
                    {

                        if (row + r < 0 || moduleCount <= row + r)
                        {
                            continue;
                        }

                        for (var c = -1; c <= 1; c++)
                        {

                            if (col + c < 0 || moduleCount <= col + c)
                            {
                                continue;
                            }

                            if (r == 0 && c == 0)
                            {
                                continue;
                            }

                            if (dark == qrCode.IsDark((int)((int)row + r), (int)((int)col + c)))
                            {
                                sameCount++;
                            }
                        }
                    }

                    if (sameCount > 5)
                    {
                        lostPoint += (3 + sameCount - 5);
                    }
                }
            }

            // LEVEL2

            for (var row = 0; row < moduleCount - 1; row++)
            {
                for (var col = 0; col < moduleCount - 1; col++)
                {
                    var count = 0;

                    if (qrCode.IsDark(row, col))
                    {
                        count++;
                    }

                    if (qrCode.IsDark(row + 1, col))
                    {
                        count++;
                    }

                    if (qrCode.IsDark(row, col + 1))
                    {
                        count++;
                    }

                    if (qrCode.IsDark(row + 1, col + 1))
                    {
                        count++;
                    }

                    if (count == 0 || count == 4)
                    {
                        lostPoint += 3;
                    }
                }
            }

            // LEVEL3

            for (var row = 0; row < moduleCount; row++)
            {
                for (var col = 0; col < moduleCount - 6; col++)
                {
                    if (qrCode.IsDark(row, col)
                            && !qrCode.IsDark(row, col + 1)
                            && qrCode.IsDark(row, col + 2)
                            && qrCode.IsDark(row, col + 3)
                            && qrCode.IsDark(row, col + 4)
                            && !qrCode.IsDark(row, col + 5)
                            && qrCode.IsDark(row, col + 6))
                    {
                        lostPoint += 40.0;
                    }
                }
            }

            for (var col = 0; col < moduleCount; col++)
            {
                for (var row = 0; row < moduleCount - 6; row++)
                {
                    if (qrCode.IsDark(row, col)
                            && !qrCode.IsDark(row + 1, col)
                            && qrCode.IsDark(row + 2, col)
                            && qrCode.IsDark(row + 3, col)
                            && qrCode.IsDark(row + 4, col)
                            && !qrCode.IsDark(row + 5, col)
                            && qrCode.IsDark(row + 6, col))
                    {
                        lostPoint += 40;
                    }
                }
            }

            // LEVEL4
            var darkCount = 0;

            for (var col = 0; col < moduleCount; col++)
            {
                for (var row = 0; row < moduleCount; row++)
                {
                    if (qrCode.IsDark(row, col))
                    {
                        darkCount++;
                    }
                }
            }

            var ratio = Math.Abs(100.0 * Convert.ToDouble(darkCount) / Convert.ToDouble(moduleCount) / Convert.ToDouble(moduleCount) - 50.0) / 5.0;
            lostPoint += ratio * 10.0;
            return lostPoint;
        }

        internal static int GetBCHTypeInfo(int data)
        {
            var d = (data << 10);
            var s = 0;

            while ((s = (int)(QRUtil.GetBCHDigit(d) - QRUtil.GetBCHDigit(QRUtil.G15))) >= 0)
            {
                d ^= (Convert.ToInt32(QRUtil.G15) << s);
            }

            return ((data << 10) | d) ^ QRUtil.G15_MASK;
        }

        internal static int GetBCHTypeNumber(int data)
        {
            var d = data << 12;

            while (QRUtil.GetBCHDigit(d) - QRUtil.GetBCHDigit(QRUtil.G18) >= 0)
            {
                d ^= (QRUtil.G18 << (QRUtil.GetBCHDigit(d) - QRUtil.GetBCHDigit(QRUtil.G18)));
            }

            return (data << 12) | d;
        }

        internal static int GetBCHDigit(int dataInt)
        {
            var digit = 0;
            var data = Convert.ToUInt32(dataInt);

            while (data != 0)
            {
                digit++;
                data >>= 1;
            }

            return digit;
        }

        internal static bool GetMask(QRMaskPattern maskPattern, int i, int j)
        {
            switch (maskPattern)
            {

                case QRMaskPattern.PATTERN000: return (i + j) % 2 == 0;
                case QRMaskPattern.PATTERN001: return i % 2 == 0;
                case QRMaskPattern.PATTERN010: return j % 3 == 0;
                case QRMaskPattern.PATTERN011: return (i + j) % 3 == 0;
                case QRMaskPattern.PATTERN100: return (Math.Floor(Convert.ToDouble(i) / 2.0) + Math.Floor(Convert.ToDouble(j) / 3.0)) % 2 == 0;
                case QRMaskPattern.PATTERN101: return (i * j) % 2 + (i * j) % 3 == 0;
                case QRMaskPattern.PATTERN110: return ((i * j) % 2 + (i * j) % 3) % 2 == 0;
                case QRMaskPattern.PATTERN111: return ((i * j) % 3 + (i + j) % 2) % 2 == 0;
            }
            throw new Exception("bad maskPattern:" + maskPattern);
        }

        internal static QRPolynomial GetErrorCorrectPolynomial(int errorCorrectLength)
        {
            var a = new QRPolynomial(new DataCache() { 1 }, 0);

            for (var i = 0; i < errorCorrectLength; i++)
            {
                a = a.Multiply(new QRPolynomial(new DataCache() { 1, QRMath.GExp(i) }, 0));
            }

            return a;
        }
    }
}
