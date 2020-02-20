//---------------------------------------------------------------------
// QRCode for C#4.0 is translation of QRCode for JavaScript
// https://github.com/jeromeetienne/jquery-qrcode/
//
// Copyright (c) 2009 Kazuhiko Arase
//
// URL: http://www.d-project.com/
//
// Licensed under the MIT license:
//   http://www.opensource.org/licenses/mit-license.php
//
// The word "QR Code" is registered trademark of 
// DENSO WAVE INCORPORATED
//   http://www.denso-wave.com/qrcode/faqpatent-e.html
//
// This code initially was published here:
// https://qrcode4cs.codeplex.com/
//---------------------------------------------------------------------
namespace TOTPAuthenticationProvider.QRCodeGenerator
{
    using System;
    using System.Collections.Generic;
    using System.Text;

    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]

    public class QRCode
    {
        private const int PAD0 = 0xEC;
        private const int PAD1 = 0x11;
        private List<QR8bitByte> dataList = new List<QR8bitByte>();
        private int typeNumber;
        private DataCache dataCache;
        private int moduleCount;

        public int ModuleCount
        {
            get
            {
                return this.moduleCount;
            }
        }

        private bool?[][] modules;

        public QRCode(string text)
        {
            var encoding = new UTF8Encoding();
            byte[] bytes = encoding.GetBytes(text);
            int bits = bytes.Length * 8;

            if (bits <= 152)
            {
                this.typeNumber = 1;
            }
            else if (bits <= 272)
            {
                this.typeNumber = 2;
            }
            else if (bits <= 440)
            {
                this.typeNumber = 3;
            }
            else if (bits <= 640)
            {
                this.typeNumber = 4;
            }
            else if (bits <= 864)
            {
                this.typeNumber = 5;
            }
            else if (bits <= 1088)
            {
                this.typeNumber = 6;
            }
            else if (bits <= 1248)
            {
                this.typeNumber = 7;
            }
            else if (bits <= 1522)
            {
                this.typeNumber = 8;
            }
            else if (bits <= 1856)
            {
                this.typeNumber = 9;
            }
            else if (bits <= 2192)
            {
                this.typeNumber = 10;
            }
            else
            {
                throw new ArgumentOutOfRangeException("text", text, "text too long");
            }

            this.moduleCount = (this.typeNumber * 4) + 17;
            this.dataCache = null;
            this.dataList.Add(new QR8bitByte(text));
        }

        public void Make()
        {
            this.MakeImpl(false, this.GetBestMaskPattern());
        }

        private QRMaskPattern GetBestMaskPattern()
        {
            var minLostPoint = 0.0;
            var pattern = QRMaskPattern.PATTERN000;

            for (var i = 0; i < 8; i++)
            {
                this.MakeImpl(true, (QRMaskPattern)i);
                var lostPoint = QRUtil.GetLostPoint(this);

                if (i == 0 || minLostPoint > lostPoint)
                {
                    minLostPoint = lostPoint;
                    pattern = (QRMaskPattern)i;
                }
            }

            return pattern;
        }

        private void MakeImpl(bool test, QRMaskPattern maskPattern)
        {
            this.modules = new bool?[this.moduleCount][];

            for (int row = 0; row < this.moduleCount; row++)
            {
                this.modules[row] = new bool?[this.moduleCount];

                for (var col = 0; col < this.moduleCount; col++)
                {
                    this.modules[row][col] = null;
                }
            }

            this.SetupPositionProbePattern(0, 0);
            this.SetupPositionProbePattern(this.moduleCount - 7, 0);
            this.SetupPositionProbePattern(0, this.moduleCount - 7);
            this.SetupPositionAdjustPattern();
            this.SetupTimingPattern();
            this.SetupTypeInfo(test, maskPattern);

            if (this.typeNumber >= 7)
            {
                this.SetupTypeNumber(test);
            }

            if (this.dataCache == null)
            {
                this.dataCache = this.CreateData(this.typeNumber, this.dataList);
            }

            this.MapData(this.dataCache, maskPattern);
        }

        public bool IsDark(int row, int col)
        {
            return this.modules[row][col].Value;
        }

        private void SetupTimingPattern()
        {
            for (var r = 8; r < this.moduleCount - 8; r++)
            {
                if (this.modules[r][6] != null)
                {
                    continue;
                }

                this.modules[r][6] = r % 2 == 0;
            }

            for (var c = 8; c < this.moduleCount - 8; c++)
            {
                if (this.modules[6][c] != null)
                {
                    continue;
                }

                this.modules[6][c] = c % 2 == 0;
            }
        }

        private void SetupTypeNumber(bool test)
        {
            var bits = QRUtil.GetBCHTypeNumber(this.typeNumber);

            for (var i = 0; i < 18; i++)
            {
                var mod = !test && ((bits >> i) & 1) == 1;
                this.modules[(int)Math.Floor(Convert.ToDouble(i) / 3.0)][i % 3 + this.moduleCount - 8 - 3] = mod;
            }

            for (var i = 0; i < 18; i++)
            {
                var mod = !test && ((bits >> i) & 1) == 1;
                this.modules[i % 3 + this.moduleCount - 8 - 3][(int)Math.Floor(Convert.ToDouble(i) / 3.0)] = mod;
            }
        }

        private void SetupPositionAdjustPattern()
        {
            var pos = QRUtil.PATTERN_POSITION_TABLE[this.typeNumber - 1];

            for (var i = 0; i < pos.Length; i++)
            {
                for (var j = 0; j < pos.Length; j++)
                {
                    var row = pos[i];
                    var col = pos[j];

                    if (this.modules[row][col] != null)
                    {
                        continue;
                    }

                    for (var r = -2; r <= 2; r++)
                    {
                        for (var c = -2; c <= 2; c++)
                        {
                            if (r == -2 || r == 2 || c == -2 || c == 2 || (r == 0 && c == 0))
                            {
                                this.modules[row + r][col + c] = true;
                            }
                            else
                            {
                                this.modules[row + r][col + c] = false;
                            }
                        }
                    }
                }
            }
        }

        private void SetupTypeInfo(bool test, QRMaskPattern maskPattern)
        {
            var data = (1 << 3) | (int)maskPattern;
            var bits = QRUtil.GetBCHTypeInfo(data);

            // vertical
            for (var i = 0; i < 15; i++)
            {
                var mod = !test && ((bits >> i) & 1) == 1;

                if (i < 6)
                {
                    this.modules[i][8] = mod;
                }
                else if (i < 8)
                {
                    this.modules[i + 1][8] = mod;
                }
                else
                {
                    this.modules[this.moduleCount - 15 + i][8] = mod;
                }
            }

            // horizontal
            for (var i = 0; i < 15; i++)
            {
                var mod = !test && ((bits >> i) & 1) == 1;

                if (i < 8)
                {
                    this.modules[8][this.moduleCount - i - 1] = mod;
                }
                else if (i < 9)
                {
                    this.modules[8][15 - i - 1 + 1] = mod;
                }
                else
                {
                    this.modules[8][15 - i - 1] = mod;
                }
            }

            // fixed module
            this.modules[this.moduleCount - 8][8] = !test;
        }

        private void MapData(DataCache data, QRMaskPattern maskPattern)
        {
            var inc = -1;
            var row = this.moduleCount - 1;
            var bitIndex = 7;
            var byteIndex = 0;

            for (var col = this.moduleCount - 1; col > 0; col -= 2)
            {
                if (col == 6)
                {
                    col--;
                }

                while (true)
                {
                    for (int c = 0; c < 2; c++)
                    {
                        if (this.modules[row][col - c] == null)
                        {
                            var dark = false;

                            if (byteIndex < data.Count)
                            {
                                dark = ((Convert.ToUInt32(data[byteIndex]) >> bitIndex) & 1) == 1;
                            }

                            var mask = QRUtil.GetMask(maskPattern, row, col - c);

                            if (mask)
                            {
                                dark = !dark;
                            }

                            this.modules[row][col - c] = dark;
                            bitIndex--;

                            if (bitIndex == -1)
                            {
                                byteIndex++;
                                bitIndex = 7;
                            }
                        }
                    }

                    row += inc;

                    if (row < 0 || this.moduleCount <= row)
                    {
                        row -= inc;
                        inc = -inc;
                        break;
                    }
                }
            }
        }

        private DataCache CreateData(int typeNumber, List<QR8bitByte> dataList)
        {
            var rsBlocks = QRRSBlock.GetRSBlocks(typeNumber);
            var buffer = new QRBitBuffer();

            for (var i = 0; i < dataList.Count; i++)
            {
                QR8bitByte data = dataList[i];
                buffer.Put(1 << 2, 4);
                buffer.Put(data.Length, QRUtil.GetLengthInBits(typeNumber));
                data.Write(buffer);
            }

            // calc num max data.
            int totalDataCount = 0;

            for (var i = 0; i < rsBlocks.Count; i++)
            {
                totalDataCount += rsBlocks[i].DataCount;
            }

            if (buffer.Length > totalDataCount * 8)
            {
                throw new Exception(string.Format(
                    "code length overflow ({0} > {1})",
                    buffer.Length,
                    totalDataCount * 8));
            }

            // end code
            if (buffer.Length + 4 <= totalDataCount * 8)
            {
                buffer.Put(0, 4);
            }

            // padding
            while (buffer.Length % 8 != 0)
            {
                buffer.PutBit(false);
            }

            // padding
            while (true)
            {
                if (buffer.Length >= totalDataCount * 8)
                {
                    break;
                }

                buffer.Put(QRCode.PAD0, 8);

                if (buffer.Length >= totalDataCount * 8)
                {
                    break;
                }

                buffer.Put(QRCode.PAD1, 8);
            }

            return this.CreateBytes(buffer, rsBlocks);
        }

        private DataCache CreateBytes(QRBitBuffer buffer, List<QRRSBlock> rsBlocks)
        {
            var offset = 0;
            var maxDcCount = 0;
            var maxEcCount = 0;
            var dcdata = new DataCache[rsBlocks.Count];
            var ecdata = new DataCache[rsBlocks.Count];

            for (var r = 0; r < rsBlocks.Count; r++)
            {
                var dcCount = rsBlocks[r].DataCount;
                var ecCount = rsBlocks[r].TotalCount - dcCount;
                maxDcCount = Math.Max(maxDcCount, dcCount);
                maxEcCount = Math.Max(maxEcCount, ecCount);
                dcdata[r] = new DataCache(dcCount);

                for (var i = 0; i < dcdata[r].Count; i++)
                {
                    dcdata[r][i] = 0xff & buffer._buffer[i + offset];
                }

                offset += dcCount;
                var rsPoly = QRUtil.GetErrorCorrectPolynomial(ecCount);
                var rawPoly = new QRPolynomial(dcdata[r], rsPoly.GetLength() - 1);
                var modPoly = rawPoly.Mod(rsPoly);
                ecdata[r] = new DataCache(rsPoly.GetLength() - 1);

                for (var i = 0; i < ecdata[r].Count; i++)
                {
                    int modIndex = i + modPoly.GetLength() - ecdata[r].Count;
                    ecdata[r][i] = (modIndex >= 0) ? modPoly.Get(modIndex) : 0;
                }
            }

            var totalCodeCount = 0;

            for (var i = 0; i < rsBlocks.Count; i++)
            {
                totalCodeCount += rsBlocks[i].TotalCount;
            }

            var data = new DataCache(totalCodeCount);
            var index = 0;

            for (var i = 0; i < maxDcCount; i++)
            {
                for (var r = 0; r < rsBlocks.Count; r++)
                {
                    if (i < dcdata[r].Count)
                    {
                        data[index++] = dcdata[r][i];
                    }
                }
            }

            for (var i = 0; i < maxEcCount; i++)
            {
                for (var r = 0; r < rsBlocks.Count; r++)
                {
                    if (i < ecdata[r].Count)
                    {
                        data[index++] = ecdata[r][i];
                    }
                }
            }

            return data;
        }

        private void SetupPositionProbePattern(int row, int col)
        {
            for (var r = -1; r <= 7; r++)
            {
                if (row + r <= -1 || this.moduleCount <= row + r)
                {
                    continue;
                }

                for (var c = -1; c <= 7; c++)
                {
                    if (col + c <= -1 || this.moduleCount <= col + c)
                    {
                        continue;
                    }

                    if ((0 <= r && r <= 6 && (c == 0 || c == 6))
                            || (0 <= c && c <= 6 && (r == 0 || r == 6))
                            || (2 <= r && r <= 4 && 2 <= c && c <= 4))
                    {
                        this.modules[row + r][col + c] = true;
                    }
                    else
                    {
                        this.modules[row + r][col + c] = false;
                    }
                }
            }
        }
    }
}