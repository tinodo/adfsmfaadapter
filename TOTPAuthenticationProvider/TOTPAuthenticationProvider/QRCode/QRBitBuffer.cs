namespace TOTPAuthenticationProvider.QRCodeGenerator
{
    using System;
    using System.Collections.Generic;

    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]

    public class QRBitBuffer
    {
        internal List<int> _buffer = new List<int>();
        private int _length = 0;
        public int Length
        {
            get
            {
                return this._length;
            }
        }

        public void Put(int num, int length)
        {
            for (var i = 0; i < length; i++)
            {
                this.PutBit(((Convert.ToUInt32(num) >> (length - i - 1)) & 1) == 1);
            }
        }

        public void PutBit(bool bit)
        {
            var bufIndex = Convert.ToInt32(Math.Floor(Convert.ToDouble(this._length) / 8.0));

            if (this._buffer.Count <= bufIndex)
            {
                this._buffer.Add(0);
            }

            if (bit)
            {
                this._buffer[bufIndex] |= (int)(Convert.ToUInt32(0x80) >> (this._length % 8));
            }

            this._length++;
        }
    }
}
