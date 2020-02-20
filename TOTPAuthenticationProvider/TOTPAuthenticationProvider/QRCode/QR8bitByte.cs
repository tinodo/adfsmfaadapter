namespace TOTPAuthenticationProvider.QRCodeGenerator
{
    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
    public struct QR8bitByte
    {
        private string _data { get; set; }

        public QR8bitByte(string data)
        {
            this._data = data;
        }

        public int Length
        {
            get
            {
                return this._data.Length;
            }
        }

        public void Write(QRBitBuffer buffer)
        {
            for (var i = 0; i < this._data.Length; ++i)
            {
                buffer.Put(this._data[i], 8);
            }
        }
    }
}
