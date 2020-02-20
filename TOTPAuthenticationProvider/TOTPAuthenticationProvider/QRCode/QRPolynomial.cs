namespace TOTPAuthenticationProvider.QRCodeGenerator
{
    using System;

    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]

    internal struct QRPolynomial
    {
        private int[] _num;

        public QRPolynomial(DataCache num, int shift)
            : this()
        {
            if (num == null)
            {
                throw new ArgumentNullException("num");
            }

            var offset = 0;

            while (offset < num.Count && num[offset] == 0)
            {
                offset++;
            }

            _num = new int[num.Count - offset + shift];

            for (var i = 0; i < num.Count - offset; i++)
            {
                _num[i] = num[i + offset];
            }
        }

        public int Get(int index)
        {
            return _num[index];
        }

        public int GetLength()
        {
            return _num.Length;
        }

        public QRPolynomial Multiply(QRPolynomial e)
        {
            var num = new DataCache(GetLength() + e.GetLength() - 1);

            for (var i = 0; i < GetLength(); i++)
            {
                for (var j = 0; j < e.GetLength(); j++)
                {
                    num[i + j] ^= QRMath.GExp(QRMath.GLog(Get(i)) + QRMath.GLog(e.Get(j)));
                }
            }

            return new QRPolynomial(num, 0);
        }

        public QRPolynomial Mod(QRPolynomial e)
        {
            if (Convert.ToInt64(GetLength()) - Convert.ToInt64(e.GetLength()) < 0L)
            {
                return this;
            }

            var ratio = QRMath.GLog(Get(0)) - QRMath.GLog(e.Get(0));
            var num = new DataCache(GetLength());

            for (var i = 0; i < GetLength(); i++)
            {
                num[i] = Get(i);
            }

            for (var i = 0; i < e.GetLength(); i++)
            {
                num[i] ^= QRMath.GExp(QRMath.GLog(e.Get(i)) + ratio);
            }

            // recursive call
            return new QRPolynomial(num, 0).Mod(e);
        }
    }
}
