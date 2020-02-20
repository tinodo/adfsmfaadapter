namespace TOTPAuthenticationProvider.QRCodeGenerator
{
    using System.Collections.Generic;
    using System.Linq;

    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
    internal class DataCache : List<int>
    {
        public DataCache(int capacity)
            : base()
        {
            base.AddRange(Enumerable.Repeat(0, capacity).ToList());
        }

        public DataCache()
            : base()
        {

        }
    }
}
