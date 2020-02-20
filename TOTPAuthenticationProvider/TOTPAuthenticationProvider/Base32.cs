namespace TOTPAuthenticationProvider.foo
{

    using System;
    using System.Linq;
    public static class Base32
    {
        private const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        public static byte[] ToByteArray(this string input)
        {
            if (string.IsNullOrEmpty(input))
            {
                return new byte[0];
            }

            var bits = input.TrimEnd('=').ToUpper().ToCharArray().Select(c => Convert.ToString(alphabet.IndexOf(c), 2).PadLeft(5, '0')).Aggregate((a, b) => a + b);
            var result = Enumerable.Range(0, bits.Length / 8).Select(i => Convert.ToByte(bits.Substring(i * 8, 8), 2)).ToArray();
            return result;

            #region old
            /*
            if (string.IsNullOrEmpty(input))
            {
                return new byte[0];
            }

            input = input.TrimEnd('=').ToUpper(); //remove padding characters
            var bytes = input.Length * 5 / 8; //this must be TRUNCATED
            var result = new byte[bytes];

            byte curByte = 0;
            var bitsRemaining = 8;
            var mask = 0;
            var arrayIndex = 0;

            foreach (var c in input)
            {
                //var cValue = CharToValue(c);
                var cValue = alphabet.IndexOf(c);
                if (cValue < 0)
                {
                    throw new ArgumentException("Not a Base32 Hex String", "input");
                }

                if (bitsRemaining > 5)
                {
                    mask = cValue << (bitsRemaining - 5);
                    curByte = (byte)(curByte | mask);
                    bitsRemaining -= 5;
                }
                else
                {
                    mask = cValue >> (5 - bitsRemaining);
                    curByte = (byte)(curByte | mask);
                    result[arrayIndex++] = curByte;
                    curByte = (byte)(cValue << (3 + bitsRemaining));
                    bitsRemaining += 3;
                }
            }

            //if we didn't end with a full byte
            if (arrayIndex != bytes)
            {
                result[arrayIndex] = curByte;
            }

            return result;
            */
            #endregion
        }

        public static string ToBase32String(this byte[] input)
        {
            if (input == null || input.Length == 0)
            {
                return string.Empty;
            }

            var bits = input.Select(b => Convert.ToString(b, 2).PadLeft(8, '0')).Aggregate((a, b) => a + b);
            bits = bits.PadRight((int)(Math.Ceiling(bits.Length / 5d) * 5), '0');
            var result = Enumerable.Range(0, bits.Length / 5).Select(i => alphabet.Substring(Convert.ToInt32(bits.Substring(i * 5, 5), 2), 1)).Aggregate((a, b) => a + b);
            result = result.PadRight((int)(Math.Ceiling(result.Length / 8d) * 8), '=');
            return result;

            #region old
            /*
            if (input == null || input.Length == 0)
            {
                return string.Empty;
            }

            var charCount = (int)Math.Ceiling(input.Length / 5d) * 8;
            var result = new char[charCount];

            byte nextChar = 0;
            var bitsRemaining = 5;
            var arrayIndex = 0;

            foreach (var b in input)
            {
                nextChar = (byte)(nextChar | (b >> (8 - bitsRemaining)));
                //result[arrayIndex++] = ValueToChar(nextChar);
                result[arrayIndex++] = alphabet[nextChar];

                if (bitsRemaining < 4)
                {
                    nextChar = (byte)((b >> (3 - bitsRemaining)) & 31);
                    //result[arrayIndex++] = ValueToChar(nextChar);
                    result[arrayIndex++] = alphabet[nextChar];
                    bitsRemaining += 5;
                }

                bitsRemaining -= 3;
                nextChar = (byte)((b << bitsRemaining) & 31);
            }

            //if we didn't end with a full char
            if (arrayIndex != charCount)
            {
                //result[arrayIndex++] = ValueToChar(nextChar);
                result[arrayIndex++] = alphabet[nextChar];
                while (arrayIndex != charCount) result[arrayIndex++] = '='; //padding
            }

            return new string(result);
            */
            #endregion
        }

        //private static int CharToValue(char c)
        //{
        //    var value = (int)c;

        //    //65-90 == uppercase letters
        //    if (value < 91 && value > 64)
        //    {
        //        return value - 65;
        //    }
        //    //50-55 == numbers 2-7
        //    if (value < 56 && value > 49)
        //    {
        //        return value - 24;
        //    }
        //    //97-122 == lowercase letters
        //    if (value < 123 && value > 96)
        //    {
        //        return value - 97;
        //    }

        //    throw new ArgumentException("Character is not a Base32 character.", "c");
        //}

        //private static char ValueToChar(byte b)
        //{
        //    if (b < 26)
        //    {
        //        return (char)(b + 65);
        //    }

        //    if (b < 32)
        //    {
        //        return (char)(b + 24);
        //    }

        //    throw new ArgumentException("Byte is not a value Base32 value.", "b");
        //}

    }
}