//-----------------------------------------------------------------------
// <copyright file="TOTPAuthenticator.cs" company="Microsoft">
//  Copyright (c) Microsoft. All rights reserved.
// </copyright>
// <author>Tino Donderwinkel</author>
// 
// THIS CODE AND ANY ASSOCIATED INFORMATION ARE PROVIDED “AS IS” WITHOUT
// WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT
// LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS
// FOR A PARTICULAR PURPOSE. THE ENTIRE RISK OF USE, INABILITY TO USE, OR 
// RESULTS FROM THE USE OF THIS CODE REMAINS WITH THE USER.
//
//-----------------------------------------------------------------------

namespace TOTPAuthenticationProvider
{
    using System;
    using System.Drawing;
    using System.Drawing.Drawing2D;
    using System.Drawing.Imaging;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;
    using System.Web;

    using TOTPAuthenticationProvider.QRCodeGenerator;

    /// <summary>
    /// This class implements Time-Based One-Time Password Authentication.
    /// </summary>
    /// <remarks>
    /// <see cref="https://tools.ietf.org/html/rfc6238">RFC 6238</see>
    /// </remarks>
    public static class TOTPAuthenticator
    {
        #region Private Static Fields

        /// <summary>
        /// The different characters allowed in Base32 encoding.
        /// </summary>
        /// <remarks>
        /// This is a 32-character subset of the twenty-six letters A–Z and six digits 2–7.
        /// <see cref="https://en.wikipedia.org/wiki/Base32" />
        /// </remarks>
        private const string Base32AllowedCharacters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

        /// <summary>
        /// The different characters allowed in a secret key.
        /// </summary>
        /// <remarks>
        /// Secret keys do not have to be human readable.
        /// </remarks>
        private const string SecretKeyAllowedCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";

        /// <summary>
        /// The beginning of time according to Unix; January 1st, 1970.
        /// </summary>
        /// <remarks>
        /// RFC6238 4.1; T0 is the Unix time to start counting time steps (default value is 0, i.e., the Unix epoch).
        /// </remarks>
        private static readonly DateTime UnixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        /// <summary>
        /// Gets or sets the length of the secret key in Bytes.
        /// </summary>
        /// <remarks>
        /// RFC4226, Section 4. Algorithm Requirements:, R6 - The algorithm MUST use a strong shared secret.
        /// The length of the shared secret MUST be at least 128 bits. This document RECOMMENDs a shared secret length of 160 bits.
        /// If this value is set to 0, the length is determined on the HASH algortihm used.
        /// </remarks>
        private static int secretKeyLength = 0;

        /// <summary>
        /// Gets or sets the implementation of the store interface.
        /// </summary>
        private static TOTPAuthenticatorStore store;

        /// <summary>
        /// Gets or sets the interval for a time-based password. Although configurable, the default is 30 seconds for most authenticator apps.
        /// </summary>
        /// <remarks>
        /// RFC6238 4.1; X represents the time step in seconds (default value X = 30 seconds) and is a system parameter.
        /// </remarks>
        private static int validityPeriodSeconds = 30;

        /// <summary>
        /// Gets or sets the maximum number of allowed authentication attempts.
        /// </summary>
        /// <remarks>
        /// This is not part of any RFC, but specific to this implementation.
        /// </remarks>
        private static int maxAttempts = 0;

        /// <summary>
        /// Gets or sets the number of intervals to check after the current interval, when a code appears invalid. This is to mitigate time differences between server and client.
        /// </summary>
        /// <remarks>
        /// See also RFC6238, section 5.2.
        /// </remarks>
        private static int futureIntervals = 1;

        /// <summary>
        /// Gets or sets the number of intervals to check before the current interval, when a code appears invalid. This is to mitigate time differences between server and client.
        /// </summary>
        /// <remarks>
        /// See also RFC6238, section 5.2.
        /// </remarks>
        private static int pastIntervals = 1;

        /// <summary>
        /// Gets or sets the length of the lockout period after the maximum number of attempts is exceeded.
        /// </summary>
        /// <remarks>
        /// This is not part of any RFC, but specific to this implementation.
        /// </remarks>
        private static TimeSpan lockoutDuration = new TimeSpan(0, 30, 0);

        /// <summary>
        /// Gets or sets the length of the generated codes.
        /// </summary>
        /// <remarks>Recommended length is 6 or 8. Some authenticator apps do not support anything else than 8.</remarks>
        private static int codeLength = 6;

        /// <summary>
        /// The background color of the QR Code.
        /// </summary>
        /// <remarks>Typically, white.</remarks>
        private static Brush qrCodeBackgroundColor = Brushes.White;

        /// <summary>
        /// The foreground color of the QR Code.
        /// </summary>
        /// <remarks>Typically, black.</remarks>
        private static Brush qrCodeForegroundColor = Brushes.Black;

        /// <summary>
        /// The base color of the QR Code image.
        /// </summary>
        /// <remarks>Typically, white, the same color as <see cref="qrCodeBackgroundColor"/>.</remarks>
        private static Color qrCodeImageBaseColor = Color.White;

        /// <summary>
        /// The preferred width and height of the QR Code image. We will try to scale to this size, but the actual size might differ.
        /// </summary>
        private static int preferredQrCodeWidth = 200;
        #endregion

        #region Public Static Fields

        /// <summary>
        /// Gets the length of the lockout period after the maximum number of attempts is exceeded.
        /// </summary>
        /// <remarks>This will return null when lockout is not enabled.</remarks>
        public static TimeSpan LockoutDuration
        {
            get
            {
                return TOTPAuthenticator.lockoutDuration;
            }
        }

        /// <summary>
        /// Gets a value indicating whether account lockout is enabled or not.
        /// </summary>
        public static bool LockoutEnabled
        {
            get
            {
                return TOTPAuthenticator.maxAttempts > 0;
            }
        }

        #endregion

        #region Public Static Properties

        /// <summary>
        /// Gets or sets the interval for a time-based password. Although configurable, the default is 30 seconds for most authenticator apps.
        /// </summary>
        /// <remarks>
        /// RFC6238 4.1; X represents the time step in seconds (default value X = 30 seconds) and is a system parameter.
        /// </remarks>
        public static int ValidityPeriodSeconds
        {
            get
            {
                return TOTPAuthenticator.validityPeriodSeconds;
            }

            set
            {
                if (value < 30)
                {
                    throw new ArgumentException("Validity Period should be at least 30 seconds.");
                }
                else
                {
                    TOTPAuthenticator.validityPeriodSeconds = value;
                }
            }
        }

        /// <summary>
        /// Gets or sets the number of intervals to check after the current interval, when a code appears invalid. This is to mitigate time differences between server and client.
        /// </summary>
        public static int FutureIntervals
        {
            get
            {
                return TOTPAuthenticator.futureIntervals;
            }

            set
            {
                if (value >= 0)
                {
                    TOTPAuthenticator.futureIntervals = value;
                }
                else
                {
                    throw new ArgumentException("Future Intervals should be 0 or greater.");
                }
            }
        }

        /// <summary>
        /// Gets or sets the number of intervals to check before the current interval, when a code appears invalid. This is to mitigate time differences between server and client.
        /// </summary>
        public static int PastIntervals
        {
            get
            {
                return TOTPAuthenticator.pastIntervals;
            }

            set
            {
                if (value >= 0)
                {
                    TOTPAuthenticator.pastIntervals = value;
                }
                else
                {
                    throw new ArgumentException("Past Intervals should be 0 or greater.");
                }
            }
        }

        /// <summary>
        /// Gets or sets the length of the secret key.
        /// </summary>
        /// <remarks>
        /// RFC4226, Section 4. Algorithm Requirements:, R6 - The algorithm MUST use a strong shared secret.
        /// The length of the shared secret MUST be at least 128 bits. This document RECOMMENDs a shared secret length of 160 bits.
        /// If this value is set to 0, the length is determined on the HASH algortihm used.
        /// </remarks>
        public static int SecretKeyLength
        {
            get
            {
                return TOTPAuthenticator.secretKeyLength;
            }

            set
            {
                if (value < 16 && value != 0)
                {
                    throw new ArgumentException("Secret Keys need to be at least 16 characters, or 0.");
                }

                TOTPAuthenticator.secretKeyLength = value;
            }
        }

        /// <summary>
        /// Gets or sets the algorithm used to create the codes.
        /// </summary>
        /// <remarks>Defaults to SHA1, but SHA256 and SHA512 are also supported according to the RFC.</remarks>
        public static TOTPAlgorithm CodeAlgorithm = TOTPAlgorithm.HmacSHA1;

        /// <summary>
        /// Gets or sets the length of the generated codes.
        /// </summary>
        /// <remarks>Recommended length is 6 or 8.</remarks>
        public static int CodeLength
        {
            get
            {
                return TOTPAuthenticator.codeLength;
            }

            set
            {
                if (value < 6 || value > 8)
                {
                    throw new ArgumentException("Code should be between 6 and 8 characters.");
                }

                TOTPAuthenticator.codeLength = value;
            }
        }

        /// <summary>
        /// Gets the maximum number of allowed authentication attempts before locking out the user. Or 0 to indicate no locking is to be used.
        /// </summary>
        public static int MaxAttempts
        {
            get
            {
                return TOTPAuthenticator.maxAttempts;
            }
        }

        #endregion

        #region Public Static Methods

        /// <summary>
        /// Sets the SQL Connection String to the database storing the secrets.
        /// </summary>
        /// <param name="storeType">The type of store to use.</param>
        /// <param name="connectionString">The connection string, if required.</param>
        public static void SetStore(string storeType, string connectionString = null)
        {
            TOTPAuthenticator.store = TOTPAuthenticatorStoreFactory.GetStore(storeType, connectionString);
        }

        /// <summary>
        /// Enables locking of accounts in MFA.
        /// </summary>
        /// <param name="maxAttempts">The maximum number of failed attempts before locking the user.</param>
        /// <param name="lockoutDuration">The time the user is locked after <see cref="maxAttempts"/> is reached.</param>
        public static void EnableLockout(int maxAttempts, TimeSpan lockoutDuration)
        {
            if (maxAttempts < 1)
            {
                throw new ArgumentOutOfRangeException("maxAttempts", "Should be at least 1. Use DisableLockout to disable lockout.");
            }

            TOTPAuthenticator.maxAttempts = maxAttempts;
            TOTPAuthenticator.lockoutDuration = lockoutDuration;
        }

        /// <summary>
        /// Disables locking of accounts in MFA.
        /// </summary>
        public static void DisableLockout()
        {
            TOTPAuthenticator.maxAttempts = 0;
        }

        /// <summary>
        /// Gets the HTML IMAGE object which holds the QRCode image.
        /// </summary>
        /// <param name="provider">The string that is shown in the Authenticator App as the organization.</param>
        /// <param name="user">The string that is shown in the Authenticator App the user account.</param>
        /// <param name="secretKey">The Secret Key for which to to create the QRCode. The key will be present in Base32 format.</param>
        /// <param name="altText">The alternative text shown when hovering over the image.</param>
        /// <returns>The string containing the HTML image.</returns>
        public static string GetQrCodeImage(string provider, string user, string secretKey, string altText)
        {
            string result;
            var base32SecretKey = Encoding.UTF8.GetBytes(secretKey).ToBase32String(false);
            provider = HttpUtility.UrlEncode(provider);
            var otpauthString = $"otpauth://totp/{provider}:{user}?secret={base32SecretKey}&issuer={provider}&algorithm={TOTPAuthenticator.CodeAlgorithm}&digits={TOTPAuthenticator.codeLength}&period={TOTPAuthenticator.validityPeriodSeconds}";
            var qrcode = new QRCode(otpauthString);
            qrcode.Make();
            var qrcodeImage = TOTPAuthenticator.CreateBitmap(qrcode, TOTPAuthenticator.preferredQrCodeWidth, TOTPAuthenticator.qrCodeImageBaseColor, TOTPAuthenticator.qrCodeForegroundColor, TOTPAuthenticator.qrCodeBackgroundColor);

            using (qrcodeImage)
            {
                using (var stream = new MemoryStream())
                {
                    qrcodeImage.Save(stream, ImageFormat.Png);
                    var qrcodeImageBytes = stream.ToArray();
                    var qrcodeImageString = Convert.ToBase64String(qrcodeImageBytes);
                    result = $"<img width=\"{qrcodeImage.Width}\" height=\"{qrcodeImage.Height}\" src=\"data:image/png;base64,{qrcodeImageString}\" alt=\"{altText}\"/>";
                }
            }

            return result;
        }


        /* I think this is no longer used.

           /// <summary>
           /// Generate the code for a given secret key, at a specific date and time.
           /// </summary>
           /// <param name="secretKey">The secret key.</param>
           /// <param name="when">The date and time to generate the code for.</param>
           /// <returns>The generated code.</returns>
           public static string GetCode(string secretKey, DateTime when)
           {
               if (string.IsNullOrEmpty(secretKey))
               {
                   throw new ArgumentNullException("secretKey");
               }

               if (secretKey.Length != TOTPAuthenticator.secretKeyLength)
               {
                   throw new ArgumentOutOfRangeException("secretKey");
               }

               if (!secretKey.All(c => TOTPAuthenticator.AllowedCharacters.Contains(c)))
               {
                   throw new ArgumentOutOfRangeException("secretKey");
               }

               if (when < TOTPAuthenticator.UnixEpoch)
               {
                   throw new ArgumentOutOfRangeException("when", "Should be later than 01-01-1970.");
               }

               var interval = TOTPAuthenticator.GetInterval(when);
               var result = TOTPAuthenticator.GetCode(secretKey, interval);
               return result;
           }

        */

        /// <summary>
        /// Checks whether a code is valid for a specific user when assuming it is for the current interval.
        /// </summary>
        /// <param name="upn">The UPN of the the user.</param>
        /// <param name="code">The code provided by the user.</param>
        /// <param name="attempts">The number of attempts to verify a code for the user so far.</param>
        /// <param name="locked">Indication whether the user is locked out or not.</param>
        /// <returns>True, when the code is valid, false otherwise.</returns>
        public static bool CodeIsValid(string upn, string code, out int attempts, out bool locked)
        {
            bool result;
            if (TOTPAuthenticator.TryGetSecretKey(upn, out var secretKey, out attempts, out locked))
            {
                // The user has a secret key, so he or she has been enrolled in TOTP MFA.
                if (locked)
                {
                    result = false;
                }
                else
                {
                    result = TOTPAuthenticator.IsValidCode(secretKey, code, upn, DateTime.UtcNow, out attempts, out locked);
                }
            }
            else
            {
                // The user does not have a secret key, so he or she has not enrolled in TOTP MFA.
                result = false;
                attempts = 0;
                locked = false;
                secretKey = null;
            }

            return result;
        }

        /// <summary>
        /// Tries to get the secret key for a user.
        /// </summary>
        /// <param name="upn">The UPN of the user to get the secret key for.</param>
        /// <param name="secretKey">The secret key for the user, or <c>null</c> when the user is not enrolled in TOTP MFA.</param>
        /// <param name="attempts">The number of attempts to verify a code for the user so far.</param>
        /// <param name="locked">Indication whether the user is locked out or not.</param>
        /// <returns>True, if the operation was successful, false otherwise (when the user is not enrolled in TOTP MFA).</returns>
        /// <remarks>
        /// Keep in mind that the operation might return TRUE, even when the user is locked. Always check the locked out parameter.
        /// Typically, the return value is used to see only if the user has onboarded TOTP MFA or not, if so; check the out parameters for what you need.
        /// This method is private since it exposes the secret key.
        /// </remarks>
        private static bool TryGetSecretKey(string upn, out string secretKey, out int attempts, out bool locked)
        {
            var result = TOTPAuthenticator.store.TryGetSecretKey(upn, out secretKey, out attempts, out locked);
            return result;
        }

        /// <summary>
        /// Determines whether a user has a secret key and is therefore enrolled.
        /// </summary>
        /// <param name="upn">The UPN of the user to get the secret key for.</param>
        /// <param name="attempts">The number of attempts to verify a code for the user so far.</param>
        /// <param name="locked">Indication whether the user is locked out or not.</param>
        /// <returns>True, if the operation was successful, false otherwise (when the user is not enrolled in TOTP MFA).</returns>
        /// <remarks>
        /// Keep in mind that the operation might return TRUE, even when the user is locked. Always check the locked out parameter.
        /// Typically, the return value is used to see only if the user has onboarded TOTP MFA or not, if so; check the out parameters for what you need.
        /// </remarks>
        public static bool HasSecretKey(string upn, out int attempts, out bool locked)
        {
            var result = TOTPAuthenticator.store.TryGetSecretKey(upn, out var _, out attempts, out locked);
            return result;
        }

        /// <summary>
        /// Sets the secret key for a user.
        /// </summary>
        /// <param name="upn">The UPN of the user.</param>
        /// <returns>The secret key for the user.</returns>
        /// <remarks>The UPN is not validated. Since this adapter will be create for use with AD FS, we assume the validation happened there.</remarks>
        public static string CreateSecretKey(string upn)
        {
            var length = TOTPAuthenticator.secretKeyLength;
            if (length == 0)
            {
                switch (TOTPAuthenticator.CodeAlgorithm)
                {
                    case TOTPAlgorithm.HmacSHA1:
                        length = 20;
                        break;
                    case TOTPAlgorithm.HmacSHA256:
                        length = 32;
                        break;
                    case TOTPAlgorithm.HmacSHA512:
                        length = 64;
                        break;
                }
            }

            var secret = TOTPAuthenticator.GenerateSecretKey(length);
            TOTPAuthenticator.store.CreateSecretKey(upn, secret);
            return secret;
        }

        /// <summary>
        /// Converts a Base32 string into the corresponding byte array, using 5 bits per character.
        /// </summary>
        /// <param name="input">The Base32 String</param>
        /// <returns>A byte array containing the properly encoded bytes.</returns>
        public static byte[] ToByteArray(this string input)
        {
            if (string.IsNullOrEmpty(input))
            {
                return new byte[0];
            }

            var bits = input.TrimEnd('=').ToUpper().ToCharArray().Select(c => Convert.ToString(TOTPAuthenticator.Base32AllowedCharacters.IndexOf(c), 2).PadLeft(5, '0')).Aggregate((a, b) => a + b);
            var result = Enumerable.Range(0, bits.Length / 8).Select(i => Convert.ToByte(bits.Substring(i * 8, 8), 2)).ToArray();
            return result;
        }

        /// <summary>
        /// Converts a byte array into a Base32 string.
        /// </summary>
        /// <param name="input">The string to convert to Base32.</param>
        /// <param name="addPadding">Whether or not to add RFC3548 '='-padding to the string.</param>
        /// <returns>A Base32 string.</returns>
        /// <remarks>
        /// https://tools.ietf.org/html/rfc3548#section-2.2 indicates padding MUST be added unless the reference to the RFC tells us otherswise.
        /// https://github.com/google/google-authenticator/wiki/Key-Uri-Format indicates that padding SHOULD be omitted.
        /// To meet both requirements, you can omit padding when required.
        /// </remarks>
        public static string ToBase32String(this byte[] input, bool addPadding = true)
        {
            if (input == null || input.Length == 0)
            {
                return string.Empty;
            }

            var bits = input.Select(b => Convert.ToString(b, 2).PadLeft(8, '0')).Aggregate((a, b) => a + b).PadRight((int)(Math.Ceiling((input.Length * 8) / 5d) * 5), '0');
            var result = Enumerable.Range(0, bits.Length / 5).Select(i => TOTPAuthenticator.Base32AllowedCharacters.Substring(Convert.ToInt32(bits.Substring(i * 5, 5), 2), 1)).Aggregate((a, b) => a + b);
            if (addPadding)
            {
                result = result.PadRight((int)(Math.Ceiling(result.Length / 8d) * 8), '=');
            }
            return result;
        }

        public static string EncodeAsBase32String(this string input, bool addPadding = true)
        {
            if (string.IsNullOrEmpty(input))
            {
                return string.Empty;
            }

            var bytes = Encoding.UTF8.GetBytes(input);
            var result = bytes.ToBase32String(addPadding);
            return result;
        }

        public static string DecodeFromBase32String(this string input)
        {
            if (string.IsNullOrEmpty(input))
            {
                return string.Empty;
            }

            var bytes = input.ToByteArray();
            var result = Encoding.UTF8.GetString(bytes);
            return result;
        }
        #endregion

        #region Protected Static Methods

        /// <summary>
        /// Checks if two strings are identical, always using the same amount of time to prevent a potential security hack.
        /// </summary>
        /// <param name="a">The first string to compare.</param>
        /// <param name="b">The second string to compare.</param>
        /// <returns>True, when the two strings are identical, false otherwise.</returns>
        private static bool ConstantTimeEquals(string a, string b)
        {
            var diff = (uint)a.Length ^ (uint)b.Length;

            for (var i = 0; i < a.Length && i < b.Length; i++)
            {
                diff |= (uint)a[i] ^ (uint)b[i];
            }

            var result = diff == 0;
            return result;
        }

        #endregion

        #region Private Static Methods

        /// <summary>
        /// Checks whether a code is valid for a specific user in a certain time interval.
        /// </summary>
        /// <param name="secretKey">The secret key for the user.</param>
        /// <param name="code">The code the user provided.</param>
        /// <param name="upn">The UPN of the user.</param>
        /// <param name="when">The date and time when the code was issued.</param>
        /// <param name="attempts">The number of attempts to verify a code for the user so far.</param>
        /// <param name="locked">Indication whether the user is locked out or not.</param>
        /// <returns>True, if the code is valid, false otherwise.</returns>
        private static bool IsValidCode(string secretKey, string code, string upn, DateTime when, out int attempts, out bool locked)
        {
            var currentInterval = GetInterval(when);
            var fromInterval = currentInterval - TOTPAuthenticator.pastIntervals;
            var toInterval = currentInterval + TOTPAuthenticator.futureIntervals;

            var success = false;
            for (var interval = fromInterval; interval <= toInterval; interval++)
            {
                if (TOTPAuthenticator.store.CodeWasUsedPreviously(upn, interval))
                {
                    break;
                }

                var intervalCode = TOTPAuthenticator.GetCode(secretKey, interval);
                if (TOTPAuthenticator.ConstantTimeEquals(intervalCode, code))
                {
                    success = true;
                    TOTPAuthenticator.store.AddUsedCode(upn, interval);
                    TOTPAuthenticator.store.CleanupUsedCodes(upn, fromInterval - 1);
                    break;
                }
            }

            if (success)
            {
                // Clean attempts
                TOTPAuthenticator.store.ResetAttempts(upn);
                attempts = 0;
                locked = false; // Potentially, the user *could* be locked... In this PRIVATE method, that's not checked.
            }
            else
            {
                // Update attempts
                attempts = TOTPAuthenticator.store.IncreaseAttempts(upn);

                if (TOTPAuthenticator.LockoutEnabled && attempts >= TOTPAuthenticator.maxAttempts)
                {
                    var lockedUntil = DateTime.UtcNow.Add(TOTPAuthenticator.lockoutDuration);
                    TOTPAuthenticator.store.LockAccount(upn, lockedUntil);
                    locked = true;
                }
                else
                {
                    locked = false;
                }
            }

            return success;
        }

        /// <summary>
        /// Determines whether a code for a user has been used already.
        /// </summary>
        /// <param name="upn">The UPN of the user.</param>
        /// <param name="interval">The interval of the code.</param>
        /// <returns>True, when the code has been used before, false otherwise.</returns>
        //private static bool CodeWasUsedPreviously(string upn, long interval)
        //{
        //    var result = TOTPAuthenticator.store.CodeWasUsedPreviously(upn, interval);
        //    TOTPAuthenticator.store.CleanupUsedCodes(upn, interval - (TOTPAuthenticator.PastIntervals * 2) + 1); // This should be moved somewhere else.
        //    return result;
        //}

        /// <summary>
        /// Increases the number of code verifications by 1 for a specific user.
        /// </summary>
        /// <param name="upn">The UPN of the user.</param>
        /// <param name="locked">Indication whether the user has been locked out or not.</param>
        /// <returns>The new number of attempts.</returns>
        //private static int IncreaseAttempts(string upn, out bool locked)
        //{
        //    var attempts = TOTPAuthenticator.store.IncreaseAttempts(upn);

        //    if (TOTPAuthenticator.LockoutEnabled && attempts >= TOTPAuthenticator.maxAttempts)
        //    {
        //        var lockedUntil = DateTime.UtcNow.Add(TOTPAuthenticator.lockoutDuration);
        //        TOTPAuthenticator.store.LockAccount(upn, lockedUntil);
        //        locked = true;
        //    }
        //    else
        //    {
        //        locked = false;
        //    }

        //    return attempts;
        //}

        /// <summary>
        /// Generates a 'random' secret key.
        /// </summary>
        /// <param name="length">The length of the key.</param>
        /// <returns>The secret key generated.</returns>
        /// <remarks>
        /// The secret key generated is using the letters from the Base32 characterset. This is not a requirement for a secret key, but a convenience thing.
        /// </remarks>
        private static string GenerateSecretKey(int length)
        {
            var result = new StringBuilder();
            var buffer = new byte[sizeof(uint)];

            using (var provider = new RNGCryptoServiceProvider())
            {
                for (var counter = 0; counter < length; counter++)
                {
                    provider.GetBytes(buffer);
                    var num = BitConverter.ToUInt32(buffer, 0);
                    var characterPos = (int)(num % (uint)TOTPAuthenticator.SecretKeyAllowedCharacters.Length);
                    var character = TOTPAuthenticator.SecretKeyAllowedCharacters[characterPos];
                    result.Append(character);
                }
            }

            return result.ToString();
        }

        /// <summary>
        /// Gets a <see cref="Bitmap"/> image for a <see cref="QRCode"/> object. 
        /// </summary>
        /// <param name="qrcode">The <see cref="QRCode"/> object to get a <see cref="Bitmap"/> for.</param>
        /// <param name="preferredSize">The preferred width of the image.</param>
        /// <param name="baseColor">The base color of the image. (Typically White)</param>
        /// <param name="foregroundColor">The foreground color of the QRCode modules. (Typically Black)</param>
        /// <param name="backgroundColor">The background color of the QRCode modules. (Typically White)</param>
        /// <returns>A <see cref="Bitmap"/> object for the <see cref="QRCode"/>.</returns>
        /// <remarks>
        /// This will scale the <see cref="QRCode"/> as close to the preferred width as possible. The <see cref="Bitmap"/> size might not match the required size.
        /// </remarks>
        private static Bitmap CreateBitmap(QRCode qrcode, int preferredSize, Color baseColor, Brush foregroundColor, Brush backgroundColor)
        {
            var pixelsPerModule = Convert.ToInt32(Math.Floor(preferredSize / (decimal)qrcode.ModuleCount));
            var actualSize = qrcode.ModuleCount * pixelsPerModule;
            var bitmap = new Bitmap(actualSize, actualSize, PixelFormat.Format24bppRgb);
            var graphic = Graphics.FromImage(bitmap);

            graphic.InterpolationMode = InterpolationMode.HighQualityBicubic;
            graphic.CompositingQuality = CompositingQuality.HighQuality;
            graphic.Clear(baseColor);

            for (var x = 0; x < actualSize; x += pixelsPerModule)
            {
                for (var y = 0; y < actualSize; y += pixelsPerModule)
                {
                    var isDark = qrcode.IsDark(((y + pixelsPerModule) / pixelsPerModule) - 1, ((x + pixelsPerModule) / pixelsPerModule) - 1);
                    var pixelColor = isDark ? foregroundColor : backgroundColor;
                    var rectangle = new Rectangle(x, y, pixelsPerModule, pixelsPerModule);
                    graphic.FillRectangle(pixelColor, rectangle);
                }
            }

            graphic.Save();
            return bitmap;
        }

        /// <summary>
        /// Gets a (6-number) code for a specific interval, given a secret key.
        /// </summary>
        /// <param name="secretKey">The secret key to calculate the code for.</param>
        /// <param name="interval">The time interval to calculate the code for.</param>
        /// <returns>The code for the secret key at the specified interval.</returns>
        /// <remarks>
        /// This is taken from RFC 6238
        /// </remarks>
        public static string GetCode(string secretKey, long interval)
        {
            var secretKeyBytes = Encoding.UTF8.GetBytes(secretKey);
            var challenge = BitConverter.GetBytes(interval).Reverse().ToArray();

            HashAlgorithm hmac = null;

            switch (TOTPAuthenticator.CodeAlgorithm)
            {
                case TOTPAlgorithm.HmacSHA1:
                    hmac = new HMACSHA1(secretKeyBytes);
                    break;
                case TOTPAlgorithm.HmacSHA256:
                    hmac = new HMACSHA256(secretKeyBytes);
                    break;
                case TOTPAlgorithm.HmacSHA512:
                    hmac = new HMACSHA512(secretKeyBytes);
                    break;
            }

            var hash = hmac.ComputeHash(challenge);
            var offset = hash[hash.Length - 1] & 0xf;
            var truncatedHash = hash[offset] & 0x7f;
            for (var i = 1; i < 4; i++)
            {
                truncatedHash <<= 8;
                truncatedHash |= hash[offset + i] & 0xff;
            }

            truncatedHash %= Convert.ToInt32(Math.Pow(10, TOTPAuthenticator.codeLength));
            var result = truncatedHash.ToString($"D{TOTPAuthenticator.codeLength}");
            return result;
        }


        //private static byte[] Base32ToBytes(string source)
        //{
        //    var bits = source.ToUpper().ToCharArray().Select(c => Convert.ToString(AllowedCharacters.IndexOf(c), 2).PadLeft(5, '0')).Aggregate((a, b) => a + b);
        //    var result = Enumerable.Range(0, bits.Length / 8).Select(i => Convert.ToByte(bits.Substring(i * 8, 8), 2)).ToArray();
        //    return result;
        //}

        /// <summary>
        /// Gets the interval for the given date and time.
        /// </summary>
        /// <param name="dateTime">The date and time to calculate the interval for.</param>
        /// <returns>The calculated interval.</returns>
        public static long GetInterval(DateTime dateTime)
        {
            var elapsedTime = dateTime.ToUniversalTime() - TOTPAuthenticator.UnixEpoch;
            var result = (long)elapsedTime.TotalSeconds / TOTPAuthenticator.validityPeriodSeconds;
            return result;
        }
        #endregion
    }
}