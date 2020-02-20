//-----------------------------------------------------------------------
// <copyright file="ConfigurationData.cs" company="Microsoft">
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

    /// <summary>
    /// This class is used to deserialize the configuration file passed through AD FS. It is used to configure the static fields in the <see cref="TOTPAuthenticator"/>. 
    /// </summary>
    [Serializable]
    public class TOTPConfiguration
    {
        public string StoreType { get; set; }
        /// <summary>
        /// Gets or sets the SQL Connection String to the database storing the secrets.
        /// </summary>
        public string ConnectionString { get; set; }

        /// <summary>
        /// Gets or sets the interval for a time-based password. Although configurable, the default is 30 seconds for most authenticator apps.
        /// </summary>
        /// <remarks>
        /// RFC6238 4.1; X represents the time step in seconds (default value X = 30 seconds) and is a system parameter.
        /// </remarks>
        public int ValidityPeriodSeconds { get; set; }

        /// <summary>
        /// Gets or sets the number of intervals to check after the current interval, when a code appears invalid. This is to mitigate time differences between server and client.
        /// </summary>
        public int FutureIntervals { get; set; } // How much time in the future can the client be; in validityPeriodSeconds intervals.

        /// <summary>
        /// Gets or sets the number of intervals to check before the current interval, when a code appears invalid. This is to mitigate time differences between server and client.
        /// </summary>
        public int PastIntervals { get; set; } // How much time in the past can the client be; in validityPeriodSeconds intervals.

        /// <summary>
        /// Gets or sets the length of the secret key. This must be a multiple of 8.
        /// </summary>
        public int SecretKeyLength { get; set; }

        /// <summary>
        /// Gets or sets the length of the lockout period after the maximum number of attempts is exceeded.
        /// </summary>
        public int LockoutDurationInSeconds { get; set; }

        /// <summary>
        /// Gets or sets the maximum number of allowed authentication attempts.
        /// </summary>
        public int MaxAttempts { get; set; }

        /// <summary>
        /// Gets or sets the name of your organization, used in the QR code.
        /// </summary>
        public string CompanyName { get; set;  }

        /// <summary>
        /// Gets or sets the email address for your support organization.
        /// </summary>
        public string SupportEmail { get; set; }

        /// <summary>
        /// Gets or sets the algorithm used to create codes.
        /// </summary>
        /// <remarks>Valid values could be SHA1, SHA256 and SHA512. Some authenticator apps only support SHA1.</remarks>
        public string Algorithm { get; set; }

        /// <summary>
        /// Gets or sets the length of the generated codes.
        /// </summary>
        /// <remarks>It is recommended that the length is either 6 or 8. Some authenticator apps only support 8.</remarks>
        public int CodeLength { get; set; }
    }
}