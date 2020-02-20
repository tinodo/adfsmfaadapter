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
    public class TOTPAuthenticatorStoreException : Exception
    {
        public TOTPAuthenticatorStoreException(string message, Exception innerException) : base(message, innerException)
        {
        }

        public TOTPAuthenticatorStoreException(string message) : base(message)
        {
        }
    }
}
