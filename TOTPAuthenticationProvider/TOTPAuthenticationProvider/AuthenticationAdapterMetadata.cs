﻿//-----------------------------------------------------------------------
// <copyright file="AuthenticationAdapterMetadata.cs" company="Microsoft">
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
    using System.Collections.Generic;
    using System.Globalization;

    using Microsoft.IdentityServer.Web.Authentication.External;

    /// <summary>
    /// Implementation of the <see cref="IAuthenticationAdapterMetadata"/>.
    /// </summary>
    public class AuthenticationAdapterMetadata : IAuthenticationAdapterMetadata
    {
        /// <summary>
        /// Gets the administrative name of the authentication adapter.
        /// </summary>
        public string AdminName
        {
            get
            {
                return Resources.AdminName;
            }
        }

        /// <summary>
        /// Gets the identifiers for the authentication methods implemented by the authentication adapter.
        /// </summary>
        /// <remarks>
        /// AD FS requires that, if authentication is successful, the method actually employed will be returned by the
        /// final call to TryEndAuthentication(). If no authentication method is returned, or the method returned is not
        /// one of the methods listed in this property, the authentication attempt will fail.
        /// </remarks>
        public string[] AuthenticationMethods
        {
            get
            {
                return new string[] { "http://schemas.microsoft.com/ws/2012/12/authmethod/otp" };
            }
        }

        /// <summary>
        /// Gets the available language culture identifiers for this authentication adapter.
        /// </summary>
        /// <remarks>
        /// Check <see href="https://msdn.microsoft.com/en-us/library/ee825488(v=cs.20).aspx">MSDN</see> for all language culture identifiers.
        /// </remarks>
        public int[] AvailableLcids
        {
            get
            {
                return new int[] 
                {
                    new CultureInfo("en").LCID,
                    new CultureInfo("nl").LCID,
                    new CultureInfo("no").LCID
                };
            }
        }

        /// <summary>
        /// Gets the description of this authentication adapter, per language culture identifier.
        /// </summary>
        public Dictionary<int, string> Descriptions
        {
            get
            {
                var result = new Dictionary<int, string>();
                foreach (var lcid in this.AvailableLcids)
                {
                    Resources.Culture = new CultureInfo(lcid);
                    result.Add(lcid, Resources.Description);
                }

                return result;
            }
        }

        /// <summary>
        /// Gets the friendly (or display-) name of this authentication adapter, per language culture identifier.
        /// </summary>
        public Dictionary<int, string> FriendlyNames
        {
            get
            {
                var result = new Dictionary<int, string>();
                foreach (var lcid in this.AvailableLcids)
                {
                    Resources.Culture = new CultureInfo(lcid);
                    result.Add(lcid, Resources.FriendlyName);
                }

                return result;
            }
        }

        /// <summary>
        /// Gets the claim types that that the authentication adapter uses to identify the user being authenticated.
        /// </summary>
        /// <remarks>
        /// Note that although the property is an array, only the first element is currently used.
        /// Must be one of the following:
        /// <see href="http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname"></see>
        /// <see href="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"></see>
        /// <see href="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"></see>
        /// <see href="http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid"></see>
        /// </remarks>
        public string[] IdentityClaims
        {
            get
            {
                return new string[] { "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn" };
            }
        }

        /// <summary>
        /// Gets a value indicating whether an identity claim is required for this authentication adapter.
        /// </summary>
        /// <remarks>
        /// All custom authentication providers must return 'true'.
        /// </remarks>
        public bool RequiresIdentity
        {
            get
            {
                return true;
            }
        }
    }
}
