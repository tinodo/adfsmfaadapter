//-----------------------------------------------------------------------
// <copyright file="AuthenticationAdapter.cs" company="Microsoft">
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
    using System.Net;
    using System.Security.Claims;
    using System.Xml.Serialization;

    using Microsoft.IdentityServer.Web.Authentication.External;

    /// <summary>
    /// Implementation of the <see cref="IAuthenticationAdapter"/>.
    /// </summary>
    public class AuthenticationAdapter : IAuthenticationAdapter
    {
        /// <summary>
        /// Gets the metadata describing the authentication adapter.
        /// </summary>
        public IAuthenticationAdapterMetadata Metadata => new AuthenticationAdapterMetadata();

        /// <summary>
        /// Begins the authentication process for the authentication adapter.
        /// </summary>
        /// <param name="identityClaim">The claim identifying the user.</param>
        /// <param name="request">The actual AD FS request.</param>
        /// <param name="context">The AD FS authentication context.</param>
        /// <returns>The <see cref="AdapterPresentation"/> the be shown in the AD FS dialog.</returns>
        public IAdapterPresentation BeginAuthentication(Claim identityClaim, HttpListenerRequest request, IAuthenticationContext context)
        {
            IAdapterPresentation result;
            var upn = identityClaim.Value;
            context.Data.Add("upn", upn);
            if (TOTPAuthenticator.HasSecretKey(upn, out var attempts, out var locked))
            {
                // The user has already enrolled in TOTP MFA.
                result = new AdapterPresentation(attempts, locked);
            }
            else
            {
                // The user has not yet enrolled in TOTP MFA.
                var secretKey = TOTPAuthenticator.CreateSecretKey(upn);
                result = new AdapterPresentation(upn, secretKey);
            }

            return result;
        }

        /// <summary>
        /// Determines whether this authentication adapter is available for the user.
        /// </summary>
        /// <param name="identityClaim">The claim identifying the user.</param>
        /// <param name="context">The AD FS authentication context.</param>
        /// <returns>'false', if the user has been locked out, 'true' otherwise.</returns>
        public bool IsAvailableForUser(Claim identityClaim, IAuthenticationContext context)
        {
            var hasKey = TOTPAuthenticator.HasSecretKey(identityClaim.Value, out var _, out var locked);
            var result = hasKey ? !locked : true;
            return result;
        }

        /// <summary>
        /// Initializes the authentication adapter.
        /// </summary>
        /// <param name="configData">A stream for reading the configuration data.</param>
        /// <remarks>
        /// Called when AD FS starts and loads the authentication adapters. 
        /// The configuration is read from the AD FS configuration database.
        /// </remarks>
        public void OnAuthenticationPipelineLoad(IAuthenticationMethodConfigData configData)
        {
            if (configData == null || configData.Data == null)
            {
                throw new ExternalAuthenticationException("No configuration data.", null);
            }

            try
            {
                var serializer = new XmlSerializer(typeof(TOTPConfiguration));
                var configurationData = (TOTPConfiguration)serializer.Deserialize(configData.Data);

                TOTPAuthenticator.SetStore(configurationData.StoreType, configurationData.ConnectionString);

                if (configurationData.MaxAttempts > 0)
                {
                    TOTPAuthenticator.EnableLockout(configurationData.MaxAttempts, new TimeSpan(0, 0, configurationData.LockoutDurationInSeconds));
                }
                else
                {
                    TOTPAuthenticator.DisableLockout();
                }

                TOTPAuthenticator.FutureIntervals = configurationData.FutureIntervals;
                TOTPAuthenticator.PastIntervals = configurationData.PastIntervals;
                TOTPAuthenticator.SecretKeyLength = configurationData.SecretKeyLength;
                TOTPAuthenticator.ValidityPeriodSeconds = configurationData.ValidityPeriodSeconds;
                TOTPAuthenticator.CodeAlgorithm = (TOTPAlgorithm)Enum.Parse(typeof(TOTPAlgorithm), configurationData.Algorithm);
                TOTPAuthenticator.CodeLength = configurationData.CodeLength;

                AdapterPresentation.CompanyName = configurationData.CompanyName;
                AdapterPresentation.SupportEmail = configurationData.SupportEmail;
            }
            catch (Exception error)
            {
                throw new Exception("Invalid configuration data.", error);
            }
        }

        /// <summary>
        /// Allows the authentication adapter to dispose resources when the adapter is unloaded.
        /// </summary>
        /// <remarks>Called when AD FS stops.</remarks>
        public void OnAuthenticationPipelineUnload()
        {
        }

        /// <summary>
        /// This is called whenever something goes wrong in the authentication process. 
        /// </summary>
        /// <param name="request">The actual AD FS request.</param>
        /// <param name="ex">The exception raised</param>
        /// <returns>An <see cref="AdapterPresentation"/> web form to be shown in the AD FS dialog.</returns>
        /// <remarks>
        /// This is called whenever something goes wrong in the authentication process.
        /// To be more precise; if anything goes wrong in the BeginAuthentication or TryEndAuthentication
        /// methods of this authentication adapter, and either of these methods throw an ExternalAuthenticationException,
        /// the OnError method is called.
        /// </remarks>
        public IAdapterPresentation OnError(HttpListenerRequest request, ExternalAuthenticationException ex)
        {
            return new AdapterPresentation(ex);
        }

        /// <summary>
        /// Tries to complete the MFA request by validating the user input.
        /// </summary>
        /// <param name="context">The AD FS authentication context.</param>
        /// <param name="proofData">The proof provided by the client.</param>
        /// <param name="request">The actual AD FS request.</param>
        /// <param name="claims">If the validation was successful, this contains the authentication method claim.</param>
        /// <returns>'null' if successful, an <see cref="AdapterPresentation"/> to be shown in the AD FS dialog otherwise.</returns>
        public IAdapterPresentation TryEndAuthentication(IAuthenticationContext context, IProofData proofData, HttpListenerRequest request, out Claim[] claims)
        {
            object code = null;
            object upn = null;
            proofData?.Properties?.TryGetValue("ChallengeQuestionAnswer", out code);
            context?.Data?.TryGetValue("upn", out upn);
            if (code == null || upn == null)
            {
                throw new ExternalAuthenticationException("No answer found or corrupted context.", context);
            }

            IAdapterPresentation result;
            if (TOTPAuthenticator.CodeIsValid((string)upn, (string)code, out var attempts, out var locked))
            {
                var claim = new Claim("http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod", "http://schemas.microsoft.com/ws/2012/12/authmethod/otp");
                claims = new Claim[] { claim };
                result = null;
            }
            else
            {
                claims = null;
                result = new AdapterPresentation(attempts, locked);
            }

            return result;
        }
    }
}
