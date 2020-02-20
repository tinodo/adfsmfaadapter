//-----------------------------------------------------------------------
// <copyright file="AdapterPresentation.cs" company="Microsoft">
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
    using System.Globalization;

    using Microsoft.IdentityServer.Web.Authentication.External;

    /// <summary>
    /// Implementation of the <see cref="IAdapterPresentation"/> and <see cref="IAdapterPresentationForm"/>.  
    /// </summary>
    public class AdapterPresentation : IAdapterPresentation, IAdapterPresentationForm
    {
        /// <summary>
        /// The users UPN.
        /// </summary>
        private string upn = null;

        /// <summary>
        /// The users secret key.
        /// </summary>
        private string secretKey = null;

        /// <summary>
        /// The number of attempts the user has gone through entering the proper code.
        /// </summary>
        private int attempts = 0;

        /// <summary>
        /// Whether or not the user has been locked out of this authentication adapter.
        /// </summary>
        private bool locked = false;

        /// <summary>
        /// Indicates whether the authentication adapter ran into an exception.
        /// </summary>
        private ExternalAuthenticationException error = null;

        /// <summary>
        /// Initializes a new instance of the <see cref="AdapterPresentation"/> class, when the user has not been enrolled in TOTP MFA or when the user hits the page after primary authentication.
        /// </summary>
        /// <param name="upn">The UPN of the user.</param>
        /// <param name="secretKey">The secret key for the user. When the secret key is null, the user is already enrolled in TOTP MFA.</param>
        /// <remarks>This constructor is called when the user needs to enroll in TOTP MFA or when the user first hits the TOTP MFA page.</remarks>
        public AdapterPresentation(string upn, string secretKey)
        {
            this.attempts = 0;
            this.locked = false;
            this.upn = upn;
            this.secretKey = secretKey;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AdapterPresentation"/> class, when trying to verify the proof data. 
        /// </summary>
        /// <param name="attempts">The number of attempts the user has gone through entering the proper code.</param>
        /// <param name="locked">Whether or not the user has been locked out of this Authentication Provider.</param>
        /// <remarks>This constructor is called when the users has entered an invalid code.</remarks>
        public AdapterPresentation(int attempts, bool locked)
        {
            this.attempts = attempts;
            this.locked = locked;
            this.upn = null;
            this.secretKey = null;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AdapterPresentation"/> class, whenever an error has occurred.
        /// </summary>
        /// <param name="ex">The exception that needs to be handled.</param>
        /// <remarks>Called by the OnError method of the <see cref="AuthenticationAdapter"/>.</remarks>
        public AdapterPresentation(ExternalAuthenticationException ex)
        {
            this.error = ex;
        }

        /// <summary>
        /// Gets or sets the name of your organization as used in the QR code.
        /// </summary>
        public static string CompanyName { get; set; }

        /// <summary>
        /// Gets or sets the support email address of your organization.
        /// </summary>
        public static string SupportEmail { get; set; }

        /// <summary>
        /// Gets the title of the page to be displayed in the browser for this Authentication Provider, given a language culture identifier.
        /// </summary>
        /// <param name="lcid">The language culture identifier of the language.</param>
        /// <returns>The title of the page to be displayed in the users browser.</returns>
        /// <remarks>
        /// Check <see href="https://msdn.microsoft.com/en-us/library/ee825488(v=cs.20).aspx">MSDN</see> for all language culture identifiers.
        /// </remarks>
        public string GetPageTitle(int lcid)
        {
            Resources.Culture = new CultureInfo(lcid);
            return Resources.PageTitle;
        }

        /// <summary>
        /// Gets the HTML to be displayed within the AD FS MFA page for a user, given a language culture identifier.
        /// </summary>
        /// <param name="lcid">The language culture identifier of the language.</param>
        /// <returns>The HTML to be displayed in the AD FS MFA page.</returns>
        /// <remarks>
        /// Check <see href="https://msdn.microsoft.com/en-us/library/ee825488(v=cs.20).aspx">MSDN</see> for all language culture identifiers.
        /// </remarks>
        public string GetFormHtml(int lcid)
        {
            Resources.Culture = new CultureInfo(lcid);
            string result;
            if (this.error == null)
            {
                result = Resources.AuthenticationForm;
                var hideQRCode = string.IsNullOrEmpty(this.secretKey);
                result = result.Replace("*SUBMIT*", Resources.SubmitText);
                result = result.Replace("*MFA*", Resources.MFAText);
                result = result.Replace("*ENTERCODE*", Resources.EnterCodeText);
                result = result.Replace("*CODE*", string.Format(Resources.ShortCodeText, TOTPAuthenticator.CodeLength));
                result = result.Replace("*INCORRECTCODEFORMAT*", string.Format(Resources.IncorrectCodeFormatText, TOTPAuthenticator.CodeLength));

                result = result.Replace("*QRCODETEXT*", hideQRCode ? string.Empty : Resources.QRCodeHelpText);
                result = result.Replace("*QRCODEIMAGE*", hideQRCode ? string.Empty : TOTPAuthenticator.GetQrCodeImage(AdapterPresentation.CompanyName, this.upn, this.secretKey, Resources.QRCodeHelpText));
                result = result.Replace("*HIDEQRCODE*", hideQRCode ? "1" : "0");
                result = result.Replace("*HIDELOGIN*", hideQRCode ? this.locked ? "1" : "0" : "0");
                result = result.Replace("*HIDEERROR*", hideQRCode ? "0" : "1");
                result = result.Replace("*CODEDIGITS*", TOTPAuthenticator.CodeLength.ToString());

                result = result.Replace("*ERROR*", hideQRCode ? this.locked ? Resources.LockedErrorText : string.Format(Resources.AttemptsLeftText, TOTPAuthenticator.MaxAttempts - this.attempts) : string.Empty);
            }
            else
            {
                result = Resources.ErrorForm;
                result = result.Replace("*ERROR*", Resources.InternalErrorText);
            }

            result = result.Replace("*SUPPORT*", string.Format(Resources.SupportText, AdapterPresentation.SupportEmail));

            return result;
        }

        /// <summary>
        /// Gets the HTML code that needs to be inserted into the AD FS MFA page before the body of the page, given a language culture identifier.
        /// </summary>
        /// <param name="lcid">The language code identifier of the language.</param>
        /// <returns>The HTML code that needs to be inserted before the BODY part of the AD FS MFA page.</returns>
        /// <remarks>
        /// Check <see href="https://msdn.microsoft.com/en-us/library/ee825488(v=cs.20).aspx">MSDN</see> for all language culture identifiers.
        /// </remarks>
        public string GetFormPreRenderHtml(int lcid)
        {
            Resources.Culture = new CultureInfo(lcid);
            return string.Empty;
        }
    }
}