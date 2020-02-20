﻿//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//     Runtime Version:4.0.30319.42000
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace TOTPAuthenticationProvider {
    using System;
    
    
    /// <summary>
    ///   A strongly-typed resource class, for looking up localized strings, etc.
    /// </summary>
    // This class was auto-generated by the StronglyTypedResourceBuilder
    // class via a tool like ResGen or Visual Studio.
    // To add or remove a member, edit your .ResX file then rerun ResGen
    // with the /str option, or rebuild your VS project.
    [global::System.CodeDom.Compiler.GeneratedCodeAttribute("System.Resources.Tools.StronglyTypedResourceBuilder", "4.0.0.0")]
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute()]
    [global::System.Runtime.CompilerServices.CompilerGeneratedAttribute()]
    internal class Resources {
        
        private static global::System.Resources.ResourceManager resourceMan;
        
        private static global::System.Globalization.CultureInfo resourceCulture;
        
        [global::System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1811:AvoidUncalledPrivateCode")]
        internal Resources() {
        }
        
        /// <summary>
        ///   Returns the cached ResourceManager instance used by this class.
        /// </summary>
        [global::System.ComponentModel.EditorBrowsableAttribute(global::System.ComponentModel.EditorBrowsableState.Advanced)]
        internal static global::System.Resources.ResourceManager ResourceManager {
            get {
                if (object.ReferenceEquals(resourceMan, null)) {
                    global::System.Resources.ResourceManager temp = new global::System.Resources.ResourceManager("TOTPAuthenticationProvider.Resources", typeof(Resources).Assembly);
                    resourceMan = temp;
                }
                return resourceMan;
            }
        }
        
        /// <summary>
        ///   Overrides the current thread's CurrentUICulture property for all
        ///   resource lookups using this strongly typed resource class.
        /// </summary>
        [global::System.ComponentModel.EditorBrowsableAttribute(global::System.ComponentModel.EditorBrowsableState.Advanced)]
        internal static global::System.Globalization.CultureInfo Culture {
            get {
                return resourceCulture;
            }
            set {
                resourceCulture = value;
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Time-Based One-Time Password Authentication.
        /// </summary>
        internal static string AdminName {
            get {
                return ResourceManager.GetString("AdminName", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to {0} Attempt(s) left..
        /// </summary>
        internal static string AttemptsLeftText {
            get {
                return ResourceManager.GetString("AttemptsLeftText", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to &lt;div id=&quot;loginArea&quot;&gt;
        ///	&lt;form method=&quot;post&quot; id=&quot;loginForm&quot; name=&quot;loginForm&quot;&gt;
        ///		&lt;input id=&quot;authMethod&quot; type=&quot;hidden&quot; name=&quot;AuthMethod&quot; value=&quot;%AuthMethod%&quot;/&gt;
        ///		&lt;input id=&quot;context&quot; type=&quot;hidden&quot; name=&quot;Context&quot; value=&quot;%Context%&quot;/&gt;
        ///		&lt;div id=&quot;titleDiv&quot; class=&quot;groupMargin&quot;&gt;
        ///			&lt;h1 id=&quot;sectionHeader&quot;&gt;*MFA*&lt;/h1&gt; 
        ///		&lt;/div&gt; 
        ///		&lt;div id=&quot;qrcode&quot;&gt;
        ///			&lt;p&gt;*QRCODETEXT*&lt;/p&gt;
        ///			&lt;br /&gt;
        ///			*QRCODEIMAGE*
        ///		&lt;/div&gt;
        ///		&lt;label for=&quot;challengeQuestionInput&quot; class=&quot;block&quot;&gt;*ENTERCODE*&lt;/label&gt;
        ///		&lt;input id=&quot;challengeQuestionIn [rest of string was truncated]&quot;;.
        /// </summary>
        internal static string AuthenticationForm {
            get {
                return ResourceManager.GetString("AuthenticationForm", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Time-Based One-Time Password.
        /// </summary>
        internal static string Description {
            get {
                return ResourceManager.GetString("Description", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Enter the code generated by your authenticator app..
        /// </summary>
        internal static string EnterCodeText {
            get {
                return ResourceManager.GetString("EnterCodeText", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to 
        ///&lt;div id=&quot;loginArea&quot;&gt;
        ///	&lt;div id=&quot;errorArea&quot; class=&quot;error&quot;&gt;
        ///		&lt;p id=&quot;error&quot;&gt;*ERROR*&lt;/p&gt;
        ///	&lt;/div&gt;
        ///
        ///	&lt;div id=&quot;intro&quot; class=&quot;groupMargin&quot;&gt;
        ///		&lt;p id=&quot;supportEmail&quot;&gt;*SUPPORT*&lt;/p&gt;
        ///	&lt;/div&gt;
        ///&lt;/div&gt;.
        /// </summary>
        internal static string ErrorForm {
            get {
                return ResourceManager.GetString("ErrorForm", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Time-Based One-Time Password.
        /// </summary>
        internal static string FriendlyName {
            get {
                return ResourceManager.GetString("FriendlyName", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Please enter your {0}-digit code..
        /// </summary>
        internal static string IncorrectCodeFormatText {
            get {
                return ResourceManager.GetString("IncorrectCodeFormatText", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to An error occurred. Please contact your organization..
        /// </summary>
        internal static string InternalErrorText {
            get {
                return ResourceManager.GetString("InternalErrorText", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Try another method..
        /// </summary>
        internal static string LockedErrorText {
            get {
                return ResourceManager.GetString("LockedErrorText", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Multi-Factor Authentication.
        /// </summary>
        internal static string MFAText {
            get {
                return ResourceManager.GetString("MFAText", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Time-Based One-Time Password Authentication.
        /// </summary>
        internal static string PageTitle {
            get {
                return ResourceManager.GetString("PageTitle", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Please configure your Authenticator App (Microsoft Authenticator, Google Authenticator, et al.) using the QR Code below..
        /// </summary>
        internal static string QRCodeHelpText {
            get {
                return ResourceManager.GetString("QRCodeHelpText", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to {0}-digit code.
        /// </summary>
        internal static string ShortCodeText {
            get {
                return ResourceManager.GetString("ShortCodeText", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Submit.
        /// </summary>
        internal static string SubmitText {
            get {
                return ResourceManager.GetString("SubmitText", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Need support? Contact &lt;a href=\&quot;mailto:{0}\&quot;&gt;{0}&lt;/a&gt;..
        /// </summary>
        internal static string SupportText {
            get {
                return ResourceManager.GetString("SupportText", resourceCulture);
            }
        }
    }
}