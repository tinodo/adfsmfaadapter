//-----------------------------------------------------------------------
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
    using System;
    using System.Reflection;

    /// <summary>
    /// The Factory class for the TOTP Authentication Store.
    /// </summary>
    public class TOTPAuthenticatorStoreFactory
    {
        /// <summary>
        /// Creates a new instance of a class implementing the <see cref="TOTPAuthenticatorStore"/> interface.
        /// </summary>
        /// <param name="storeType">The <see cref="TOTPAuthenticatorStoreType"/> to use.</param>
        /// <param name="connectionString">The Connection String.</param>
        /// <returns>A new instance of a class implementing the <see cref="TOTPAuthenticatorStore"/> interface.</returns>
        public static TOTPAuthenticatorStore GetStore(string storeType, string connectionString = null)
        {
            var parts = storeType.Split(',');
            var typeName = parts[0].Trim();
            var assemblyName = parts[1].Trim();
            var constructorParameters = new object[] { connectionString };
            TOTPAuthenticatorStore result = null;

            if (string.Equals(assemblyName, typeof(TOTPAuthenticatorStore).Assembly.GetName().Name, StringComparison.InvariantCultureIgnoreCase))
            {
                // The Store implementation is in the current assembly.
                var database = Type.GetType(typeName, true, true);
                if (database.IsSubclassOf(typeof(TOTPAuthenticatorStore)))
                {
                    var constructor = database.GetConstructor(new Type[] { typeof(string) });
                    result = (TOTPAuthenticatorStore)constructor.Invoke(constructorParameters);
                }
            }
            else
            {
                // The Store implementatin is in some other assembly.
                var database = Activator.CreateInstance(assemblyName, typeName, true, 0, null, constructorParameters, null, new object[] { }).Unwrap();
                if (database != null && database.GetType().IsSubclassOf(typeof(TOTPAuthenticatorStore)))
                {
                    result = (TOTPAuthenticatorStore)database;
                }
            }

            if (result == null)
            {
                throw new ArgumentException("Wrong type.", "storeType");
            }

            return result;
        }
    }
}
