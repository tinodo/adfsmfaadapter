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

    /// <summary>
    /// The abstract class describing all Store operations.
    /// </summary>
    public abstract class TOTPAuthenticatorStore
    {
        protected string connectionString;

        public TOTPAuthenticatorStore(string connectionString)
        {
            this.connectionString = connectionString;
        }

        /// <summary>
        /// Determines whether a user, identified by a UPN, has a Secret Key set. If so, it also returns the secret key, the number of attempts already made and whether the user is locked out or not.
        /// </summary>
        /// <param name="upn">The UPN identifying the user.</param>
        /// <param name="secretKey">The secret key for the user (or null if the user has no secret key).</param>
        /// <param name="attempts">The number of attempts the user already made to validate a code (or 0 if the user has no secret key).</param>
        /// <param name="locked">Indication whether the user is locked out or not (or false when the user has no secret key).</param>
        /// <returns>A boolean indication whether the user has a secret key or not.</returns>
        public abstract bool TryGetSecretKey(string upn, out string secretKey, out int attempts, out bool locked);

        /// <summary>
        /// Inserts a secret key for a user in the store. If the user already has secret key, this method should throw an exception.
        /// </summary>
        /// <param name="upn">The UPN identifying the user.</param>
        /// <param name="secretKey">The secret key for the user.</param>
        /// <remarks>The UPN or secret keys are not validated. It's up to the caller to validate these before calling the method.</remarks>
        public abstract void CreateSecretKey(string upn, string secretKey);

        /// <summary>
        /// Determines whether the code for the given user and interval is already used.
        /// </summary>
        /// <param name="upn">The UPN identifying the user.</param>
        /// <param name="interval">The interval to check the code usage for.</param>
        /// <returns>True, when the code for the given interval was already used or false when it has not.</returns>
        public abstract bool CodeWasUsedPreviously(string upn, long interval);

        /// <summary>
        /// Cleans up old used codes from the store.
        /// </summary>
        /// <param name="upn">The UPN identifying the user.</param>
        /// <param name="fromInterval">The interface before which to cleanup used codes.</param>
        public abstract void CleanupUsedCodes(string upn, long fromInterval);

        /// <summary>
        /// Inserts a record in the store to indicated that a code for a given user and interval is already used.
        /// </summary>
        /// <param name="upn">The UPN identifying the user.</param>
        /// <param name="interval">The interval at which the code was used.</param>
        public abstract void AddUsedCode(string upn, long interval);

        /// <summary>
        /// Increases the number of validation attempts for a given user in the store.
        /// </summary>
        /// <param name="upn">The UPN identifying the user.</param>
        /// <returns>The new, increased, number of attempts.</returns>
        public abstract int IncreaseAttempts(string upn);

        /// <summary>
        /// Unlocks a user, and reset the attempts.
        /// </summary>
        /// <param name="upn">The UPN identifying the user.</param>
        //public abstract void UnlockAccount(string upn);

        /// <summary>
        /// Locks a user, given by it's UPN, for a given amount of time.
        /// </summary>
        /// <param name="upn">The UPN identifying the user.</param>
        /// <param name="lockedUntil">The date and time until when the user is locked out.</param>
        public abstract void LockAccount(string upn, DateTime lockedUntil);

        /// <summary>
        /// Resets the attempts counter in the store for a user identified but it's UPN.
        /// </summary>
        /// <param name="upn">The UPN identifying the user.</param>
        public abstract void ResetAttempts(string upn);
    }
}
