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

namespace TOTPAuthenticationProviderTests
{
    using System;
    using System.Collections.Generic;
    using TOTPAuthenticationProvider;

    public class TOTPAuthenticatorDummyStore : TOTPAuthenticatorStore
    {
        private class Secret
        {
            public string upn;
            public string secret;
            public int attempts;
            public DateTime? lockedUntil;
        }

        private class UsedCode
        {
            public string upn;
            public long interval;
        }

        private List<Secret> secrets;
        private List<UsedCode> usedCodes;
        public TOTPAuthenticatorDummyStore(string connectionString)
: base(connectionString)
        {
            this.secrets = new List<Secret>();
            this.usedCodes = new List<UsedCode>();
        }

        public override void AddUsedCode(string upn, long interval)
        {
            if (this.secrets.Exists(secret => secret.upn == upn))
            {
                this.usedCodes.Add(new UsedCode() { upn = upn, interval = interval });
            }
            else
            {
                throw new TOTPAuthenticatorStoreException("User does not exist.");
            }
        }

        public override void CleanupUsedCodes(string upn, long fromInterval)
        {
            if (this.secrets.Exists(secret => secret.upn == upn))
            {
                this.usedCodes.RemoveAll(usedCode => usedCode.interval < fromInterval);
            }
            else
            {
                throw new TOTPAuthenticatorStoreException("User does not exist.");
            }
        }

        public override bool CodeWasUsedPreviously(string upn, long interval)
        {
            if (this.secrets.Exists(secret => secret.upn == upn))
            {
                return this.usedCodes.Exists(usedCode => usedCode.upn == upn && usedCode.interval == interval);
            }
            else
            {
                throw new TOTPAuthenticatorStoreException("User does not exist.");
            }
        }

        public override void CreateSecretKey(string upn, string secretKey)
        {
            if (this.secrets.Exists(secret => secret.upn == upn))
            {
                throw new TOTPAuthenticatorStoreException("User already has a secret key.");
            }
            else
            {
                this.secrets.Add(new Secret() { upn = upn, secret = secretKey, attempts = 0, lockedUntil = null });
            }
        }

        public override bool TryGetSecretKey(string upn, out string secretKey, out int attempts, out bool locked)
        {
            bool hasSecretKey;
            var secret = this.secrets.Find(s => s.upn == upn);
            if (secret == null)
            {
                hasSecretKey = false;
                secretKey = null;
                attempts = 0;
                locked = false;
            }
            else
            {
                hasSecretKey = true;
                secretKey = secret.secret;
                attempts = secret.attempts;
                if (secret.lockedUntil.HasValue)
                {
                    locked = secret.lockedUntil.Value > DateTime.UtcNow;
                    if (!locked)
                    {
                        secret.attempts = 0;
                        secret.lockedUntil = null;
                    }
                }
                else
                {
                    locked = false;
                }
            }

            return hasSecretKey;
        }

        public override int IncreaseAttempts(string upn)
        {
            var secret = this.secrets.Find(s => s.upn == upn);
            if (secret == null)
            {
                throw new TOTPAuthenticatorStoreException("User does not exist.");
            }

            secret.attempts++;
            return secret.attempts;
        }

        //public override void UnlockAccount(string upn)
        //{
        //    var secret = this.secrets.Find(s => s.upn == upn);
        //    if (secret == null)
        //    {
        //        throw new TOTPAuthenticatorStoreException("User does not exist.");
        //    }

        //    secret.attempts = 0;
        //    secret.lockedUntil = null;
        //}
        public override void LockAccount(string upn, DateTime lockedUntil)
        {
            var secret = this.secrets.Find(s => s.upn == upn);
            if (secret == null)
            {
                throw new TOTPAuthenticatorStoreException("User does not exist.");
            }

            secret.lockedUntil = lockedUntil;
        }

        public override void ResetAttempts(string upn)
        {
            var secret = this.secrets.Find(s => s.upn == upn);
            if (secret == null)
            {
                throw new TOTPAuthenticatorStoreException("User does not exist.");
            }

            secret.attempts = 0;
            secret.lockedUntil = null;
        }
    }
}
