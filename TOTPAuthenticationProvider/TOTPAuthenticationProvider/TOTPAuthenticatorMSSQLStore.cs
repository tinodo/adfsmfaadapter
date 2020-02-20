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
    using System.Data.SqlClient;

    public class TOTPAuthenticatorMSSQLStore : TOTPAuthenticatorStore
    {
        public TOTPAuthenticatorMSSQLStore(string sqlConnectionString)
            : base (sqlConnectionString)
        {
        }

        public override bool CodeWasUsedPreviously(string upn, long interval)
        {
            bool result;
            using (var sqlConnection = new SqlConnection(this.connectionString))
            {
                var sqlCommandString = "SELECT COUNT(*) FROM UsedCodes WHERE upn = @upn AND interval = @interval";
                var sqlCommand = new SqlCommand(sqlCommandString, sqlConnection);
                sqlConnection.Open();
                sqlCommand.Parameters.AddWithValue("@upn", upn);
                sqlCommand.Parameters.AddWithValue("@interval", interval);
                var count = (int)sqlCommand.ExecuteScalar();
                result = count > 0;
            }

            return result;
        }

        public override void CleanupUsedCodes(string upn, long fromInterval)
        {
            using (var sqlConnection = new SqlConnection(this.connectionString))
            {
                var sqlCommandString = "DELETE FROM UsedCodes WHERE upn = @upn AND interval < @interval";
                var sqlCommand = new SqlCommand(sqlCommandString, sqlConnection);
                sqlConnection.Open();
                sqlCommand.Parameters.AddWithValue("@upn", upn);
                sqlCommand.Parameters.AddWithValue("@interval", fromInterval);
                sqlCommand.ExecuteNonQuery();
            }
        }

        public override void CreateSecretKey(string upn, string secretKey)
        {
            using (var sqlConnection = new SqlConnection(this.connectionString))
            {
                var sqlCommandString = "INSERT INTO Secrets (upn, secret, attempts) VALUES (@upn, @secret, 0)";
                var sqlCommand = new SqlCommand(sqlCommandString, sqlConnection);
                sqlConnection.Open();
                sqlCommand.Parameters.AddWithValue("@upn", upn);
                sqlCommand.Parameters.AddWithValue("@secret", secretKey);
                if (sqlCommand.ExecuteNonQuery() == 0)
                {
                    throw new Exception("Something terrible has happened.");
                }
            }
        }

        public override int IncreaseAttempts(string upn)
        {
            int attempts;
            using (var sqlConnection = new SqlConnection(this.connectionString))
            {
                var sqlCommandString = "UPDATE Secrets SET attempts = attempts + 1 OUTPUT INSERTED.attempts WHERE upn = @upn";
                var sqlCommand = new SqlCommand(sqlCommandString, sqlConnection);
                sqlConnection.Open();
                sqlCommand.Parameters.AddWithValue("@upn", upn);
                attempts = (int)sqlCommand.ExecuteScalar();
            }

            return attempts;
        }

        //public override void UnlockAccount(string upn)
        //{
        //    using (var sqlConnection = new SqlConnection(this.connectionString))
        //    {
        //        var sqlCommandString = "UPDATE Secrets SET attempts = 0, lockedUntil = null WHERE upn = @upn";
        //        var sqlCommand = new SqlCommand(sqlCommandString, sqlConnection);
        //        sqlConnection.Open();
        //        sqlCommand.Parameters.AddWithValue("@upn", upn);
        //        sqlCommand.ExecuteNonQuery();
        //    }
        //}

        public override void LockAccount(string upn, DateTime lockedUntil)
        {
            using (var sqlConnection = new SqlConnection(this.connectionString))
            {
                var sqlCommandString = "UPDATE Secrets SET attempts = 0, lockedUntil = @lockedUntil WHERE upn = @upn";
                var sqlCommand = new SqlCommand(sqlCommandString, sqlConnection);
                sqlConnection.Open();
                sqlCommand.Parameters.AddWithValue("@upn", upn);
                sqlCommand.Parameters.AddWithValue("@lockedUntil", lockedUntil);
                sqlCommand.ExecuteNonQuery();
            }
        }

        public override void ResetAttempts(string upn)
        {
            using (var sqlConnection = new SqlConnection(this.connectionString))
            {
                var sqlCommandString = "UPDATE Secrets SET attempts = 0, lockedUntil = NULL WHERE upn = @upn";
                var sqlCommand = new SqlCommand(sqlCommandString, sqlConnection);
                sqlConnection.Open();
                sqlCommand.Parameters.AddWithValue("@upn", upn);
                sqlCommand.ExecuteNonQuery();
            }
        }

        public override void AddUsedCode(string upn, long interval)
        {
            using (var sqlConnection = new SqlConnection(this.connectionString))
            {
                var sqlCommandString = "INSERT INTO UsedCodes (upn, interval) VALUES (@upn, @interval)";
                var sqlCommand = new SqlCommand(sqlCommandString, sqlConnection);
                sqlConnection.Open();
                sqlCommand.Parameters.AddWithValue("@upn", upn);
                sqlCommand.Parameters.AddWithValue("@interval", interval);
                sqlCommand.ExecuteNonQuery();
            }
        }

        public override bool TryGetSecretKey(string upn, out string secretKey, out int attempts, out bool locked)
        {
            bool hasSecretKey;
            using (var sqlConnection = new SqlConnection(this.connectionString))
            {
                var sqlCommandString = "SELECT secret, attempts, lockedUntil FROM Secrets WHERE upn = @upn";
                var sqlCommand = new SqlCommand(sqlCommandString, sqlConnection);
                sqlConnection.Open();
                sqlCommand.Parameters.AddWithValue("@upn", upn);
                var clearLock = false;
                using (var reader = sqlCommand.ExecuteReader(System.Data.CommandBehavior.CloseConnection))
                {
                    if (reader.HasRows)
                    {
                        reader.Read();
                        secretKey = reader.GetString(0);
                        attempts = reader.GetInt32(1);
                        if (reader.IsDBNull(2))
                        {
                            locked = false;
                        }
                        else
                        {
                            var lockedUntil = reader.GetDateTime(2);
                            if (lockedUntil > DateTime.UtcNow)
                            {
                                locked = false;
                                clearLock = true;
                            }
                            else
                            {
                                locked = true;
                            }
                        }

                        hasSecretKey = true;
                    }
                    else
                    {
                        secretKey = null;
                        attempts = 0;
                        locked = false;
                        hasSecretKey = false;
                    }
                }
                // This might not be the best place to do this.
                if (clearLock)
                {
                    sqlCommandString = "UPDATE Secrets SET attempts = 0, lockedUntil = NULL WHERE upn = @upn";
                    sqlCommand = new SqlCommand(sqlCommandString, sqlConnection);
                    sqlCommand.Parameters.AddWithValue("@upn", upn);
                    sqlCommand.ExecuteNonQuery();
                }
            }

            return hasSecretKey;
        }
    }
}
