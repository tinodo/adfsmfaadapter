//-----------------------------------------------------------------------
// 
// THIS CODE AND ANY ASSOCIATED INFORMATION ARE PROVIDED “AS IS” WITHOUT
// WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT
// LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS
// FOR A PARTICULAR PURPOSE. THE ENTIRE RISK OF USE, INABILITY TO USE, OR 
// RESULTS FROM THE USE OF THIS CODE REMAINS WITH THE USER.
//
//-----------------------------------------------------------------------

0. Introduction


1. Create a database

Create a database using the provided script (CreateDatabase.sql), or, if you want to use a SQL Azure Database,
create the database from the Azure portal and create the tables using the CreateDatabase.sql script.
Create a user accounts in SQL that has read/write permissions to all the data in the two tables or assign the AD FS Service Account the proper permissions.

2. Modify the configuration

Open TOTPAuthenticator.xml and modify it to meet your environment.
Change the ConnectionString value to match the SQL Connection String to your newly created database.
The other fields should be selfexplenatory.
To be safe, do not change these fields: Algorithm, CodeLength, ValidityPeriodSeconds, StoreType

3. Get the Microsoft.IdentityServer.Web.dll

Copy Microsoft.IdentityServer.Web.dll from the AD FS directory (C:\Windows\ADFS) to your developer machine.
Create a new reference to the DLL in the TOTPAuthenticationProvider project and set the "Copy Local" property to "False".

4. Build

5. Get the PublicKeyToken

To get the PublicKeyToken for the Authentication Provider, run this command from a Visual Studio Command Prompt:

SN -T "C:\PATHTOFILE\TOTPAuthenticationProvider.dll"

Copy the "Public key token" from the output;

Microsoft (R) .NET Framework Strong Name Utility  Version 4.0.30319.0
Copyright (c) Microsoft Corporation.  All rights reserved.

Public key token is 1ab23c0000dd1234

6. Copy the Authentication Provider DLL to the AD FS server, for example in "C:\Program Files (x86)\ADFS TOTP Authentication Provider"

7. Register the Authentication Provider in the GAC

From a PowerShell Window with elevated privileges, issue these commands on each AD FS Server in the Farm:

Set-location "C:\Program Files (x86)\ADFS TOTP Authentication Provider"
[System.Reflection.Assembly]::Load("System.EnterpriseServices, Version=4.0.0.0, Culture=neutral, PublicKeyToken=1ab23c0000dd1234")
$publish = New-Object System.EnterpriseServices.Internal.Publish
$publish.GacInstall("C:\Program Files (x86)\ADFS TOTP Authentication Provider\TOTPAuthenticationProvider.dll")
$publish.GacInstall("C:\Program Files (x86)\ADFS TOTP Authentication Provider\nl\TOTPAuthenticationProvider.resources.dll")
$publish.GacInstall("C:\Program Files (x86)\ADFS TOTP Authentication Provider\no\TOTPAuthenticationProvider.resources.dll")

Replace the PublicKeyToken with your Public Key Token and replace the location and name of the file if you need to.

8. Register the Authentication Provider with AD FS

From a PowerShell Window with elevated privileges, issue these commands:

$typeName = "TOTPAuthenticationProvider.AuthenticationAdapter, TOTPAuthenticationProvider, Version=1.0.0.0, Culture=neutral, PublicKeyToken=7ed29f0000dd7766"
Register-AdfsAuthenticationProvider -TypeName $typeName -Name "TOTP" -Verbose

9. Now you can use the provider in AD FS!