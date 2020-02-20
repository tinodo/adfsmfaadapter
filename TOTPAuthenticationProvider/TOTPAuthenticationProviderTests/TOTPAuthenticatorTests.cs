namespace TOTPAuthenticationProvider.Tests
{
    using System;
    using System.Linq;
    using System.Fakes;
    using System.Data.SqlClient.Fakes;

    using Microsoft.QualityTools.Testing.Fakes;
    using Microsoft.VisualStudio.TestTools.UnitTesting;

    using TOTPAuthenticationProvider;
    using TOTPAuthenticationProvider.Fakes;
    using System.Text;

    public class Foo
    {
        public Foo(string foo)
        { }
    }
    [TestClass()]
    public class TOTPAuthenticatorTests
    {
        /*
         * 
            Secret Key: K4YPKAHBWAZYQ4NL, When: 1/1/1970 12:00:00 AM, Code: 952652
            Secret Key: 2NMBKBZO7LWWDF23, When: 2/3/1974 2:03:06 AM, Code: 405209
            Secret Key: RZ4ORJIPJC7IWH2X, When: 3/5/1978 4:06:12 AM, Code: 875252
            Secret Key: I7U3FO4KH5ULLRQR, When: 4/7/1982 6:09:18 AM, Code: 818947
            Secret Key: NXCJRUZKXX7BJU7B, When: 5/9/1986 8:12:24 AM, Code: 367108
            Secret Key: HXRYXNNCMMDL5O3V, When: 6/11/1990 10:15:30 AM, Code: 086684
            Secret Key: O62PDAQRRUF2IQTS, When: 7/13/1994 12:18:36 PM, Code: 458138
            Secret Key: O6UQKLEDC3TF2D74, When: 8/15/1998 2:21:42 PM, Code: 381504
            Secret Key: 2JYR4T4ORX4W5QO6, When: 9/17/2002 4:24:48 PM, Code: 684504
            Secret Key: VKTX5GACFH7ZHIES, When: 10/19/2006 6:27:54 PM, Code: 775729
         */

        [TestInitialize()]
        public void Initialize()
        {
            //TOTPAuthenticator.SecretKeyLength = 0;
            //TOTPAuthenticator.ValidityPeriodSeconds = 30;
            //TOTPAuthenticator.EnableLockout(5, new TimeSpan(0, 30, 0));
            //TOTPAuthenticator.CodeAlgorithm = TOTPAlgorithm.HmacSHA1;
            //TOTPAuthenticator.CodeLength = 6;
            TOTPAuthenticator.SetStore("TOTPAuthenticationProviderTests.TOTPAuthenticatorDummyStore, TOTPAuthenticationProviderTests");
        }

        [TestMethod()]
        [TestCategory("PropertyTests")]
        public void Property_LockoutDuration_Tests()
        {
            var lockoutDuraction = new TimeSpan(0, 30, 0);
            TOTPAuthenticator.EnableLockout(5, lockoutDuraction);
            Assert.AreEqual(lockoutDuraction.TotalSeconds, TOTPAuthenticator.LockoutDuration.TotalSeconds);
            lockoutDuraction = new TimeSpan(0, 2, 30);
            TOTPAuthenticator.EnableLockout(5, lockoutDuraction);
            Assert.AreEqual(lockoutDuraction.TotalSeconds, TOTPAuthenticator.LockoutDuration.TotalSeconds);
            lockoutDuraction = new TimeSpan(0, 30, 0);
            TOTPAuthenticator.EnableLockout(5, lockoutDuraction);
            Assert.AreEqual(lockoutDuraction.TotalSeconds, TOTPAuthenticator.LockoutDuration.TotalSeconds);

        }

        [TestMethod()]
        [TestCategory("PropertyTests")]
        public void Property_LockoutEnabled_Tests()
        {
            var lockoutDuraction = new TimeSpan(0, 30, 0);
            TOTPAuthenticator.EnableLockout(5, lockoutDuraction);
            Assert.AreEqual(true, TOTPAuthenticator.LockoutEnabled);
            TOTPAuthenticator.DisableLockout();
            Assert.AreEqual(false, TOTPAuthenticator.LockoutEnabled);
            TOTPAuthenticator.EnableLockout(5, lockoutDuraction);
            Assert.AreEqual(true, TOTPAuthenticator.LockoutEnabled);
        }

        [TestMethod()]
        [TestCategory("PropertyTests")]
        public void Property_ValidityPeriodSeconds_Tests()
        {
            var validityPeriodSeconds = 50;
            TOTPAuthenticator.ValidityPeriodSeconds = validityPeriodSeconds;
            Assert.AreEqual(validityPeriodSeconds, TOTPAuthenticator.ValidityPeriodSeconds, "Validity Period Seconds setter appears broken.");
            Assert.ThrowsException<ArgumentException>(() => TOTPAuthenticator.ValidityPeriodSeconds = -10, "ValidityPeriodSeconds should be at least 30.");
            Assert.ThrowsException<ArgumentException>(() => TOTPAuthenticator.ValidityPeriodSeconds = 0, "ValidityPeriodSeconds should be at least 30.");
            Assert.ThrowsException<ArgumentException>(() => TOTPAuthenticator.ValidityPeriodSeconds = 20, "ValidityPeriodSeconds should be at least 30.");
            Assert.AreEqual(validityPeriodSeconds, TOTPAuthenticator.ValidityPeriodSeconds, "Validity Period Seconds setter appears broken.");
            validityPeriodSeconds = 30;
            TOTPAuthenticator.ValidityPeriodSeconds = validityPeriodSeconds;
            Assert.AreEqual(validityPeriodSeconds, TOTPAuthenticator.ValidityPeriodSeconds, "Validity Period Seconds setter appears broken.");
        }

        [TestMethod()]
        [TestCategory("PropertyTests")]
        public void Property_FutureIntervals_Tests()
        {
            var futureIntervals = 2;
            TOTPAuthenticator.FutureIntervals = futureIntervals;
            Assert.AreEqual(futureIntervals, TOTPAuthenticator.FutureIntervals, "Future Intervals setter appears broken.");
            Assert.ThrowsException<ArgumentException>(() => TOTPAuthenticator.FutureIntervals = -1, "FutureIntervals should be at least 0.");
            Assert.AreEqual(futureIntervals, TOTPAuthenticator.FutureIntervals, "Future Intervals setter appears broken.");
            futureIntervals = 1;
            TOTPAuthenticator.FutureIntervals = futureIntervals;
            Assert.AreEqual(futureIntervals, TOTPAuthenticator.FutureIntervals, "Future Intervals setter appears broken.");
        }

        [TestMethod()]
        [TestCategory("PropertyTests")]
        public void Property_PastIntervals_Tests()
        {
            var pastIntervals = 2;
            TOTPAuthenticator.PastIntervals = pastIntervals;
            Assert.AreEqual(pastIntervals, TOTPAuthenticator.PastIntervals, "Past Intervals setter appears broken.");
            Assert.ThrowsException<ArgumentException>(() => TOTPAuthenticator.PastIntervals = -1, "PastIntervals should be at least 0.");
            Assert.AreEqual(pastIntervals, TOTPAuthenticator.PastIntervals, "Past Intervals setter appears broken.");
            pastIntervals = 1;
            TOTPAuthenticator.PastIntervals = pastIntervals;
            Assert.AreEqual(pastIntervals, TOTPAuthenticator.PastIntervals, "Past Intervals setter appears broken.");
        }

        [TestMethod()]
        [TestCategory("PropertyTests")]
        public void Property_SecretKeyLength_Tests()
        {
            var secretKeyLength = 20;
            TOTPAuthenticator.SecretKeyLength = secretKeyLength;
            Assert.AreEqual(secretKeyLength, TOTPAuthenticator.SecretKeyLength, "Secret Key setter appears broken.");
            secretKeyLength = 0;
            TOTPAuthenticator.SecretKeyLength = secretKeyLength;
            Assert.AreEqual(secretKeyLength, TOTPAuthenticator.SecretKeyLength, "Secret Key setter appears broken.");
            Assert.ThrowsException<ArgumentException>(() => TOTPAuthenticator.SecretKeyLength = -10, "SecretKeyLength should be at least 16.");
            Assert.ThrowsException<ArgumentException>(() => TOTPAuthenticator.SecretKeyLength = 4, "SecretKeyLength should be at least 16.");
            Assert.AreEqual(secretKeyLength, TOTPAuthenticator.SecretKeyLength, "Secret Key setter appears broken.");
            secretKeyLength = 16;
            TOTPAuthenticator.SecretKeyLength = secretKeyLength;
            Assert.AreEqual(secretKeyLength, TOTPAuthenticator.SecretKeyLength, "Secret Key setter appears broken.");
        }

        [TestMethod()]
        [TestCategory("PropertyTests")]
        public void Property_CodeAlgorithm_Tests()
        {
            TOTPAuthenticator.CodeAlgorithm = TOTPAlgorithm.HmacSHA1;
            Assert.AreEqual(TOTPAlgorithm.HmacSHA1, TOTPAuthenticator.CodeAlgorithm, "Code Algorithm setter appears broken.");
            TOTPAuthenticator.CodeAlgorithm = TOTPAlgorithm.HmacSHA256;
            Assert.AreEqual(TOTPAlgorithm.HmacSHA256, TOTPAuthenticator.CodeAlgorithm, "Code Algorithm setter appears broken.");
            TOTPAuthenticator.CodeAlgorithm = TOTPAlgorithm.HmacSHA512;
            Assert.AreEqual(TOTPAlgorithm.HmacSHA512, TOTPAuthenticator.CodeAlgorithm, "Code Algorithm setter appears broken.");
            TOTPAuthenticator.CodeAlgorithm = TOTPAlgorithm.HmacSHA1;
            Assert.AreEqual(TOTPAlgorithm.HmacSHA1, TOTPAuthenticator.CodeAlgorithm, "Code Algorithm setter appears broken.");
        }

        [TestMethod()]
        [TestCategory("PropertyTests")]
        public void Property_CodeLength_Tests()
        {
            var codeLength = 8;
            TOTPAuthenticator.CodeLength = codeLength;
            Assert.AreEqual(codeLength, TOTPAuthenticator.CodeLength, "Code Length setter appears broken.");
            Assert.ThrowsException<ArgumentException>(() => TOTPAuthenticator.CodeLength = -10, "CodeLength should be at least 6.");
            Assert.ThrowsException<ArgumentException>(() => TOTPAuthenticator.CodeLength = 0, "CodeLength should be at least 6.");
            Assert.ThrowsException<ArgumentException>(() => TOTPAuthenticator.CodeLength = 4, "CodeLength should be at least 6.");
            Assert.ThrowsException<ArgumentException>(() => TOTPAuthenticator.CodeLength = 9, "CodeLength should be at most 8.");
            Assert.AreEqual(codeLength, TOTPAuthenticator.CodeLength, "Code Length setter appears broken.");
            codeLength = 6;
            TOTPAuthenticator.CodeLength = codeLength;
            Assert.AreEqual(codeLength, TOTPAuthenticator.CodeLength, "Code Length setter appears broken.");
        }

        [TestMethod()]
        [TestCategory("PropertyTests")]
        public void Property_MaxAttempts_Tests()
        {
            var lockoutDuraction = new TimeSpan(0, 30, 0);
            TOTPAuthenticator.EnableLockout(5, lockoutDuraction);
            Assert.AreEqual(5, TOTPAuthenticator.MaxAttempts);
            TOTPAuthenticator.EnableLockout(1, lockoutDuraction);
            Assert.AreEqual(1, TOTPAuthenticator.MaxAttempts);
            TOTPAuthenticator.DisableLockout();
            Assert.AreEqual(0, TOTPAuthenticator.MaxAttempts);
            TOTPAuthenticator.EnableLockout(5, lockoutDuraction);
            Assert.AreEqual(5, TOTPAuthenticator.MaxAttempts);
        }


        [TestMethod()]
        [TestCategory("MethodTests")]
        public void Method_SetStore_Tests()
        {
            TOTPAuthenticator.SetStore("TOTPAuthenticationProviderTests.TOTPAuthenticatorDummyStore, TOTPAuthenticationProviderTests");
            TOTPAuthenticator.SetStore("TOTPAuthenticationProvider.TOTPAuthenticatorMSSQLStore, TOTPAuthenticationProvider");
            Assert.ThrowsException<TypeLoadException>(() => TOTPAuthenticator.SetStore("TOTPAuthenticationProviderTests.TOTPAuthenticatorBREAKINGStore, TOTPAuthenticationProviderTests"));
            Assert.ThrowsException<System.IO.FileNotFoundException>(() => TOTPAuthenticator.SetStore("foo.TOTPAuthenticatorBREAKINGStore, foo"));
            Assert.ThrowsException<IndexOutOfRangeException>(() => TOTPAuthenticator.SetStore("foo"));
            Assert.ThrowsException<MissingMethodException>(() => TOTPAuthenticator.SetStore("TOTPAuthenticationProvider.Tests.TOTPAuthenticatorTests, TOTPAuthenticationProviderTests"));
            Assert.ThrowsException<ArgumentException>(() => TOTPAuthenticator.SetStore("TOTPAuthenticationProvider.Tests.foo, TOTPAuthenticationProviderTests"));
            TOTPAuthenticator.SetStore("TOTPAuthenticationProviderTests.TOTPAuthenticatorDummyStore, TOTPAuthenticationProviderTests");
        }


        [TestMethod()]
        [TestCategory("MethodTests")]
        public void Method_EnableLockout_Tests()
        {
            // Covered by Property_LockoutEnabled_Tests and Property_LockoutDuration_Tests
            var lockoutDuraction = new TimeSpan(0, 30, 0);
            TOTPAuthenticator.EnableLockout(5, lockoutDuraction);
            Assert.AreEqual(true, TOTPAuthenticator.LockoutEnabled);
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => TOTPAuthenticator.EnableLockout(0, lockoutDuraction));
            Assert.AreEqual(true, TOTPAuthenticator.LockoutEnabled);
            Assert.AreEqual(5, TOTPAuthenticator.MaxAttempts);
        }

        [TestMethod()]
        [TestCategory("MethodTests")]
        public void Method_DiasbleLockout_Tests()
        {
            // Covered by Property_LockoutEnabled_Tests and Property_LockoutDuration_Tests
        }

        [TestMethod()]
        [TestCategory("MethodTests")]
        public void Method_GetQrCodeImage_Tests()
        {
            //var x = typeof(TOTPAuthenticatorStore).Assembly.GetName().Name;
            var provider = "Test Provider";
            var user = "Method_GetQrCodeImage_Tests@foo.org";
            var secretKey = "123456";
            var altText = "Alt Text";
            var image = TOTPAuthenticator.GetQrCodeImage(provider, user, secretKey, altText);
            Assert.IsNotNull(image);
        }

        [TestMethod()]
        [TestCategory("MethodTests")]
        public void Method_CodeIsValid_Tests()
        {
            var upn = "MethodCodeIsValidTests@foo.org";
            var code = "123456";
            int attempts;
            bool locked;
            TOTPAuthenticator.CodeAlgorithm = TOTPAlgorithm.HmacSHA1;
            var codeIsValid = TOTPAuthenticator.CodeIsValid(upn, code, out attempts, out locked);
            Assert.AreEqual(false, codeIsValid);
            var key = TOTPAuthenticator.CreateSecretKey(upn);
            codeIsValid = TOTPAuthenticator.CodeIsValid(upn, code, out attempts, out locked);
            Assert.AreEqual(false, codeIsValid);

            upn = "MethodCodeIsValidTests2@foo.org";
            TOTPAuthenticator.CodeAlgorithm = TOTPAlgorithm.HmacSHA256;
            codeIsValid = TOTPAuthenticator.CodeIsValid(upn, code, out attempts, out locked);
            Assert.AreEqual(false, codeIsValid);
            key = TOTPAuthenticator.CreateSecretKey(upn);
            codeIsValid = TOTPAuthenticator.CodeIsValid(upn, code, out attempts, out locked);
            Assert.AreEqual(false, codeIsValid);

            upn = "MethodCodeIsValidTests3@foo.org";
            TOTPAuthenticator.CodeAlgorithm = TOTPAlgorithm.HmacSHA512;
            codeIsValid = TOTPAuthenticator.CodeIsValid(upn, code, out attempts, out locked);
            Assert.AreEqual(false, codeIsValid);
            key = TOTPAuthenticator.CreateSecretKey(upn);
            codeIsValid = TOTPAuthenticator.CodeIsValid(upn, code, out attempts, out locked);
            Assert.AreEqual(false, codeIsValid);

            upn = "MethodCodeIsValidTests4@foo.org";
            key = TOTPAuthenticator.CreateSecretKey(upn);
            TOTPAuthenticator.CodeAlgorithm = TOTPAlgorithm.HmacSHA1;
            TOTPAuthenticator.EnableLockout(3, new TimeSpan(0, 0, 3));
            codeIsValid = TOTPAuthenticator.CodeIsValid(upn, code, out attempts, out locked);
            Assert.AreEqual(false, locked, "");
            codeIsValid = TOTPAuthenticator.CodeIsValid(upn, code, out attempts, out locked);
            Assert.AreEqual(false, locked, "");
            codeIsValid = TOTPAuthenticator.CodeIsValid(upn, code, out attempts, out locked);
            Assert.AreEqual(true, locked, "");
            codeIsValid = TOTPAuthenticator.CodeIsValid(upn, code, out attempts, out locked);
            Assert.AreEqual(true, locked, "");

            upn = "MethodCodeIsValidTests5@foo.org";
            key = TOTPAuthenticator.CreateSecretKey(upn);
            var i = TOTPAuthenticator.GetInterval(DateTime.UtcNow);
            var x = TOTPAuthenticator.GetCode(key, i);
            var r = TOTPAuthenticator.CodeIsValid(upn, x, out _, out _);
            Assert.AreEqual(true, r);
            r = TOTPAuthenticator.CodeIsValid(upn, x, out _, out _);
            Assert.AreEqual(false, r);

            // Cannot test too much since the public methods do not allow getting the codes.
        }

        [TestMethod()]
        [TestCategory("MethodTests")]
        public void Method_HasSecretKey_Tests()
        {
            var upn = "MethodHasSecretKeyTests@foo.org";
            var hasSecretKey = TOTPAuthenticator.HasSecretKey(upn, out _, out _);
            Assert.AreEqual(false, hasSecretKey);
            var secretKey = TOTPAuthenticator.CreateSecretKey(upn);
            //hasSecretKey = TOTPAuthenticator.TryGetSecretKey(upn, out var secretKey2, out _, out _);
            hasSecretKey = TOTPAuthenticator.HasSecretKey(upn, out _, out _);
            Assert.AreEqual(true, hasSecretKey);
            //Assert.AreEqual(secretKey, secretKey2);
        }

        [TestMethod()]
        [TestCategory("MethodTests")]
        public void Method_CreateSecretKey_Tests()
        {
            // Covered by Method_HasSecretKey_Tests as well.
            TOTPAuthenticator.SecretKeyLength = 0;
            TOTPAuthenticator.CodeAlgorithm = TOTPAlgorithm.HmacSHA1;
            var upn = "MethodCreateSecretKeyTests@foo.org";
            var secretKey = TOTPAuthenticator.CreateSecretKey(upn);
            Assert.ThrowsException<TOTPAuthenticatorStoreException>(() => TOTPAuthenticator.CreateSecretKey(upn));
            Assert.AreEqual(secretKey.Length, 20);
            TOTPAuthenticator.CodeAlgorithm = TOTPAlgorithm.HmacSHA256;
            secretKey = TOTPAuthenticator.CreateSecretKey("MethodCreateSecretKeyTests2@foo.org");
            Assert.AreEqual(secretKey.Length, 32);
            TOTPAuthenticator.CodeAlgorithm = TOTPAlgorithm.HmacSHA512;
            secretKey = TOTPAuthenticator.CreateSecretKey("MethodCreateSecretKeyTests3@foo.org");
            Assert.AreEqual(secretKey.Length, 64);
            TOTPAuthenticator.SecretKeyLength = 25;
            secretKey = TOTPAuthenticator.CreateSecretKey("MethodCreateSecretKeyTests4@foo.org");
            Assert.AreEqual(secretKey.Length, 25);
            TOTPAuthenticator.SecretKeyLength = 0;
            TOTPAuthenticator.CodeAlgorithm = TOTPAlgorithm.HmacSHA1;
        }


        [TestMethod()]
        [TestCategory("RFC6238")]
        [TestCategory("MethodTests")]
        public void Method_GetInterval_Tests()
        {
            // According to RFC 6238, Appendix B.  Test Vectors
            Assert.AreEqual(0x1, TOTPAuthenticator.GetInterval(new DateTime(1970, 1, 1, 0, 0, 59, DateTimeKind.Utc)));
            Assert.AreEqual(0x23523EC, TOTPAuthenticator.GetInterval(new DateTime(2005, 3, 18, 1, 58, 29, DateTimeKind.Utc)));
            Assert.AreEqual(0x23523ED, TOTPAuthenticator.GetInterval(new DateTime(2005, 3, 18, 1, 58, 31, DateTimeKind.Utc)));
            Assert.AreEqual(0x273EF07, TOTPAuthenticator.GetInterval(new DateTime(2009, 2, 13, 23, 31, 30, DateTimeKind.Utc)));
            Assert.AreEqual(0x3F940AA, TOTPAuthenticator.GetInterval(new DateTime(2033, 5, 18, 3, 33, 20, DateTimeKind.Utc)));
            Assert.AreEqual(0x27BC86AA, TOTPAuthenticator.GetInterval(new DateTime(2603, 10, 11, 11, 33, 20, DateTimeKind.Utc)));
        }

        [TestMethod()]
        public void TestLockoutMechanism()
        {
            TOTPAuthenticator.EnableLockout(5, new TimeSpan(0, 30, 0));
            Assert.AreEqual(true, TOTPAuthenticator.LockoutEnabled);
            Assert.AreEqual(5, TOTPAuthenticator.MaxAttempts);
            Assert.AreEqual(1800, TOTPAuthenticator.LockoutDuration.TotalSeconds);
            TOTPAuthenticator.DisableLockout();
            Assert.AreEqual(0, TOTPAuthenticator.MaxAttempts);
            TOTPAuthenticator.EnableLockout(5, new TimeSpan(0, 0, 3));
            var upn = "TestLockoutSettings@unit.test";
            var attempts = 0;
            var locked = false;
            TOTPAuthenticator.CreateSecretKey(upn);
            TOTPAuthenticator.CodeIsValid(upn, "xxx", out attempts, out locked);
            Assert.AreEqual(1, attempts);
            Assert.AreEqual(false, locked);
            TOTPAuthenticator.CodeIsValid(upn, "xxx", out attempts, out locked);
            Assert.AreEqual(2, attempts);
            Assert.AreEqual(false, locked);
            TOTPAuthenticator.CodeIsValid(upn, "xxx", out attempts, out locked);
            Assert.AreEqual(3, attempts);
            Assert.AreEqual(false, locked);
            TOTPAuthenticator.CodeIsValid(upn, "xxx", out attempts, out locked);
            Assert.AreEqual(4, attempts);
            Assert.AreEqual(false, locked);
            TOTPAuthenticator.CodeIsValid(upn, "xxx", out attempts, out locked);
            Assert.AreEqual(5, attempts);
            Assert.AreEqual(true, locked);
            System.Threading.Thread.Sleep(3500);
            TOTPAuthenticator.CodeIsValid(upn, "xxx", out attempts, out locked);
            Assert.AreEqual(1, attempts);
            Assert.AreEqual(false, locked);

            TOTPAuthenticator.DisableLockout();
            TOTPAuthenticator.CodeIsValid(upn, "xxx", out attempts, out locked);
            Assert.AreEqual(2, attempts);
            Assert.AreEqual(false, locked);
            TOTPAuthenticator.CodeIsValid(upn, "xxx", out attempts, out locked);
            Assert.AreEqual(3, attempts);
            Assert.AreEqual(false, locked);
            TOTPAuthenticator.CodeIsValid(upn, "xxx", out attempts, out locked);
            Assert.AreEqual(4, attempts);
            Assert.AreEqual(false, locked);
            TOTPAuthenticator.CodeIsValid(upn, "xxx", out attempts, out locked);
            Assert.AreEqual(5, attempts);
            Assert.AreEqual(false, locked);
            TOTPAuthenticator.CodeIsValid(upn, "xxx", out attempts, out locked);
            Assert.AreEqual(6, attempts);
            Assert.AreEqual(false, locked);
            TOTPAuthenticator.CodeIsValid(upn, "xxx", out attempts, out locked);
            Assert.AreEqual(7, attempts);
            Assert.AreEqual(false, locked);

            TOTPAuthenticator.EnableLockout(5, new TimeSpan(0, 30, 0));
        }

        /// <summary>
        /// This test tests the test vectors in RFC 6238
        /// </summary>
        [TestMethod()]
        [TestCategory("RFC6238")]
        [TestCategory("MethodTests")]
        public void Method_GetCode_Tests()
        {
            TOTPAuthenticator.CodeLength = 8;

            TOTPAuthenticator.CodeAlgorithm = TOTPAlgorithm.HmacSHA1;
            var secretKey = "12345678901234567890";

            Assert.AreEqual("94287082", TOTPAuthenticator.GetCode(secretKey, 0x1));
            Assert.AreEqual("07081804", TOTPAuthenticator.GetCode(secretKey, 0x23523EC));
            Assert.AreEqual("14050471", TOTPAuthenticator.GetCode(secretKey, 0x23523ED));
            Assert.AreEqual("89005924", TOTPAuthenticator.GetCode(secretKey, 0x273EF07));
            Assert.AreEqual("69279037", TOTPAuthenticator.GetCode(secretKey, 0x3F940AA));
            Assert.AreEqual("65353130", TOTPAuthenticator.GetCode(secretKey, 0x27BC86AA));

            TOTPAuthenticator.CodeAlgorithm = TOTPAlgorithm.HmacSHA256;
            secretKey = "12345678901234567890123456789012";

            Assert.AreEqual("46119246", TOTPAuthenticator.GetCode(secretKey, 0x1));
            Assert.AreEqual("68084774", TOTPAuthenticator.GetCode(secretKey, 0x23523EC));
            Assert.AreEqual("67062674", TOTPAuthenticator.GetCode(secretKey, 0x23523ED));
            Assert.AreEqual("91819424", TOTPAuthenticator.GetCode(secretKey, 0x273EF07));
            Assert.AreEqual("90698825", TOTPAuthenticator.GetCode(secretKey, 0x3F940AA));
            Assert.AreEqual("77737706", TOTPAuthenticator.GetCode(secretKey, 0x27BC86AA));

            TOTPAuthenticator.CodeAlgorithm = TOTPAlgorithm.HmacSHA512;
            secretKey = "1234567890123456789012345678901234567890123456789012345678901234";

            Assert.AreEqual("90693936", TOTPAuthenticator.GetCode(secretKey, 0x1));
            Assert.AreEqual("25091201", TOTPAuthenticator.GetCode(secretKey, 0x23523EC));
            Assert.AreEqual("99943326", TOTPAuthenticator.GetCode(secretKey, 0x23523ED));
            Assert.AreEqual("93441116", TOTPAuthenticator.GetCode(secretKey, 0x273EF07));
            Assert.AreEqual("38618901", TOTPAuthenticator.GetCode(secretKey, 0x3F940AA));
            Assert.AreEqual("47863826", TOTPAuthenticator.GetCode(secretKey, 0x27BC86AA));
        }

        [TestMethod()]
        public void foo()
        {
            TOTPAuthenticator.SetStore("TOTPAuthenticationProvider.TOTPAuthenticatorMSSQLStore, TOTPAuthenticationProvider", "Server=tcp:gbslab.database.windows.net,1433;Initial Catalog=GBSLAB;Persist Security Info=False;User ID=bigboss;Password=P@ssword1;Encrypt=True;Connection Timeout=30;");
            TOTPAuthenticator.CodeAlgorithm = TOTPAlgorithm.HmacSHA1;
            TOTPAuthenticator.CodeLength = 6;
            var i = TOTPAuthenticator.GetInterval(DateTime.UtcNow);
            var c = TOTPAuthenticator.GetCode("KPB4Y6WYVW7ASIDAB3YC", i);
            var x = TOTPAuthenticator.CodeIsValid("tino@gbslab.com", c, out var a, out var l);
            var y = TOTPAuthenticator.GetQrCodeImage("GBSLAB", "tino@gbslab.com", "KPB4Y6WYVW7ASIDAB3YC", "Alternate Text");
        }

        /// <summary>
        /// This test tests the test vectors in RFC 4648
        /// </summary>
        [TestMethod()]
        [TestCategory("RFC4648")]
        [TestCategory("MethodTests")]
        public void Base32EncodingTests()
        {
            string text;
            string base32string;

            text = "";
            base32string = text.EncodeAsBase32String();
            Assert.AreEqual("", base32string);
            text = "f";
            base32string = text.EncodeAsBase32String();
            Assert.AreEqual("MY======", base32string);
            text = "fo";
            base32string = text.EncodeAsBase32String();
            Assert.AreEqual("MZXQ====", base32string);
            text = "foo";
            base32string = text.EncodeAsBase32String();
            Assert.AreEqual("MZXW6===", base32string);
            text = "foob";
            base32string = text.EncodeAsBase32String();
            Assert.AreEqual("MZXW6YQ=", base32string);
            text = "fooba";
            base32string = text.EncodeAsBase32String();
            Assert.AreEqual("MZXW6YTB", base32string);
            text = "foobar";
            base32string = text.EncodeAsBase32String();
            Assert.AreEqual("MZXW6YTBOI======", base32string);
        }

        /// <summary>
        /// This test tests the test vectors in RFC 4648
        /// </summary>
        [TestMethod()]
        [TestCategory("RFC4648")]
        [TestCategory("MethodTests")]
        public void Base32DecodingTests()
        {
            string text;
            string base32string;

            base32string = "";
            text = base32string.DecodeFromBase32String();
            Assert.AreEqual("", text);
            base32string = "MY======";
            text = base32string.DecodeFromBase32String();
            Assert.AreEqual("f", text);
            base32string = "MZXQ====";
            text = base32string.DecodeFromBase32String();
            Assert.AreEqual("fo", text);
            base32string = "MZXW6===";
            text = base32string.DecodeFromBase32String();
            Assert.AreEqual("foo", text);
            base32string = "MZXW6YQ=";
            text = base32string.DecodeFromBase32String();
            Assert.AreEqual("foob", text);
            base32string = "MZXW6YTB";
            text = base32string.DecodeFromBase32String();
            Assert.AreEqual("fooba", text);
            base32string = "MZXW6YTBOI======";
            text = base32string.DecodeFromBase32String();
            Assert.AreEqual("foobar", text);
        }
    }
}