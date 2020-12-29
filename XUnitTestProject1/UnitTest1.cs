using System;
using Xunit;
using IIG.PasswordHashingUtils;

namespace XUnitTestProject1
{
    public class UnitTest1
    {
        [Fact]
        public void InitTest()
        {
            PasswordHasher.Init("init_salt", 7);

            Assert.Equal(PasswordHasher.GetHash("pass"), PasswordHasher.GetHash("pass", "init_salt", 7));
            Assert.NotEqual(PasswordHasher.GetHash("pass"), PasswordHasher.GetHash("pass", "salt", 1));
        }


        [Fact]
        public void GetHashTest()
        {
            Assert.NotNull(PasswordHasher.GetHash("pass"));
            Assert.NotEmpty(PasswordHasher.GetHash("pass1"));
            Assert.NotEqual(PasswordHasher.GetHash("pass2"), PasswordHasher.GetHash("pass3"));
            Assert.Equal(PasswordHasher.GetHash("pass2"), PasswordHasher.GetHash("pass2", null, null));

            Assert.NotNull(PasswordHasher.GetHash("pass", "salt"));
            Assert.NotEmpty(PasswordHasher.GetHash("pass1", "salt1"));
            Assert.NotEqual(PasswordHasher.GetHash("pass2", "salt2"), PasswordHasher.GetHash("pass2", "salt3"));

            Assert.NotNull(PasswordHasher.GetHash("pass", "salt", 0));
            Assert.NotEmpty(PasswordHasher.GetHash("pass1", "salt1", 1));
            Assert.NotEqual(PasswordHasher.GetHash("pass2", "salt2", 2), PasswordHasher.GetHash("pass2", "salt2", 3));
        }


        [Fact]
        public void GetHashSymbolsTest()
        {
            Assert.ThrowsAny<OverflowException>(() => PasswordHasher.GetHash("укр_тест/[]*&^#@!$%,.}<>{:_-+=§₽¶妈妈", null));
            Assert.ThrowsAny<OverflowException>(() => PasswordHasher.GetHash("", null));
            Assert.ThrowsAny<OverflowException>(() => PasswordHasher.GetHash(" ", null));
            Assert.NotNull(PasswordHasher.GetHash("укр_тест/[]*&^#@!$%,.}<>{:_-+=§₽¶妈妈", " "));
            Assert.NotNull(PasswordHasher.GetHash("", " "));
            Assert.NotNull(PasswordHasher.GetHash(" ", " "));

            Assert.ThrowsAny<OverflowException>(() => PasswordHasher.GetHash("pass", "укр_тест"));
            Assert.ThrowsAny<OverflowException>(() => PasswordHasher.GetHash("pass", "§₽¶妈妈"));
            Assert.ThrowsAny<OverflowException>(() => PasswordHasher.GetHash("pass", ""));
            Assert.NotNull(PasswordHasher.GetHash("pass", "/[] * &^#@!$%,.}<>{:_-+=123"));
        }

        [Fact]
        public void InitSymbolsTest()
        {
            PasswordHasher.Init(null, 1);
            Assert.NotNull(PasswordHasher.GetHash("pass"));

            PasswordHasher.Init("укр_тест", 1);
            Assert.ThrowsAny<OverflowException>(() => PasswordHasher.GetHash("pass"));
            PasswordHasher.Init("§₽¶妈妈", 1);
            Assert.ThrowsAny<OverflowException>(() => PasswordHasher.GetHash("pass"));
        }


        [Fact]
        public void BoundaryValuesTest()
        {
            Assert.NotNull(PasswordHasher.GetHash("pass", "salt", 4294967295));
            Assert.NotNull(PasswordHasher.GetHash("pass", "salt", 0));
        }

        /*
        [Fact]
        public void BoundaryValuesErrorTest()
        {
            Assert.ThrowsAny<OverflowException>(() => PasswordHasher.GetHash("pass", "salt", -1));
            Assert.ThrowsAny<OverflowException>(() => PasswordHasher.GetHash("pass", "salt", 4294967296));
        }
        */
    }
}

