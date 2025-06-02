using System;
using System.Runtime.Caching;
using System.Configuration;

namespace EmailTwoFactorLibrary
{
    internal static class Token
    {
        static readonly MemoryCache _cache = MemoryCache.Default;
        static readonly int _length;
        static readonly int _expiration;
        static readonly int _maxInt;

        static Token()
        {
            if (!int.TryParse(ConfigurationManager.AppSettings["EmailTwoFactorLibrary.Token.Length"], out _length))
            {
                throw new ArgumentOutOfRangeException("EmailTwoFactorLibrary.Token.Length", ConfigurationManager.AppSettings["EmailTwoFactorLibrary.Token.Length"], "Token length should be an integer representing the number of characters in the token.");
            }
            if (!int.TryParse(ConfigurationManager.AppSettings["EmailTwoFactorLibrary.Token.Expiration"], out _length))
            {
                throw new ArgumentOutOfRangeException("EmailTwoFactorLibrary.Token.Expiration", ConfigurationManager.AppSettings["EmailTwoFactorLibrary.Token.Expiration"], "Token expiration should be an integer representing the minutes until expiration.");
            }

            _maxInt = int.Parse("".PadLeft(_length, '9'));
        }
        public static string GenerateToken()
        {
            var random = new Random();
            var token = random.Next(_maxInt);

            return token.ToString().PadLeft(_length, '0');
        }
        public static void SetToken(int userId, string token)
        {
            _cache.Set(userId.ToString(), token, DateTimeOffset.UtcNow.AddMinutes(_expiration));
        }
    }
}
