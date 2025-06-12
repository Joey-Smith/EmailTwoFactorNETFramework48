using System;
using System.Runtime.Caching;
using System.Configuration;
using System.Net;
using System.Net.Mail;
using System.Net.Mime;
using System.Threading;
using System.ComponentModel;
using System.Threading.Tasks;
using System.Web;
using System.Web.Security;
using System.Text;

namespace EmailTwoFactorLibrary
{
    internal static class Cookie
    {
        static readonly int _expiration;

        static Cookie()
        {
            if (!int.TryParse(ConfigurationManager.AppSettings["EmailTwoFactorLibrary.Cookie.Expiration"], out _expiration))
            {
                throw new ArgumentOutOfRangeException("EmailTwoFactorLibrary.Cookie.Expiration", ConfigurationManager.AppSettings["EmailTwoFactorLibrary.Cookie.Expiration"], "Cookie expiration should be an integer representing the minutes until expiration.");
            }
        }
        public static HttpCookie CreateCookie()
        {
            HttpCookie cookie = new HttpCookie(MachineKey.Protect(Encoding.UTF8.GetBytes("TwoFactorAuth")).ToString(), MachineKey.Protect(Encoding.UTF8.GetBytes("true")).ToString())
            {
                HttpOnly = true, // Prevents client-side scripts from accessing the cookie
                Secure = true, // Ensures the cookie is sent over HTTPS only
                SameSite = SameSiteMode.Strict, // Prevents the cookie from being sent with cross-site requests
                Expires = DateTime.Now.AddMinutes(_expiration) // Set cookie expiration time
            };

            return cookie;
        }
    }
}
