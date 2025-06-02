using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Timers;
using System;
using System.Globalization;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Security;

using Microsoft.AspNet.Identity.Owin;

namespace EmailTwoFactorLibrary
{
    public class SignInManager<TUser, TKey> : Microsoft.AspNet.Identity.Owin.SignInManager<TUser, TKey> where TUser : class, IUser<TKey> where TKey : IEquatable<TKey>
    {
        public SignInManager(UserManager<TUser, TKey> userManager, IAuthenticationManager authenticationManager)
            : base(userManager, authenticationManager)
        {
        }

        public override async Task<bool> SendTwoFactorCodeAsync(string provider)
        {
            TKey userId = await GetVerifiedUserIdAsync();
            if (userId == null)
            {
                return false;
            }

            var token = Token.GenerateToken();
            Token.SetToken(Convert.ToInt32(userId), token);

            await base.UserManager.SendEmailAsync(userId, "Two Factor Authentication", "Your two factor authentication token: " + token);
            return true;
        }

        public override async Task<SignInStatus> TwoFactorSignInAsync(string provider, string code, bool isPersistent, bool rememberBrowser)
        {
            TKey val = await GetVerifiedUserIdAsync();
            if (val == null)
            {
                return SignInStatus.Failure;
            }

            TUser user = await UserManager.FindByIdAsync(val);
            if (user == null)
            {
                return SignInStatus.Failure;
            }

            if (await UserManager.IsLockedOutAsync(user.Id))
            {
                return SignInStatus.LockedOut;
            }

            if (await UserManager.VerifyTwoFactorTokenAsync(user.Id, provider, code))
            {
                if (!(await UserManager.ResetAccessFailedCountAsync(user.Id)).Succeeded)
                {
                    return SignInStatus.Failure;
                }

                await SignInAsync(user, isPersistent, rememberBrowser);
                return SignInStatus.Success;
            }

            _ = (await UserManager.AccessFailedAsync(user.Id)).Succeeded;
            return SignInStatus.Failure;
        }

        public override async Task<SignInStatus> TwoFactorSignInAsync<TUser, TKey>(string code, bool isPersistent, bool rememberBrowser) where TUser : class, IUser<TKey> where TKey : IEquatable<TKey>
        {
            TKey val = await base.GetVerifiedUserIdAsync();
            if (val == null)
            {
                return SignInStatus.Failure;
            }

            TUser user = await UserManager.FindByIdAsync(val).WithCurrentCulture();
            if (user == null)
            {
                return SignInStatus.Failure;
            }

            if (await UserManager.IsLockedOutAsync(user.Id).WithCurrentCulture())
            {
                return SignInStatus.LockedOut;
            }

            if (await UserManager.VerifyTwoFactorTokenAsync(user.Id, provider, code).WithCurrentCulture())
            {
                if (!(await UserManager.ResetAccessFailedCountAsync(user.Id).WithCurrentCulture()).Succeeded)
                {
                    return SignInStatus.Failure;
                }

                await SignInAsync(user, isPersistent, rememberBrowser).WithCurrentCulture();
                return SignInStatus.Success;
            }

            _ = (await UserManager.AccessFailedAsync(user.Id).WithCurrentCulture()).Succeeded;
            return SignInStatus.Failure;
        }
    }
}
