using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(EmailTwoFactorNETFramework48.Startup))]
namespace EmailTwoFactorNETFramework48
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
