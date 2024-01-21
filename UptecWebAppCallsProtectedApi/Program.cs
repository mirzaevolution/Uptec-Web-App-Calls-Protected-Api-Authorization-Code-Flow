
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Identity.Web;
namespace UptecWebAppCallsProtectedApi
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);
            var config = builder.Configuration;
            var services = builder.Services;

            string todoApiName = "TodoApi";

            services.AddMicrosoftIdentityWebAppAuthentication(config)
                .EnableTokenAcquisitionToCallDownstreamApi()
                .AddDownstreamApi(todoApiName, config.GetSection(todoApiName))
                .AddInMemoryTokenCaches();

            services.Configure<CookieAuthenticationOptions>(options =>
            {
                options.LoginPath = new PathString("/Auth/Login");
                options.LogoutPath = new PathString("/Auth/Logout");
                options.ReturnUrlParameter = "redirectUrl";
            });

            services.AddControllersWithViews();
            var app = builder.Build();
            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/Home/Error");
                app.UseHsts();
            }
            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();

            app.MapControllerRoute(
                name: "default",
                pattern: "{controller=Home}/{action=Index}/{id?}");

            app.Run();
        }
    }
}