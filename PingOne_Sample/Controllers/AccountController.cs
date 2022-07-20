using System;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using Microsoft.Owin.Security;

namespace PingOne_Sample.Controllers
{
    public class AccountController : Controller
    {
        // GET: Account
        public ActionResult Login()
        {
            if (!HttpContext.User.Identity.IsAuthenticated)
            {
                HttpContext.GetOwinContext().Authentication.Challenge(OpenIdConnectAuthenticationDefaults.AuthenticationType);
                //HttpContext.GetOwinContext().Authentication.Challenge(new AuthenticationProperties { RedirectUri = Url.Action("Index", "Home") }, "PingOne");
                return new HttpUnauthorizedResult();
            }
            
            return RedirectToAction("Index", "Home");
    }

    public ActionResult PostLogout()
    {
        return RedirectToAction("Index", "Home");
    }

    public ActionResult Logout()
    {
        if (HttpContext.User.Identity.IsAuthenticated)
        {
            HttpContext.GetOwinContext().Authentication.SignOut(OpenIdConnectAuthenticationDefaults.AuthenticationType,
                CookieAuthenticationDefaults.AuthenticationType);
            //HttpContext.GetOwinContext().Authentication.SignOut(new AuthenticationProperties { RedirectUri = Url.Action("Index", "Home") }, "PingOne");

        }

        return RedirectToAction("Index", "Home");
    }

    [Authorize]
    public ActionResult Claims()
    {
        return View(HttpContext.GetOwinContext().Authentication.User.Claims);
    }
}
}