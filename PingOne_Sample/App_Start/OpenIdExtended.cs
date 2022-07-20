using System;
using System.Linq;
using System.Security.Claims;

namespace PingOne_Sample.App_Start
{
    public static class OpenIdExtended
    {
        public static string GetClaimValue(this ClaimsIdentity identity, string claimName)
        {
            var specificClaim = identity.Claims.FirstOrDefault(x => x.Type == claimName);
            return specificClaim?.Value ?? string.Empty;
        }
    }
}