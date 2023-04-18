using Microsoft.AspNetCore.Antiforgery;

namespace SpaCookieAuthTemplate.Helpers
{
    public class TokenUtils
    {
        public static void RefreshCSRFToken(IAntiforgery antiforgery, HttpContext httpContext)
        {
            var tokens = antiforgery.GetAndStoreTokens(httpContext);
            var cookieOptions = new CookieOptions
            {
                HttpOnly = false,
                Secure = true,
                SameSite = SameSiteMode.None
            };

            httpContext.Response.Cookies.Append("XSRF-TOKEN", tokens.RequestToken!, cookieOptions);
        }
    }
}
