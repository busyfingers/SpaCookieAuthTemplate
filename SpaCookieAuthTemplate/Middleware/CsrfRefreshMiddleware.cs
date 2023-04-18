using Microsoft.AspNetCore.Antiforgery;
using SpaCookieAuthTemplate.Helpers;

namespace SpaCookieAuthTemplate.Middleware
{
    public class CsrfRefreshMiddleware
    {
        private readonly RequestDelegate _next;

        public CsrfRefreshMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(HttpContext context, IAntiforgery antiforgery)
        {
            TokenUtils.RefreshCSRFToken(antiforgery, context);

            await _next(context);
        }
    }
}
