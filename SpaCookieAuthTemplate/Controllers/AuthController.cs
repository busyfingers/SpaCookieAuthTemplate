using System.Security.Claims;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using SpaCookieAuthTemplate.Helpers;
using SpaCookieAuthTemplate.Model;

namespace SpaCookieAuthTemplate.Controllers
{
    [AutoValidateAntiforgeryToken]
    [Route("[controller]")]
    public class AuthController : Controller
    {
        private readonly UserManager<IdentityUser> userManager;
        private readonly SignInManager<IdentityUser> signInManager;
        private readonly IAntiforgery antiforgery;

        public AuthController(UserManager<IdentityUser> userManager,
            SignInManager<IdentityUser> signInManager,
            IAntiforgery antiforgery)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.antiforgery = antiforgery;
        }

        [HttpGet]
        [IgnoreAntiforgeryToken]
        [Route("csrf")]
        public IActionResult CSRF()
        {
            TokenUtils.RefreshCSRFToken(antiforgery, HttpContext);

            return Ok();
        }

        [HttpPost("Register")]
        public async Task<IActionResult> Register([FromBody] UserCredentials credentials)
        {
            var user = new IdentityUser { UserName = credentials.Email, Email = credentials.Email };
            var result = await userManager.CreateAsync(user, credentials.Password);

            if (!result.Succeeded)
            {
                return StatusCode(StatusCodes.Status500InternalServerError);
            }

            return Ok();
        }

        [Authorize]
        [HttpGet("secret")]
        public IActionResult Secret()
        {
            return Ok("secret!");
        }

        [Authorize]
        [HttpGet("User")]
        public async Task<IActionResult> GetUser()
        {
            var user = await userManager.GetUserAsync(User);

            return Ok(new
            {
                Name = user?.NormalizedUserName,
                Email = user?.Email
            });
        }

        [HttpPost("Login")]
        public async Task<IActionResult> Login([FromBody] UserCredentials credentials)
        {
            if (User != null && User.Identity != null && User.Identity.IsAuthenticated)
            {
                return Ok();
            }

            var result = await signInManager
                .PasswordSignInAsync(credentials.Email,
                    credentials.Password,
                    isPersistent: true,
                    lockoutOnFailure: false);

            if (!result.Succeeded)
            {
                return BadRequest("Invalid login");
            }

            TokenUtils.RefreshCSRFToken(antiforgery, HttpContext);

            return Ok();
        }

        [HttpGet("Logout")]
        public async Task<IActionResult> Logout()
        {
            await signInManager.SignOutAsync();

            return Ok();
        }

        [HttpGet("googlelogin")]
        public IActionResult GoogleLogin()
        {
            var clientUrl = Request.Headers.Origin.FirstOrDefault() ?? Request.Headers.Referer.FirstOrDefault();
            var redirectUrl = Url.Action("GoogleResponse", "Auth");
            redirectUrl += $"?clientUrl={clientUrl}";
            var properties = signInManager.ConfigureExternalAuthenticationProperties(GoogleDefaults.AuthenticationScheme, redirectUrl);

            return new ChallengeResult(GoogleDefaults.AuthenticationScheme, properties);
        }

        [HttpGet("googleresponse")]
        public async Task<IActionResult> GoogleResponse()
        {
            var info = await signInManager.GetExternalLoginInfoAsync();
            var email = info?.Principal.FindFirst(ClaimTypes.Email)?.Value;

            if (info == null || info.Principal == null || email == null)
            {
                return StatusCode(StatusCodes.Status503ServiceUnavailable);
            }

            IdentityUser? user;
            var result = await signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, true);

            if (result.Succeeded)
            {
                user = await userManager.FindByEmailAsync(email);

                if (user == null)
                {
                    return StatusCode(StatusCodes.Status500InternalServerError);
                }

                return await InitSessionAndReturn(user, email);
            }

            user = new IdentityUser
            {
                Email = info.Principal.FindFirst(ClaimTypes.Email)!.Value,
                UserName = info.Principal.FindFirst(ClaimTypes.Email)!.Value
            };

            var identResult = await userManager.CreateAsync(user);

            if (identResult.Succeeded)
            {
                identResult = await userManager.AddLoginAsync(user, info);

                if (identResult.Succeeded)
                {
                    await signInManager.SignInAsync(user, true);

                    return await InitSessionAndReturn(user, email);
                }
            }

            return StatusCode(StatusCodes.Status401Unauthorized);
        }

        private async Task<IActionResult> InitSessionAndReturn(IdentityUser user, string email)
        {
            HttpContext.User = await signInManager.CreateUserPrincipalAsync(user);

            TokenUtils.RefreshCSRFToken(antiforgery, HttpContext);

            return RedirectToClient(email);
        }

        private IActionResult RedirectToClient(string email)
        {
            var clientUrl = Request.Query.TryGetValue("clientUrl", out var match) ? match.ToString() : "/";

            return Redirect($"{clientUrl}?email={email}");
        }
    }
}
