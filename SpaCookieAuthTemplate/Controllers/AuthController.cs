using Microsoft.AspNetCore.Antiforgery;
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
        [HttpGet("User")]
        public async Task<IActionResult> GetUser()
        {
            var user = await userManager.GetUserAsync(User);

            return Ok(user);
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
    }
}
