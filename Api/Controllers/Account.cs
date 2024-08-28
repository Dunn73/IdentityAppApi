using System.Security.Claims;
using System.Text;
using Api.DTOs.Account;
using Api.Models;
using Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;

namespace Api.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AccountController : ControllerBase {
    private readonly JWTService _jwtService;
    private readonly SignInManager<User> _signInManager;
    private readonly UserManager<User> _userManager;
    private readonly EmailService _emailService;
    private readonly IConfiguration _config;

    public AccountController(JWTService jwtService,
    SignInManager<User> signInManager,
    UserManager<User> userManager,
    EmailService emailService,
    IConfiguration config) {
        _jwtService = jwtService;
        _signInManager = signInManager;
        _userManager = userManager;
        _emailService = emailService;
        _config = config;
    }

    [Authorize]
    [HttpGet("refresh-user-token")]
    public async Task<ActionResult<UserDto>> RefreshUserToken() {
        var user = await _userManager.FindByNameAsync(User.FindFirst(ClaimTypes.Email)?.Value);
        return CreateApplicationUserDto(user);
    }

    [HttpPost("login")]
    public async Task<ActionResult<UserDto>> Login(LoginDto model) {
        var user = await _userManager.FindByNameAsync(model.UserName);
        if (user == null) return Unauthorized("Incorrect username or password.");
        if (user.EmailConfirmed == false) return Unauthorized("Please confirm email.");
        var result = await _signInManager.CheckPasswordSignInAsync(user, model.Password, false);
        if (!result.Succeeded) return Unauthorized("Incorrect username or password.");

        return CreateApplicationUserDto(user);
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register(RegisterDto model) {
        if (await CheckEmailExistAsync(model.Email)) {
            return BadRequest($"An existing account is using {model.Email}, email address. Please try with another email address.");
        }
        var userToAdd = new User {
            FirstName = model.FirstName.ToLower(),
            LastName = model.LastName.ToLower(),
            UserName = model.Email.ToLower(),
            Email = model.Email.ToLower(),
        };

        var result = await _userManager.CreateAsync(userToAdd, model.Password);
        if (!result.Succeeded) return BadRequest(result.Errors);


        try {
            if (await SendConfirmEmailAsync(userToAdd)) {
                return Ok(new JsonResult(new {title = "Account created.", message = "Your account has been created, please confirm your email address."}));
            }
            return BadRequest("Failed to send email. Please contact admin.");
        }
        catch(Exception) {
            return BadRequest("Failed to send email. Please contact admin.");
        }
    }

    [HttpPut("confirm-email")]
    public async Task<IActionResult> ConfirmEmail(ConfirmEmailDto model) {
        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user == null) {
            return Unauthorized("This email address has not been registered yet.");
        }
        if (user.EmailConfirmed == true) {
            return BadRequest("Your email has already been confirmed. You may log into your account now.");
        }

        try {
            var decodedTokenBytes = WebEncoders.Base64UrlDecode(model.Token);
            var decodedToken = Encoding.UTF8.GetString(decodedTokenBytes);

            var result = await _userManager.ConfirmEmailAsync(user, decodedToken);
            if (result.Succeeded) {
                return Ok(new JsonResult(new { title="Email confirmed.", message = "Your email address is confirmed, you may now log in."}));
            }

            return BadRequest("Invalid token. Please try again.");
        }
        catch(Exception) {
            return BadRequest("Invalid token. Please try again.");
        }
    }

    [HttpPost("resend-email-confirmation-link/{email}")]
    public async Task<IActionResult> ResendEmailConfirmationLink(string email) {
        if (string.IsNullOrEmpty(email)) return BadRequest("Invalid Email");
        var user = await _userManager.FindByEmailAsync(email);

        if (user == null) return Unauthorized("This email has not been registered yet.");
        if (user.EmailConfirmed == true) {
            return BadRequest("Your email address has already been confirmed. You may now sign in.");
        }

        try {
            if (await SendConfirmEmailAsync(user)) {
                return Ok(new JsonResult(new {title = "Confirmation email sent.", message = "Please confirm your email address."}));
            }

            return BadRequest("Failed to send email. Please contact admin.");
        }
        catch (Exception) {
            return BadRequest("Failed to send email. Please contact admin.");
        }
        
    }

    [HttpPost("forgot-username-or-password/{email}")]
    public async Task<IActionResult> ForgotUsernameOrPassword(string email) {

        if (string.IsNullOrEmpty(email)) return BadRequest("Invalid Email");

        var user = await _userManager.FindByEmailAsync(email);

        if (user == null) {
            return Unauthorized("This email address has not been registered.");
        }

        if (user.EmailConfirmed == false) {
            return BadRequest("Please confirm your email address first.");
        }

        try {
            if (await SendForgotUsernameOrPasswordEmail(user)) {
                return Ok(new JsonResult(new {title = "Forgot username or password email sent.", message = "Please check email."}));
            }
            return BadRequest("Failed to send email.");
        }
        catch (Exception) {
            return BadRequest("Failed to send email.");
        }
    }

    [HttpPut("reset-password")]
    public async Task<IActionResult> ResetPassword(ResetPasswordDto model) {
        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user ==null) {
            return Unauthorized("This email address has not been registered.");
        }
        if (user.EmailConfirmed == false) {
            return BadRequest("Please confirm your email address first.");
        }

        try {
            var decodedTokenBytes = WebEncoders.Base64UrlDecode(model.Token);
            var decodedToken = Encoding.UTF8.GetString(decodedTokenBytes);

            var result = await _userManager.ResetPasswordAsync(user, decodedToken, model.NewPassword);
            if (result.Succeeded) {
                return Ok(new JsonResult(new { title="Password reset success", message = "Your password has been reset."}));
            }

            return BadRequest("Invalid token. Please try again.");
        }
        catch (Exception){
            return BadRequest("Invalid token. Please try again.");
        }
    }

    // Private helper methods
    private UserDto CreateApplicationUserDto(User user) {
        return new UserDto {
            FirstName = user.FirstName,
            LastName = user.LastName,
            JWT = _jwtService.CreateJWT(user)
        };
    }
    private async Task<bool> CheckEmailExistAsync(string email) {
        return await _userManager.Users.AnyAsync(x => x.Email == email.ToLower());
    }

    private async Task<bool> SendConfirmEmailAsync(User user) {
        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
        var url = $"{_config["JWT:ClientUrl"]}/{_config["Email:ConfirmEmailPath"]}?token={token}&email={user.Email}";

        var body = $"<p>Hello: {user.FirstName} {user.LastName}</p>" + 
        "<p>Please confirm your email address by clicking on the following link.</p>" +
        $"<p><a href=\"{url}\">Click here</a></p>" +
        "<p>Thank you, </p>" +
        $"<br>{_config["Email:ApplicationName"]}";

        var emailSend = new EmailSendDto(user.Email, "Confirm your email", body);

        return await _emailService.SendEmailAsync(emailSend);
    }

    private async Task<bool> SendForgotUsernameOrPasswordEmail(User user) {
        var token = await _userManager.GeneratePasswordResetTokenAsync(user);
        token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
        var url = $"{_config["JWT:ClientUrl"]}/{_config["Email:ResetPasswordPath"]}?token={token}&email={user.Email}";

        var body = $"<p>Hello: {user.FirstName} {user.LastName}</p>" +
            $"<p>Username: {user.UserName}.</p>" +
            "<p>In order to reset your password, please click on the following link: </p>" +
            $"<p><a href=\"{url}\">Click here</a></p>" +
            "<p>Thank you, </p>" +
            $"<br>{_config["Email:ApplicationName"]}";
        
        var emailSend = new EmailSendDto(user.Email, "Forgot username or password", body);

        return await _emailService.SendEmailAsync(emailSend);
    }
}
