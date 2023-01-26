using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using WebApplication3.Models;

namespace WebApplication3.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticateController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public AuthenticateController(
            UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IConfiguration configuration
             )
         {
            this._userManager = userManager;
            this._roleManager = roleManager;
            this._configuration = configuration;
         }

        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            var _user = await _userManager.FindByNameAsync(model.UserName);
            if (_user is not null && await _userManager.CheckPasswordAsync(_user,model.Password))
            {
                var _userRoles = await _userManager.GetRolesAsync(_user);
                var _claims = new List<Claim>()
                {
                    new Claim(ClaimTypes.Name, _user.UserName),
                    new Claim(ClaimTypes.Email, _user.Email),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };
                foreach (var userRole in _userRoles)
                {
                    _claims.Add(new Claim(ClaimTypes.Role, userRole));
                }

                var _token = GetToken(_claims);
                return Ok(new
                {
                    Token = new JwtSecurityTokenHandler().WriteToken(_token),
                    Expiration = _token.ValidTo
                });
            }

            return Unauthorized();
        }

        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            var _user = await _userManager.FindByNameAsync(model.UserName);
            if (_user is not null)
                return StatusCode(StatusCodes.Status403Forbidden, new Response { Status = "Error", Message = "User Already Exists" });
            
            _user = new IdentityUser
            {
                UserName = model.UserName,
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
            };
            var _result = await _userManager.CreateAsync(_user,model.Password);
            if (!_result.Succeeded)
                return StatusCode(StatusCodes.Status400BadRequest,new Response { Status="Error",Message="User Not Created"});
            return StatusCode(StatusCodes.Status200OK, _user);
        }

        [HttpPost]
        [Route("Admin")]
        public async Task<IActionResult> Admin([FromBody] RegisterModel model)
        {
            var _user = await _userManager.FindByNameAsync(model.UserName);
            if (_user is not null)
                return StatusCode(StatusCodes.Status400BadRequest, new Response { Status="Error",Message="User Already Exists"});

            _user = new IdentityUser 
            { 
                UserName = model.UserName, 
                Email = model.Email, 
                SecurityStamp = Guid.NewGuid().ToString()
            };            
            var _result = await _userManager.CreateAsync(_user,model.Password);
            if(!_result.Succeeded)
                return StatusCode(StatusCodes.Status400BadRequest, new Response { Status = "Error", Message = "User Not Created" });
            
            //If Roles does not exist insert into Database
            if (!await _roleManager.RoleExistsAsync(UserRoles.Admin))
                await _roleManager.CreateAsync(new IdentityRole(UserRoles.Admin));
            if (!await _roleManager.RoleExistsAsync(UserRoles.User))
                await _roleManager.CreateAsync(new IdentityRole(UserRoles.User));

            if (await _roleManager.RoleExistsAsync(UserRoles.Admin))
                await _userManager.AddToRoleAsync(_user,UserRoles.Admin);
            if (await _roleManager.RoleExistsAsync(UserRoles.User))
                await _userManager.AddToRoleAsync(_user, UserRoles.User);

            return Ok(new Response { Status = "Success", Message = "User Created " });
        }

        private JwtSecurityToken GetToken (List<Claim> claims)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                expires: DateTime.Now.AddHours(1),
                claims: claims,
                signingCredentials: new SigningCredentials(key,SecurityAlgorithms.HmacSha256Signature)
                );
            return token;
        }
    }
}
