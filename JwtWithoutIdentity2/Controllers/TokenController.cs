using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using JwtWithoutIdentity2.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;

namespace JwtWithoutIdentity2.Controllers
{
    public class TokenController : Controller
    {
        [AllowAnonymous]
        [Route("api/token")]
        [HttpPost]
        //public async Task<IActionResult> Token(LoginViewModel model)
        public async Task<IActionResult> Token([FromBody] LoginViewModel model)
        {

            if (!ModelState.IsValid) return BadRequest("Token failed to generate");

            var user = (model.Password == "password" && model.Username == "username");

            if (!user) return Unauthorized();

            //Add Claims
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.UniqueName, "data"),
                new Claim(JwtRegisteredClaimNames.Sub, "data"),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("rlyaKithdrYVl6Z80ODU350md")); //Secret
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken("me",
                "you",
                claims,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: creds);

            return Ok(new JsonWebToken()
            {
                access_token = new JwtSecurityTokenHandler().WriteToken(token),
                expires_in = 600000,
                token_type = "bearer"
            });
        }
    }
}