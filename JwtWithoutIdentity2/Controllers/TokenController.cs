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
using JwtWithoutIdentity2.Helpers;

namespace JwtWithoutIdentity2.Controllers
{
    public class TokenController : Controller
    {
        [AllowAnonymous]
        [Route("api/token")]
        [HttpPost]
        public async Task<IActionResult> Token([FromBody] LoginViewModel model)
        {

            if (!ModelState.IsValid) return BadRequest("Token failed to generate");

            var user = (model.Password == "password" && model.Username == "username");

            if (!user) return Unauthorized();

            return Ok(new AuthorizationHelper().TokenGenerator());
        }
    }
}