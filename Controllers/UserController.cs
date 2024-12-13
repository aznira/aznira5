using aznira5.Models;
using aznira5.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;

namespace aznira5.Controllers
{
    [Route("api/[controller]/[action]")]
    [ApiController]
    //[Authorize]
    public class UserController : ControllerBase
    {
        private readonly IUserService _userService;

        public UserController(IUserService userService)
        { 
            _userService = userService; 
        }
        [HttpGet]
        public ActionResult <List<UserDetails>>GetUserDetails()
        {
            var result=_userService.GetUserDetails();
            return Ok(result);
        }
        [HttpGet]
        public ActionResult<List<UserDetails>> GetUserDetailByUserId([FromQuery][Required]string userId)
        {
            var result = _userService.GetUserDetailByUserId(userId);
            return Ok(result);
        }
    }
}
