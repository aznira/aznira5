using aznira5.Models;

namespace aznira5.Services
{
    public interface IUserService
    {
        public List<UserDetails> GetUserDetails();
        public List<UserDetails> GetUserDetailByUserId(string userId);
    }
}
