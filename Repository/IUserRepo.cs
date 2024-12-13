using aznira5.Models;

namespace aznira5.Repository
{
    public interface IUserRepo

    {
        public List<UserDetails> GetUserDetails();
        public List<UserDetails> GetUserDetailByUserId(string userId);
    }
}
