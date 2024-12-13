using aznira5.Models;
using aznira5.Repository;

namespace aznira5.Services
{
    public class UserService: IUserService
    {
        private readonly IUserRepo _userRepo;

        public UserService(IUserRepo userRepo)//reference to repository
        {
            _userRepo = userRepo;
        }
        public List<UserDetails> GetUserDetails()
        { 
            return _userRepo.GetUserDetails();//calling frm service
        }

        public List<UserDetails> GetUserDetailByUserId(string userId)
        {
            return _userRepo.GetUserDetailByUserId(userId);
        }
    }

}
