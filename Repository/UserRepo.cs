using aznira5.Models;
using System.Data.SqlClient;
using System.Data;

namespace aznira5.Repository
{
    public class UserRepo: IUserRepo
    {
        private readonly string _ConnectionString;

        public UserRepo(string connectionString)
        {
            _ConnectionString = connectionString; 
        }
        public List<UserDetails> GetUserDetails()
        {
            List<UserDetails> userDetails = new List<UserDetails>();

            using (SqlConnection connection = new SqlConnection(_ConnectionString))//connection the aplication to DB
            {
                SqlCommand command = new SqlCommand("GetUserDetails", connection);// stored prosedure'name
                command.CommandType = CommandType.StoredProcedure;// atau query cmd

                connection.Open();
                SqlDataReader reader = command.ExecuteReader();

                while (reader.Read())
                {
                    UserDetails userDetail = new UserDetails();

                    userDetail.AppUserUniqueId = reader.IsDBNull(reader.GetOrdinal("APPUS_UNIQUEID")) ? Guid.Empty : (Guid)reader["APPUS_UNIQUEID"];
                    userDetail.UserId = reader["APPUS_USERID"]?.ToString();
                    userDetail.NRICPassport = reader["APPUS_NRICPASSPORT"]?.ToString();
                    userDetail.FirstName = reader["APPUS_FIRSTNAME"]?.ToString();
                    userDetail.LastName = reader["APPUS_LASTNAME"]?.ToString();
                    userDetail.DateOfBirth = reader.IsDBNull(reader.GetOrdinal("APPUS_DOB")) ? (DateTime?)null : reader.GetDateTime(reader.GetOrdinal("APPUS_DOB"));
                    userDetail.Gender = reader["GENDER"]?.ToString();
                    userDetail.GenderId = reader.IsDBNull(reader.GetOrdinal("APPUS_MAGEN_ID")) ? (short?)null : (short?)reader["APPUS_MAGEN_ID"];
                    userDetail.Email = reader["APPUS_EMAIL"]?.ToString();
                    userDetail.NationalityId = reader.IsDBNull(reader.GetOrdinal("APPUS_MANAT_ID")) ? (short?)null : (short?)reader["APPUS_MANAT_ID"];
                    userDetail.Nationality = reader["NATIONALITY"]?.ToString();
                    userDetail.PhoneNumber = reader["APPUS_PHONENUMBER"]?.ToString();
                    userDetail.Address1 = reader["APPUS_ADDRESS1"]?.ToString();
                    userDetail.Address2 = reader["APPUS_ADDRESS2"]?.ToString();
                    userDetail.TownName = reader["TOWNNAME"]?.ToString();
                    userDetail.DistrictName = reader["DISTRICTNAME"]?.ToString();
                    userDetail.StateName = reader["STATENAME"]?.ToString();
                    userDetail.ZipCode = reader["APPUS_ZIPCODE"]?.ToString();
                    userDetail.UserTypeId = reader.IsDBNull(reader.GetOrdinal("APPUS_MAUS_TYPEID")) ? (short?)null : (short?)reader["APPUS_MAUS_TYPEID"];
                    userDetail.UserType = reader["USERTYPE"]?.ToString();
                    userDetail.UserStatusId = reader.IsDBNull(reader.GetOrdinal("APPUS_MAUS_STATUSID")) ? (short?)null : (short?)reader["APPUS_MAUS_STATUSID"];
                    userDetail.UserStatus = reader["USERSTATUS"]?.ToString();
                    userDetail.ColorCode = reader["COLORCODE"]?.ToString();
                    userDetail.CreatedBy = reader["APPUS_CREATEDBY"]?.ToString();
                    userDetail.CreatedDate = reader.IsDBNull(reader.GetOrdinal("APPUS_CREATEDDATE")) ? (DateTime?)null : reader.GetDateTime(reader.GetOrdinal("APPUS_CREATEDDATE"));
                    userDetail.ModifiedBy = reader["APPUS_MODIFIEDBY"]?.ToString();
                    userDetail.ModifiedDate = reader.IsDBNull(reader.GetOrdinal("APPUS_MODIFIEDDATE")) ? (DateTime?)null : reader.GetDateTime(reader.GetOrdinal("APPUS_MODIFIEDDATE"));
                    userDetail.Remarks = reader["APPUS_REMARKS"]?.ToString();
                    userDetail.EmailVerification = reader.IsDBNull(reader.GetOrdinal("APPUS_EMAILVALIDATION")) ? (bool?)null : (bool?)reader["APPUS_EMAILVALIDATION"];
                    userDetail.ReferenceNo = reader["APPUS_REFERENCENO"]?.ToString();
                    userDetails.Add(userDetail);
                }


                reader.Close();
            }

            return userDetails;
        }

        public List<UserDetails> GetUserDetailByUserId(string userId)
        {

            List<UserDetails> userDetails = new List<UserDetails>();

            using (SqlConnection connection = new SqlConnection(_ConnectionString))
            {
                SqlCommand command = new SqlCommand("GetUserDetailsByuserId", connection);
                command.CommandType = CommandType.StoredProcedure;
                command.Parameters.AddWithValue("@userId", userId);

                connection.Open();
                SqlDataReader reader = command.ExecuteReader();

                while (reader.Read())
                {
                    UserDetails userDetail = new UserDetails();

                    userDetail.AppUserUniqueId = reader.IsDBNull(reader.GetOrdinal("APPUS_UNIQUEID")) ? Guid.Empty : (Guid)reader["APPUS_UNIQUEID"];
                    userDetail.UserId = reader["APPUS_USERID"]?.ToString();
                    userDetail.NRICPassport = reader["APPUS_NRICPASSPORT"]?.ToString();
                    userDetail.FirstName = reader["APPUS_FIRSTNAME"]?.ToString();
                    userDetail.LastName = reader["APPUS_LASTNAME"]?.ToString();
                    userDetail.DateOfBirth = reader.IsDBNull(reader.GetOrdinal("APPUS_DOB")) ? (DateTime?)null : reader.GetDateTime(reader.GetOrdinal("APPUS_DOB"));
                    userDetail.Gender = reader["GENDER"]?.ToString();
                    userDetail.GenderId = reader.IsDBNull(reader.GetOrdinal("APPUS_MAGEN_ID")) ? (short?)null : (short?)reader["APPUS_MAGEN_ID"];
                    userDetail.Email = reader["APPUS_EMAIL"]?.ToString();
                    userDetail.NationalityId = reader.IsDBNull(reader.GetOrdinal("APPUS_MANAT_ID")) ? (short?)null : (short?)reader["APPUS_MANAT_ID"];
                    userDetail.Nationality = reader["NATIONALITY"]?.ToString();
                    userDetail.PhoneNumber = reader["APPUS_PHONENUMBER"]?.ToString();
                    userDetail.Address1 = reader["APPUS_ADDRESS1"]?.ToString();
                    userDetail.Address2 = reader["APPUS_ADDRESS2"]?.ToString();
                    userDetail.TownName = reader["TOWNNAME"]?.ToString();
                    userDetail.DistrictName = reader["DISTRICTNAME"]?.ToString();
                    userDetail.StateName = reader["STATENAME"]?.ToString();
                    userDetail.ZipCode = reader["APPUS_ZIPCODE"]?.ToString();
                    userDetail.UserTypeId = reader.IsDBNull(reader.GetOrdinal("APPUS_MAUS_TYPEID")) ? (short?)null : (short?)reader["APPUS_MAUS_TYPEID"];
                    userDetail.UserType = reader["USERTYPE"]?.ToString();
                    userDetail.UserStatusId = reader.IsDBNull(reader.GetOrdinal("APPUS_MAUS_STATUSID")) ? (short?)null : (short?)reader["APPUS_MAUS_STATUSID"];
                    userDetail.UserStatus = reader["USERSTATUS"]?.ToString();
                    userDetail.ColorCode = reader["COLORCODE"]?.ToString();
                    userDetail.CreatedBy = reader["APPUS_CREATEDBY"]?.ToString();
                    userDetail.CreatedDate = reader.IsDBNull(reader.GetOrdinal("APPUS_CREATEDDATE")) ? (DateTime?)null : reader.GetDateTime(reader.GetOrdinal("APPUS_CREATEDDATE"));
                    userDetail.ModifiedBy = reader["APPUS_MODIFIEDBY"]?.ToString();
                    userDetail.ModifiedDate = reader.IsDBNull(reader.GetOrdinal("APPUS_MODIFIEDDATE")) ? (DateTime?)null : reader.GetDateTime(reader.GetOrdinal("APPUS_MODIFIEDDATE"));
                    userDetail.Remarks = reader["APPUS_REMARKS"]?.ToString();
                    userDetail.EmailVerification = reader.IsDBNull(reader.GetOrdinal("APPUS_EMAILVALIDATION")) ? (bool?)null : (bool?)reader["APPUS_EMAILVALIDATION"];
                    userDetail.ReferenceNo = reader["APPUS_REFERENCENO"]?.ToString();
                    userDetails.Add(userDetail);
                }


                reader.Close();
            }

            return userDetails;
        }

    }
}
