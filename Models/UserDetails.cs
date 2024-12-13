namespace aznira5.Models
{
    public class UserDetails
    {
        public Guid AppUserUniqueId { get; set; }
        public string UserId { get; set; }
        public string NRICPassport { get; set; }
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public DateTime? DateOfBirth { get; set; }
        public short? GenderId { get; set; }
        public string? Gender { get; set; }
        public string? Email { get; set; }
        public short? NationalityId { get; set; }
        public string? Nationality { get; set; }
        public string? PhoneNumber { get; set; }
        public string? Address1 { get; set; }
        public string? Address2 { get; set; }
        public short? TownId { get; set; }
        public string? TownName { get; set; }
        public short? DistrictId { get; set; }
        public string? DistrictName { get; set; }
        public short? StateId { get; set; }
        public string? StateName { get; set; }
        public string? ZipCode { get; set; }
        public short? UserTypeId { get; set; }
        public string? UserType { get; set; }
        public short? UserStatusId { get; set; }
        public string? UserStatus { get; set; }
        public string? ColorCode { get; set; }
        public string? CreatedBy { get; set; }
        public DateTime? CreatedDate { get; set; }
        public string? ModifiedBy { get; set; }
        public DateTime? ModifiedDate { get; set; }
        public string? Remarks { get; set; }
        public bool? EmailVerification { get; set; }
        public int? ResubmitStatusCount { get; set; }
        public string? ReferenceNo { get; set; }
        public string? UserRoleIds { get; set; }
        public string? UserRoleDescription { get; set; }
    }
}
