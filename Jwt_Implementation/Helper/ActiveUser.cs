namespace Jwt_Implementation.Helper
{
    /// <summary>
    /// we used this class to keep tack of current requesting user all over the application. 
    /// </summary>
    public class ActiveUser
    {
        public int UserId { get; set; }
        public string UserName { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
    }
}
