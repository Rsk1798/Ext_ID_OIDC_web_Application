namespace Ext_ID_OIDC_web_Application.Models
{
    public class MultiAppAuthViewModel
    {

        public string? AuthenticatedUser { get; set; }
        public string? AuthenticationScheme { get; set; }
        public string? ApplicationName { get; set; }
        public string? ClientId { get; set; }
        public bool IsAuthenticated { get; set; }
        public List<UserClaim> Claims { get; set; } = new();
        public GraphApiInfo? GraphApiInfo { get; set; }

    }



    public class GraphApiInfo
    {
        public string? DisplayName { get; set; }
        public string? UserPrincipalName { get; set; }
        public string? Id { get; set; }
        public string? Mail { get; set; }
        public string? JobTitle { get; set; }
        public string? Department { get; set; }
        public bool IsConnected { get; set; }
        public string? ErrorMessage { get; set; }
    }



    public class UserClaim
    {
        public string Type { get; set; }
        public string Value { get; set; }
    }



    public class ConfigurationInfo
    {
        public string Authority { get; set; }
        public string Domain { get; set; }
        public string ClientId { get; set; }
        public string PolicyId { get; set; }
        public string CallbackPath { get; set; }
        public string SignedOutCallbackPath { get; set; }
    }



    public class UserInfo
    {
        public string DisplayName { get; set; }
        public string UserPrincipalName { get; set; }
        public string Id { get; set; }
    }



    public class DiagnosticViewModel
    {
        public bool IsAuthenticated { get; set; }
        public List<UserClaim> UserClaims { get; set; } = new();
        public ConfigurationInfo Configuration { get; set; } = new();
        public string GraphApiStatus { get; set; }
        public UserInfo UserInfo { get; set; }
    }

}
