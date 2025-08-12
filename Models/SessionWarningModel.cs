namespace Ext_ID_OIDC_web_Application.Models
{
    public class SessionWarningModel
    {
        public string CurrentAuthScheme { get; set; } = string.Empty;
        public string RequestedAuthScheme { get; set; } = string.Empty;
        public string UserName { get; set; } = string.Empty;
        public string WarningMessage { get; set; } = string.Empty;
        public string CurrentAppName { get; set; } = string.Empty;
        public string RequestedAppName { get; set; } = string.Empty;
        public string SignOutUrl { get; set; } = string.Empty;
        public string ContinueUrl { get; set; } = string.Empty;
    }
}

