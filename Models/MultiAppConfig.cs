using Microsoft.Identity.Client;
using System.ComponentModel.DataAnnotations;

namespace Ext_ID_OIDC_web_Application.Models
{
    public class MultiAppConfig
    {

        public AppConfig App1 { get; set; } = new();
        public AppConfig App2 { get; set; } = new();
        public AppConfig App3 { get; set; } = new();
        public GraphApiAppConfig GraphApiApp { get; set; } = new();

    }

    public class AppConfig
    {
        [Required]
        public string ClientId { get; set; } = string.Empty;

        [Required]
        public string ClientSecret { get; set; } = string.Empty;

        [Required]
        public string CallbackPath { get; set; } = string.Empty;

        [Required]
        public string SignedOutCallbackPath { get; set; } = string.Empty;

        [Required]
        public string DisplayName { get; set; } = string.Empty;

        public string Description { get; set; } = string.Empty;
    }


    public class GraphApiAppConfig
    {
        [Required]
        public string ClientId { get; set; } = string.Empty;

        [Required]
        public string ClientSecret { get; set; } = string.Empty;

        [Required]
        public string TenantId { get; set; } = string.Empty;

        [Required]
        public string Instance { get; set; } = string.Empty;

        [Required]
        public string Domain { get; set; } = string.Empty;

        [Required]
        public string DisplayName { get; set; } = string.Empty;

        public string Description { get; set; } = string.Empty;

        public string Scopes { get; set; } = string.Empty;
    }



}
