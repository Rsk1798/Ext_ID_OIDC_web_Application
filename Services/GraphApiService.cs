﻿﻿﻿﻿﻿using Ext_ID_OIDC_web_Application.Models;
using Azure.Identity;
using Microsoft.Graph;
using Microsoft.Kiota.Abstractions;
using Microsoft.Kiota.Abstractions.Authentication;

namespace Ext_ID_OIDC_web_Application.Services
{


    public interface IGraphApiService
    {
        Task<GraphServiceClient> GetGraphClientAsync();
        Task<GraphServiceClient> GetDelegatedGraphClientAsync();
        Task<GraphServiceClient> GetApplicationGraphClientAsync();
        Task<string> GetAccessTokenAsync();
    }



    public class GraphApiService : IGraphApiService
    {



        private readonly IConfiguration _configuration;
        private readonly ILogger<GraphApiService> _logger;
        private readonly MultiAppConfig _multiAppConfig;
        private readonly ITokenAcquisition _tokenAcquisition;
        private readonly IHttpContextAccessor _httpContextAccessor;

        private readonly string? _tenantId;
        private readonly string? _clientId;
        private readonly string? _clientSecret;



        public GraphApiService(IConfiguration configuration, ILogger<GraphApiService> logger, ITokenAcquisition tokenAcquisition, IHttpContextAccessor httpContextAccessor)
        {
            _configuration = configuration;
            _logger = logger;
            _tokenAcquisition = tokenAcquisition;
            _httpContextAccessor = httpContextAccessor;
            _multiAppConfig = new MultiAppConfig();

            try
            {
                var section = _configuration.GetSection("MultiAppConfig");
                if (section.Exists())
                {
                    section.Bind(_multiAppConfig);
                }
                else
                {
                    _logger.LogWarning("MultiAppConfig section not found in configuration");
                }

                _tenantId = _configuration["MultiAppConfig:GraphApiApp:TenantId"];
                _clientId = _configuration["MultiAppConfig:GraphApiApp:ClientId"];
                _clientSecret = _configuration["MultiAppConfig:GraphApiApp:ClientSecret"];
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error binding MultiAppConfig from configuration");
            }
        }


        public async Task<GraphServiceClient> GetGraphClientAsync()
        {
            // Default to delegated client for /me and user context operations
            return await GetDelegatedGraphClientAsync();
        }

        public async Task<GraphServiceClient> GetDelegatedGraphClientAsync()
        {
            try
            {
                _logger.LogInformation("Creating delegated Graph client for user context operations");
                
                // Use delegated permissions with user token for /me requests
                var accessToken = await _tokenAcquisition.GetAccessTokenForUserAsync(new[] {
                    "User.Read",
                    "User.ReadWrite.All"
                });
                
                var authProvider = new GraphApiAuthProvider(accessToken);
                return new GraphServiceClient(authProvider);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating delegated Graph client");
                throw;
            }
        }

        public async Task<GraphServiceClient> GetApplicationGraphClientAsync()
        {
            try
            {
                _logger.LogInformation("Creating application Graph client for administrative operations");
                _logger.LogInformation("Using TenantId: {TenantId}, ClientId: {ClientId}", _tenantId, _clientId);
                
                // Use application permissions for administrative operations
                if (!string.IsNullOrWhiteSpace(_tenantId) && !string.IsNullOrWhiteSpace(_clientId) && !string.IsNullOrWhiteSpace(_clientSecret))
                {
                    var credential = new ClientSecretCredential(_tenantId, _clientId, _clientSecret);
                    var graphClient = new GraphServiceClient(credential, new[] { "https://graph.microsoft.com/.default" });
                    
                    // Test the connection and log token info
                    try
                    {
                        _logger.LogInformation("Testing Graph client connection with application permissions");
                        // Make a simple test call to validate permissions
                        var testRequest = graphClient.Users.GetAsync(requestConfiguration => {
                            requestConfiguration.QueryParameters.Top = 1;
                            requestConfiguration.QueryParameters.Select = new[] { "id", "displayName" };
                        });
                        
                        _logger.LogInformation("Successfully created and validated application Graph client");
                    }
                    catch (Exception testEx)
                    {
                        _logger.LogWarning(testEx, "Failed to validate Graph client connection: {Message}", testEx.Message);
                    }
                    
                    return graphClient;
                }

                // Fallback to legacy token acquisition if needed
                _logger.LogWarning("Missing configuration for ClientSecretCredential, falling back to token acquisition");
                var accessToken = await GetAccessTokenAsync();
                var authProvider = new GraphApiAuthProvider(accessToken);
                return new GraphServiceClient(authProvider);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating application Graph client: {Message}. TenantId: {TenantId}, ClientId: {ClientId}", 
                    ex.Message, _tenantId, _clientId);
                throw;
            }
        }


        public async Task<string> GetAccessTokenAsync()
        {
            try
            {
                _logger.LogInformation("Getting access token for Graph API operations using Graph API SPN");

                // If we have direct credentials, use ClientSecretCredential to request a token
                if (!string.IsNullOrWhiteSpace(_tenantId) && !string.IsNullOrWhiteSpace(_clientId) && !string.IsNullOrWhiteSpace(_clientSecret))
                {
                    var credential = new ClientSecretCredential(_tenantId, _clientId, _clientSecret);
                    var graphClient = new GraphServiceClient(credential, new[] { "https://graph.microsoft.com/.default" });
                    // Create a trivial request to force token acquisition and extract it via handler is complex; instead, keep legacy for callers that need raw token
                    // Prefer callers using GetGraphClientAsync.
                }

                // Fallback to custom acquisition abstraction
                return await _tokenAcquisition.GetAccessTokenForAppAsync("https://graph.microsoft.com/.default");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting access token for Graph API");
                throw;
            }
        }

    }


    public class GraphApiAuthProvider : IAuthenticationProvider
    {
        private readonly string _accessToken;

        public GraphApiAuthProvider(string accessToken)
        {
            _accessToken = accessToken;
        }

        public Task AuthenticateRequestAsync(RequestInformation request, Dictionary<string, object>? additionalAuthenticationContext = null, CancellationToken cancellationToken = default)
        {
            request.Headers.Add("Authorization", $"Bearer {_accessToken}");
            request.Headers.Add("Content-Type", "application/json");
            return Task.CompletedTask;
        }
    }

}
