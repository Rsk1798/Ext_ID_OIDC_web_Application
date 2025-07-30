using Ext_ID_OIDC_web_Application.Models;
using Microsoft.Graph;
using Microsoft.Kiota.Abstractions;
using Microsoft.Kiota.Abstractions.Authentication;

namespace Ext_ID_OIDC_web_Application.Services
{


    public interface IGraphApiService
    {
        Task<GraphServiceClient> GetGraphClientAsync();
        Task<string> GetAccessTokenAsync();
    }



    public class GraphApiService : IGraphApiService
    {



        private readonly IConfiguration _configuration;
        private readonly ILogger<GraphApiService> _logger;
        private readonly MultiAppConfig _multiAppConfig;
        private readonly ITokenAcquisition _tokenAcquisition;



        public GraphApiService(IConfiguration configuration, ILogger<GraphApiService> logger, ITokenAcquisition tokenAcquisition)
        {
            _configuration = configuration;
            _logger = logger;
            _tokenAcquisition = tokenAcquisition;
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
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error binding MultiAppConfig from configuration");
            }
        }


        public async Task<GraphServiceClient> GetGraphClientAsync()
        {
            try
            {
                var accessToken = await GetAccessTokenAsync();
                var authProvider = new GraphApiAuthProvider(accessToken);
                return new GraphServiceClient(authProvider);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating Graph client");
                throw;
            }
        }


        public async Task<string> GetAccessTokenAsync()
        {
            try
            {
                _logger.LogInformation("Getting access token for Graph API operations using Graph API SPN");

                // Use our custom token acquisition for application permissions
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
