using Ext_ID_OIDC_web_Application.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Graph;
using Microsoft.Graph.Models;
using Microsoft.Kiota.Abstractions;
using Microsoft.Kiota.Abstractions.Authentication;
using OIDCDemoApp.Models;
using Ext_ID_OIDC_web_Application.Services;
using System.Security.Claims;
using System.Diagnostics;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Linq;
using System.Net;
using System.Text.Json.Serialization;
using System.IdentityModel.Tokens.Jwt;

namespace Ext_ID_OIDC_web_Application.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly IConfiguration _configuration;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly ITokenAcquisition _tokenAcquisition;
        private readonly IGraphApiService _graphApiService;
        private static readonly Dictionary<string, (int Count, DateTime LastAttempt)> _loginAttempts = new();
        private const int MaxLoginAttempts = 5;
        private const int LoginAttemptWindowMinutes = 15;



        public HomeController(
        ILogger<HomeController> logger,
        IConfiguration configuration,
        IHttpClientFactory httpClientFactory,
        ITokenAcquisition tokenAcquisition,
        IGraphApiService graphApiService)
        {
            _logger = logger;
            _configuration = configuration;
            _httpClientFactory = httpClientFactory;
            _tokenAcquisition = tokenAcquisition;
            _graphApiService = graphApiService;
        }

        private string? GetCurrentUserObjectId()
        {
            return User.FindFirstValue("oid")
                ?? User.FindFirstValue("http://schemas.microsoft.com/identity/claims/objectidentifier")
                ?? User.FindFirstValue(ClaimTypes.NameIdentifier);
        }

        /// <summary>
        /// Helper method to safely extract string values from JsonElement
        /// </summary>
        /// <param name="element">The JsonElement to extract from</param>
        /// <param name="propertyName">The property name to extract</param>
        /// <returns>String value or null if property doesn't exist or is null</returns>
        private string? GetJsonStringValue(JsonElement element, string propertyName)
        {
            try
            {
                if (element.TryGetProperty(propertyName, out var property))
                {
                    return property.ValueKind == JsonValueKind.String ? property.GetString() : null;
                }
                return null;
            }
            catch
            {
                return null;
            }
        }



        private void AddSecurityHeaders()
        {
            // Add security headers
            Response.Headers.Add("X-Content-Type-Options", "nosniff");
            Response.Headers.Add("X-Frame-Options", "DENY");
            Response.Headers.Add("X-XSS-Protection", "1; mode=block");
            Response.Headers.Add("Referrer-Policy", "strict-origin-when-cross-origin");
            Response.Headers.Add("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';");
            Response.Headers.Add("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
            Response.Headers.Add("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
            Response.Headers.Add("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
            Response.Headers.Add("Pragma", "no-cache");
            Response.Headers.Add("Expires", "0");
        }



        private bool IsRateLimited(string key)
        {
            if (_loginAttempts.TryGetValue(key, out var attempt))
            {
                if (DateTime.UtcNow - attempt.LastAttempt < TimeSpan.FromMinutes(LoginAttemptWindowMinutes))
                {
                    if (attempt.Count >= MaxLoginAttempts)
                    {
                        _logger.LogWarning("Rate limit exceeded for key: {Key}", key);
                        return true;
                    }
                }
                else
                {
                    _loginAttempts.Remove(key);
                }
            }
            return false;
        }

        private void IncrementAttemptCount(string key)
        {
            if (_loginAttempts.TryGetValue(key, out var attempt))
            {
                if (DateTime.UtcNow - attempt.LastAttempt < TimeSpan.FromMinutes(LoginAttemptWindowMinutes))
                {
                    _loginAttempts[key] = (attempt.Count + 1, DateTime.UtcNow);
                }
                else
                {
                    _loginAttempts[key] = (1, DateTime.UtcNow);
                }
            }
            else
            {
                _loginAttempts[key] = (1, DateTime.UtcNow);
            }
        }



        private void LogSecurityEvent(string eventType, string details, string userId = null)
        {
            var logEntry = new
            {
                Timestamp = DateTime.UtcNow,
                EventType = eventType,
                Details = details,
                UserId = userId,
                IPAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
                UserAgent = HttpContext.Request.Headers["User-Agent"].ToString()
            };

            _logger.LogInformation("Security Event: {@LogEntry}", logEntry);
        }




        public IActionResult Index()
        {
            AddSecurityHeaders();
            return View();
        }



        // Helper to map scheme to friendly name
        private string GetAppDisplayName(string authScheme)
        {
            return authScheme switch
            {
                "App1Scheme" => "Application 1 (Volvo Selected)",
                "App2Scheme" => "Application 2 (Volvo Group - Default)",
                "App3Scheme" => "Application 3 (Mack Truck)",
                _ => "Unknown Application"
            };
        }

        // Session warning page
        [Authorize]
        public IActionResult SessionWarning(string requestedScheme, string returnUrl = null)
        {
            var currentScheme = User.Claims.FirstOrDefault(c => c.Type == "auth_scheme")?.Value;
            if (string.IsNullOrEmpty(currentScheme) || string.IsNullOrEmpty(requestedScheme))
            {
                return RedirectToAction("Index");
            }

            var model = new SessionWarningModel
            {
                CurrentAuthScheme = currentScheme,
                RequestedAuthScheme = requestedScheme,
                UserName = User.Identity?.Name ?? "",
                CurrentAppName = GetAppDisplayName(currentScheme),
                RequestedAppName = GetAppDisplayName(requestedScheme),
                WarningMessage = $"You are currently signed in to {GetAppDisplayName(currentScheme)}. To switch to {GetAppDisplayName(requestedScheme)}, please sign out first.",
                SignOutUrl = Url.Action("SignOut", "Home") ?? "/Home/SignOut",
                ContinueUrl = returnUrl ?? Url.Action("Index", "Home") ?? "/"
            };

            return View(model);
        }

        // Sign-in actions with single-session enforcement
        public IActionResult SignInApp1()
        {
            if (User.Identity?.IsAuthenticated == true)
            {
                var currentScheme = User.Claims.FirstOrDefault(c => c.Type == "auth_scheme")?.Value;
                if (!string.IsNullOrEmpty(currentScheme) && currentScheme != "App1Scheme")
                {
                    LogSecurityEvent("SessionConflict", $"User attempted to sign in to App1 while authenticated via {currentScheme}");
                    return RedirectToAction("SessionWarning", new { requestedScheme = "App1Scheme" });
                }
            }

            LogSecurityEvent("SignInAttempt", "User attempting to sign in with App1");
            return Challenge(new AuthenticationProperties
            {
                RedirectUri = Url.Action("Index", "Home"),
                Items = { { "scheme", "App1Scheme" } }
            }, "App1Scheme");
        }



        public IActionResult SignInApp2()
        {
            if (User.Identity?.IsAuthenticated == true)
            {
                var currentScheme = User.Claims.FirstOrDefault(c => c.Type == "auth_scheme")?.Value;
                if (!string.IsNullOrEmpty(currentScheme) && currentScheme != "App2Scheme")
                {
                    LogSecurityEvent("SessionConflict", $"User attempted to sign in to App2 while authenticated via {currentScheme}");
                    return RedirectToAction("SessionWarning", new { requestedScheme = "App2Scheme" });
                }
            }

            LogSecurityEvent("SignInAttempt", "User attempting to sign in with App2");
            return Challenge(new AuthenticationProperties
            {
                RedirectUri = Url.Action("Index", "Home"),
                Items = { { "scheme", "App2Scheme" } }
            }, "App2Scheme");
        }



        public IActionResult SignInApp3()
        {
            if (User.Identity?.IsAuthenticated == true)
            {
                var currentScheme = User.Claims.FirstOrDefault(c => c.Type == "auth_scheme")?.Value;
                if (!string.IsNullOrEmpty(currentScheme) && currentScheme != "App3Scheme")
                {
                    LogSecurityEvent("SessionConflict", $"User attempted to sign in to App3 while authenticated via {currentScheme}");
                    return RedirectToAction("SessionWarning", new { requestedScheme = "App3Scheme" });
                }
            }

            LogSecurityEvent("SignInAttempt", "User attempting to sign in with App3");
            return Challenge(new AuthenticationProperties
            {
                RedirectUri = Url.Action("Index", "Home"),
                Items = { { "scheme", "App3Scheme" } }
            }, "App3Scheme");
        }



        [Authorize]
        public async Task<IActionResult> Profile()
        {
            AddSecurityHeaders();
            try
            {
                // Log all available claims for debugging
                _logger.LogInformation("Available claims for user:");
                foreach (var claim in User.Claims)
                {
                    _logger.LogInformation("Claim Type: {Type}, Value: {Value}", claim.Type, claim.Value);
                }

                // Try multiple possible email claim types
                var userEmail = User.Claims.FirstOrDefault(c => 
                    c.Type == "email" || 
                    c.Type == "preferred_username" || 
                    c.Type == "emails" ||
                    c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress" ||
                    c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn" ||
                    c.Type == "upn" ||
                    c.Type == ClaimTypes.Email ||
                    c.Type == ClaimTypes.Upn
                )?.Value;

                _logger.LogInformation("Initial userEmail from claims: {UserEmail}", userEmail);

                // Check if this is a GUID-based email (common with App3)
                bool isGuidEmail = false;
                if (!string.IsNullOrEmpty(userEmail) && userEmail.Contains("@"))
                {
                    var emailPart = userEmail.Split('@')[0];
                    isGuidEmail = Guid.TryParse(emailPart, out _);
                    _logger.LogInformation("Email appears to be GUID-based: {IsGuidEmail}", isGuidEmail);
                }

                // If email not found in claims OR it's a GUID-based email, try to get real email from Microsoft Graph API
                if (string.IsNullOrEmpty(userEmail) || isGuidEmail)
                {
                    _logger.LogWarning("Email not found in claims or is GUID-based, attempting to get real email from Microsoft Graph API");
                    try
                    {
                        var graphClient = await _graphApiService.GetDelegatedGraphClientAsync();
                        var user = await graphClient.Me.GetAsync();
                        
                        if (user != null)
                        {
                            var realEmail = user.Mail ?? user.UserPrincipalName;
                            if (!string.IsNullOrEmpty(realEmail))
                            {
                                _logger.LogInformation("Successfully retrieved real email from Graph API: {RealEmail} (was: {OriginalEmail})", realEmail, userEmail);
                                userEmail = realEmail;
                            }
                            else
                            {
                                _logger.LogWarning("Graph API returned user but no email found. User.Mail: {Mail}, User.UserPrincipalName: {UPN}", user.Mail, user.UserPrincipalName);
                            }
                        }
                        else
                        {
                            _logger.LogWarning("Graph API returned null user");
                        }
                    }
                    catch (Exception graphEx)
                    {
                        _logger.LogError(graphEx, "Failed to get email from Graph API");
                    }
                }

                if (string.IsNullOrEmpty(userEmail))
                {
                    _logger.LogError("User email not found in claims or Graph API");
                    return RedirectToAction("ProfileError", new { message = "User email not found in authentication claims or Graph API" });
                }

                _logger.LogInformation("Using email for API call: {Email}", userEmail);

                // Get access token for API authentication
                string accessToken = null;
                try
                {
                    // Try to get access token from the current authentication context
                    accessToken = await HttpContext.GetTokenAsync("access_token");
                    if (string.IsNullOrEmpty(accessToken))
                    {
                        // Try different authentication schemes
                        var authScheme = User.Claims.FirstOrDefault(c => c.Type == "auth_scheme")?.Value;
                        if (!string.IsNullOrEmpty(authScheme))
                        {
                            accessToken = await HttpContext.GetTokenAsync(authScheme, "access_token");
                        }
                    }
                    
                    if (!string.IsNullOrEmpty(accessToken))
                    {
                        _logger.LogInformation("Access token retrieved successfully for external API call");
                    }
                    else
                    {
                        _logger.LogWarning("No access token found - proceeding without authentication header");
                    }
                }
                catch (Exception tokenEx)
                {
                    _logger.LogWarning(tokenEx, "Failed to retrieve access token - proceeding without authentication header");
                }

                // Call external REST API
                var httpClient = _httpClientFactory.CreateClient();
                
                // Add authentication header if access token is available
                if (!string.IsNullOrEmpty(accessToken))
                {
                    httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
                }
                
                var baseUrl = _configuration["MultiAppConfig:ExternalApi:BaseUrl"];
                var endpoint = _configuration["MultiAppConfig:ExternalApi:GetUserByEmailEndpoint"];
                var apiUrl = $"{baseUrl}{endpoint}?email={Uri.EscapeDataString(userEmail)}";
                
                _logger.LogInformation("Calling external API: {ApiUrl} with authentication: {HasAuth}", apiUrl, !string.IsNullOrEmpty(accessToken));
                
                var response = await httpClient.GetAsync(apiUrl);
                
                if (!response.IsSuccessStatusCode)
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    _logger.LogError("External API returned error status: {StatusCode}, Email: {Email}, Response: {ErrorContent}", 
                        response.StatusCode, userEmail, errorContent);
                    
                    var errorMessage = response.StatusCode switch
                    {
                        HttpStatusCode.NotFound => $"User not found in external API. Email used: '{userEmail}'. Please ensure this user exists in the external system. You can also check /Home/DebugProfileApi for detailed debugging information.",
                        HttpStatusCode.Unauthorized => "Authentication failed. Please check if the access token is valid.",
                        HttpStatusCode.Forbidden => "Access denied. Please check API permissions.",
                        _ => $"External API error: {response.StatusCode} - {errorContent}"
                    };
                    
                    return RedirectToAction("ProfileError", new { message = errorMessage });
                }

                var jsonResponse = await response.Content.ReadAsStringAsync();
                _logger.LogInformation("External API response: {Response}", jsonResponse);
                
                // Parse the JSON response
                using var jsonDocument = JsonDocument.Parse(jsonResponse);
                var root = jsonDocument.RootElement;

                // Create user profile from external API data
                var userProfile = new UserProfile
                {
                    Name = GetJsonStringValue(root, "displayName") ?? GetJsonStringValue(root, "name"),
                    Email = GetJsonStringValue(root, "mail") ?? GetJsonStringValue(root, "userPrincipalName") ?? userEmail,
                    ObjectId = GetJsonStringValue(root, "id") ?? GetJsonStringValue(root, "objectId"),
                    GivenName = GetJsonStringValue(root, "givenName"),
                    Surname = GetJsonStringValue(root, "surname"),
                    StreetAddress = GetJsonStringValue(root, "streetAddress"),
                    City = GetJsonStringValue(root, "city"),
                    StateProvince = GetJsonStringValue(root, "state") ?? GetJsonStringValue(root, "stateProvince"),
                    CountryOrRegion = GetJsonStringValue(root, "country") ?? GetJsonStringValue(root, "countryOrRegion")
                };

                // Get updated fields from TempData if available
                if (TempData["UpdatedFields"] != null)
                {
                    var updatedFields = System.Text.Json.JsonSerializer.Deserialize<List<string>>(TempData["UpdatedFields"].ToString());
                    userProfile.UpdatedFields = updatedFields;
                }

                return View(userProfile);
            }
            catch (HttpRequestException ex)
            {
                _logger.LogError(ex, "HTTP request exception when calling external API");
                return RedirectToAction("ProfileError", new { message = $"Network error: {ex.Message}" });
            }
            catch (JsonException ex)
            {
                _logger.LogError(ex, "JSON parsing exception when processing external API response");
                return RedirectToAction("ProfileError", new { message = $"Invalid response format: {ex.Message}" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error accessing external API");
                return RedirectToAction("ProfileError", new { message = $"Error accessing external API: {ex.Message}" });
            }
        }



        [Authorize]
        public async Task<IActionResult> TestUpdateApi()
        {
            try
            {
                // Get user's email from claims
                var userEmail = User.Claims.FirstOrDefault(c => 
                    c.Type == "email" || 
                    c.Type == "preferred_username" || 
                    c.Type == "emails" ||
                    c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress" ||
                    c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn" ||
                    c.Type == "upn" ||
                    c.Type == ClaimTypes.Email ||
                    c.Type == ClaimTypes.Upn
                )?.Value;

                if (string.IsNullOrEmpty(userEmail))
                {
                    return Json(new { success = false, error = "User email not found in claims" });
                }

                // Get access token
                string accessToken = null;
                try
                {
                    accessToken = await HttpContext.GetTokenAsync("access_token");
                    if (string.IsNullOrEmpty(accessToken))
                    {
                        var authScheme = User.Claims.FirstOrDefault(c => c.Type == "auth_scheme")?.Value;
                        if (!string.IsNullOrEmpty(authScheme))
                        {
                            accessToken = await HttpContext.GetTokenAsync(authScheme, "access_token");
                        }
                    }
                }
                catch (Exception tokenEx)
                {
                    return Json(new { success = false, error = $"Token error: {tokenEx.Message}" });
                }

                // Create test update payload
                var testPayload = new Dictionary<string, object>
                {
                    ["displayName"] = "Test Update " + DateTime.Now.ToString("HH:mm:ss"),
                    ["givenName"] = "TestGiven",
                    ["surname"] = "TestSurname"
                };

                var httpClient = _httpClientFactory.CreateClient();
                
                // Add authentication header if access token is available
                if (!string.IsNullOrEmpty(accessToken))
                {
                    httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
                }
                
                var baseUrl = _configuration["MultiAppConfig:ExternalApi:BaseUrl"];
                var endpoint = _configuration["MultiAppConfig:ExternalApi:UpdateUserByEmailEndpoint"];
                var apiUrl = $"{baseUrl}{endpoint}?email={Uri.EscapeDataString(userEmail)}";
                
                var jsonContent = System.Text.Json.JsonSerializer.Serialize(testPayload);
                var content = new StringContent(
                    jsonContent,
                    System.Text.Encoding.UTF8,
                    "application/json"
                );

                // Make PATCH request
                var request = new HttpRequestMessage(HttpMethod.Patch, apiUrl)
                {
                    Content = content
                };
                var response = await httpClient.SendAsync(request);
                var responseContent = await response.Content.ReadAsStringAsync();
                
                var result = new
                {
                    success = response.IsSuccessStatusCode,
                    statusCode = (int)response.StatusCode,
                    userEmail = userEmail,
                    apiUrl = apiUrl,
                    hasAccessToken = !string.IsNullOrEmpty(accessToken),
                    requestPayload = testPayload,
                    responseHeaders = response.Headers.ToDictionary(h => h.Key, h => string.Join(", ", h.Value)),
                    responseBody = responseContent
                };

                return Json(result);
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        [Authorize]
        public async Task<IActionResult> TestExternalApi()
        {
            try
            {
                // Try multiple possible email claim types
                var userEmail = User.Claims.FirstOrDefault(c => 
                    c.Type == "email" || 
                    c.Type == "preferred_username" || 
                    c.Type == "emails" ||
                    c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress" ||
                    c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn" ||
                    c.Type == "upn" ||
                    c.Type == ClaimTypes.Email ||
                    c.Type == ClaimTypes.Upn
                )?.Value;

                // If email not found in claims, try to get it from Microsoft Graph API
                if (string.IsNullOrEmpty(userEmail))
                {
                    try
                    {
                        var graphClient = await _graphApiService.GetDelegatedGraphClientAsync();
                        var user = await graphClient.Me.GetAsync();
                        userEmail = user.Mail ?? user.UserPrincipalName;
                    }
                    catch (Exception graphEx)
                    {
                        return Json(new { success = false, error = $"Email not found in claims and Graph API failed: {graphEx.Message}" });
                    }
                }

                if (string.IsNullOrEmpty(userEmail))
                {
                    return Json(new { 
                        success = false, 
                        error = "User email not found in claims or Graph API",
                        availableClaims = User.Claims.Select(c => new { type = c.Type, value = c.Value }).ToList()
                    });
                }

                // Get access token for API authentication
                string accessToken = null;
                try
                {
                    // Try to get access token from the current authentication context
                    accessToken = await HttpContext.GetTokenAsync("access_token");
                    if (string.IsNullOrEmpty(accessToken))
                    {
                        // Try different authentication schemes
                        var authScheme = User.Claims.FirstOrDefault(c => c.Type == "auth_scheme")?.Value;
                        if (!string.IsNullOrEmpty(authScheme))
                        {
                            accessToken = await HttpContext.GetTokenAsync(authScheme, "access_token");
                        }
                    }
                }
                catch (Exception tokenEx)
                {
                    // Continue without token for testing
                }

                // Call external REST API
                var httpClient = _httpClientFactory.CreateClient();
                
                // Add authentication header if access token is available
                if (!string.IsNullOrEmpty(accessToken))
                {
                    httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
                }
                var baseUrl = _configuration["MultiAppConfig:ExternalApi:BaseUrl"];
                var endpoint = _configuration["MultiAppConfig:ExternalApi:GetUserByEmailEndpoint"];
                var apiUrl = $"{baseUrl}{endpoint}?email={Uri.EscapeDataString(userEmail)}";
                
                _logger.LogInformation("Testing external API: {ApiUrl}", apiUrl);
                
                var response = await httpClient.GetAsync(apiUrl);
                var jsonResponse = await response.Content.ReadAsStringAsync();
                
                var result = new
                {
                    success = response.IsSuccessStatusCode,
                    statusCode = (int)response.StatusCode,
                    userEmail = userEmail,
                    apiUrl = apiUrl,
                    hasAccessToken = !string.IsNullOrEmpty(accessToken),
                    accessTokenPreview = !string.IsNullOrEmpty(accessToken) ? accessToken.Substring(0, Math.Min(20, accessToken.Length)) + "..." : null,
                    authScheme = User.Claims.FirstOrDefault(c => c.Type == "auth_scheme")?.Value,
                    responseHeaders = response.Headers.ToDictionary(h => h.Key, h => string.Join(", ", h.Value)),
                    responseBody = jsonResponse
                };

                return Json(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error testing external API");
                return Json(new { success = false, error = ex.Message });
            }
        }


        public async Task<IActionResult> CheckOpenIdConfig()
        {
            try
            {
                var httpClient = _httpClientFactory.CreateClient();
                var authority = _configuration["AzureAd:Instance"];
                var domain = _configuration["AzureAd:Domain"];

                // Try different OpenID configuration URLs
                var configUrls = new[]
                {
                $"{authority}/{domain}/.well-known/openid-configuration",
                $"{authority}/{domain}/v2.0/.well-known/openid-configuration"
            };

                var results = new List<object>();

                foreach (var url in configUrls)
                {
                    try
                    {
                        var response = await httpClient.GetAsync(url);
                        results.Add(new
                        {
                            Url = url,
                            StatusCode = response.StatusCode,
                            Content = await response.Content.ReadAsStringAsync()
                        });
                    }
                    catch (Exception ex)
                    {
                        results.Add(new
                        {
                            Url = url,
                            Error = ex.Message
                        });
                    }
                }

                return View("OpenIdConfig", results);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking OpenID configuration");
                return Error($"Error checking OpenID configuration: {ex.Message}");
            }
        }


        public async Task<IActionResult> Diagnostic()
        {
            try
            {
                var diagnosticInfo = new DiagnosticViewModel
                {
                    IsAuthenticated = User.Identity?.IsAuthenticated ?? false,
                    UserClaims = User.Claims.Select(c => new UserClaim { Type = c.Type, Value = c.Value }).ToList(),
                    Configuration = new ConfigurationInfo
                    {
                        Authority = _configuration["AzureAd:Instance"],
                        Domain = _configuration["AzureAd:Domain"],
                        ClientId = _configuration["AzureAd:ClientId"],
                        CallbackPath = _configuration["AzureAd:CallbackPath"],
                        SignedOutCallbackPath = _configuration["AzureAd:SignedOutCallbackPath"]
                    },
                    GraphApiStatus = "Not authenticated"
                };

                if (User.Identity?.IsAuthenticated == true)
                {
                    try
                    {
                        // Use delegated GraphApiService for /me requests
                        var graphClient = await _graphApiService.GetDelegatedGraphClientAsync();
                        
                        // Test Graph API connection
                        var user = await graphClient.Me.GetAsync();
                        diagnosticInfo.GraphApiStatus = "Connected successfully";
                        diagnosticInfo.UserInfo = new UserInfo
                        {
                            DisplayName = user.DisplayName,
                            UserPrincipalName = user.UserPrincipalName,
                            Id = user.Id
                        };
                    }
                    catch (Exception ex)
                    {
                        diagnosticInfo.GraphApiStatus = $"Error: {ex.Message}";
                    }
                }

                return View(diagnosticInfo);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in diagnostic endpoint");
                return Error($"Error in diagnostic endpoint: {ex.Message}");
            }
        }




        public IActionResult Privacy()
        {
            return View();
        }



        [Authorize]
        public async Task<IActionResult> SignOut()
        {
            try
            {
                // Use delegated permissions for /me requests
                var delegatedGraphClient = await _graphApiService.GetDelegatedGraphClientAsync();
                
                // Get the current user's account
                var user = await delegatedGraphClient.Me.GetAsync();
                if (user != null)
                {
                    _logger.LogInformation("User {DisplayName} signing out", user.DisplayName);

                    try
                    {
                        // Use application permissions for revoke sessions operation
                        var appGraphClient = await _graphApiService.GetApplicationGraphClientAsync();
                        await appGraphClient.Users[user.Id].RevokeSignInSessions.PostAsync();
                        _logger.LogInformation("Successfully revoked sign-in sessions for user {DisplayName}", user.DisplayName);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to revoke Graph API sessions for user {DisplayName}", user.DisplayName);
                    }
                }

                // Clear all cookies with specific options
                var cookieOptions = new CookieOptions
                {
                    Path = "/",
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Lax,
                    Expires = DateTime.UtcNow.AddYears(-1) // Expire in the past
                };

                // Clear all cookies including authentication cookies
                foreach (var cookie in Request.Cookies.Keys)
                {
                    Response.Cookies.Delete(cookie, cookieOptions);
                }

                // Clear specific authentication cookies
                var authCookies = new[] {
                ".AspNetCore.Cookies",
                ".AspNetCore.OpenIdConnect.Nonce",
                ".AspNetCore.OpenIdConnect.Correlation",
                "OIDCDemoApp.Session",
                "msal.client.info",
                "msal.error",
                "msal.error.description",
                "msal.session.state",
                "msal.nonce.idtoken"
            };

                foreach (var cookie in authCookies)
                {
                    Response.Cookies.Delete(cookie, cookieOptions);
                }

                // Clear the session
                HttpContext.Session.Clear();
                await HttpContext.Session.LoadAsync();

                // Clear browser cache by setting cache control headers
                Response.Headers["Cache-Control"] = "no-cache, no-store, must-revalidate, private, max-age=0";
                Response.Headers["Pragma"] = "no-cache";
                Response.Headers["Expires"] = "-1";

                // Sign out from OpenID Connect with specific options
                var authProperties = new AuthenticationProperties
                {
                    RedirectUri = Url.Action("Index", "Home"),
                    AllowRefresh = false,
                    IsPersistent = false
                };

                // Sign out from all authentication schemes
                await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme, authProperties);
                await HttpContext.SignOutAsync("App1Scheme", authProperties);
                await HttpContext.SignOutAsync("App2Scheme", authProperties);
                await HttpContext.SignOutAsync("App3Scheme", authProperties);

                // Redirect to home page with cache-busting parameters
                return RedirectToAction("Index", "Home", new { t = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during sign-out");
                // Even if there's an error, try to sign out locally
                try
                {
                    await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                    await HttpContext.SignOutAsync("App1Scheme");
                    await HttpContext.SignOutAsync("App2Scheme");
                    await HttpContext.SignOutAsync("App3Scheme");
                }
                catch (Exception signOutEx)
                {
                    _logger.LogWarning(signOutEx, "Error during fallback sign-out");
                }
                HttpContext.Session.Clear();
                return RedirectToAction("Index", "Home");
            }
        }



        [Authorize]
        public async Task<IActionResult> EditProfile()
        {
            try
            {
                // Get user's email from claims with multiple fallback options
                var userEmail = User.Claims.FirstOrDefault(c => 
                    c.Type == "email" || 
                    c.Type == "preferred_username" || 
                    c.Type == "emails" ||
                    c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress" ||
                    c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn" ||
                    c.Type == "upn" ||
                    c.Type == ClaimTypes.Email ||
                    c.Type == ClaimTypes.Upn
                )?.Value;

                _logger.LogInformation("Initial userEmail from claims for edit: {UserEmail}", userEmail);

                // Check if this is a GUID-based email (common with App3)
                bool isGuidEmail = false;
                if (!string.IsNullOrEmpty(userEmail) && userEmail.Contains("@"))
                {
                    var emailPart = userEmail.Split('@')[0];
                    isGuidEmail = Guid.TryParse(emailPart, out _);
                    _logger.LogInformation("Email appears to be GUID-based for edit: {IsGuidEmail}", isGuidEmail);
                }

                // If email not found in claims OR it's a GUID-based email, try to get real email from Microsoft Graph API
                if (string.IsNullOrEmpty(userEmail) || isGuidEmail)
                {
                    _logger.LogWarning("Email not found in claims or is GUID-based for edit, attempting to get real email from Microsoft Graph API");
                    try
                    {
                        var graphClient = await _graphApiService.GetDelegatedGraphClientAsync();
                        var user = await graphClient.Me.GetAsync();
                        
                        if (user != null)
                        {
                            var realEmail = user.Mail ?? user.UserPrincipalName;
                            if (!string.IsNullOrEmpty(realEmail))
                            {
                                _logger.LogInformation("Successfully retrieved real email from Graph API for edit: {RealEmail} (was: {OriginalEmail})", realEmail, userEmail);
                                userEmail = realEmail;
                            }
                            else
                            {
                                _logger.LogWarning("Graph API returned user but no email found for edit. User.Mail: {Mail}, User.UserPrincipalName: {UPN}", user.Mail, user.UserPrincipalName);
                            }
                        }
                        else
                        {
                            _logger.LogWarning("Graph API returned null user for edit");
                        }
                    }
                    catch (Exception graphEx)
                    {
                        _logger.LogError(graphEx, "Failed to get email from Graph API for edit");
                    }
                }

                if (string.IsNullOrEmpty(userEmail))
                {
                    _logger.LogError("User email not found in claims or Graph API");
                    return Error("User email not found in authentication claims or Graph API");
                }

                // Get access token for API authentication
                string accessToken = null;
                try
                {
                    accessToken = await HttpContext.GetTokenAsync("access_token");
                    if (string.IsNullOrEmpty(accessToken))
                    {
                        var authScheme = User.Claims.FirstOrDefault(c => c.Type == "auth_scheme")?.Value;
                        if (!string.IsNullOrEmpty(authScheme))
                        {
                            accessToken = await HttpContext.GetTokenAsync(authScheme, "access_token");
                        }
                    }
                }
                catch (Exception tokenEx)
                {
                    _logger.LogWarning(tokenEx, "Failed to retrieve access token");
                }

                // Call external REST API to get user profile
                var httpClient = _httpClientFactory.CreateClient();
                
                // Add authentication header if access token is available
                if (!string.IsNullOrEmpty(accessToken))
                {
                    httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
                }
                
                var baseUrl = _configuration["MultiAppConfig:ExternalApi:BaseUrl"];
                var endpoint = _configuration["MultiAppConfig:ExternalApi:GetUserByEmailEndpoint"];
                var apiUrl = $"{baseUrl}{endpoint}?email={Uri.EscapeDataString(userEmail)}";
                
                _logger.LogInformation("Calling external API for edit profile: {ApiUrl}", apiUrl);
                
                var response = await httpClient.GetAsync(apiUrl);
                
                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogError("External API returned error status: {StatusCode}", response.StatusCode);
                    return Error($"External API error: {response.StatusCode}");
                }

                var jsonResponse = await response.Content.ReadAsStringAsync();
                _logger.LogInformation("External API response for edit: {Response}", jsonResponse);
                
                // Parse the JSON response
                using var jsonDocument = JsonDocument.Parse(jsonResponse);
                var root = jsonDocument.RootElement;

                // Create user profile from external API data
                var userProfile = new UserProfile
                {
                    Name = GetJsonStringValue(root, "displayName") ?? GetJsonStringValue(root, "name"),
                    Email = GetJsonStringValue(root, "mail") ?? GetJsonStringValue(root, "userPrincipalName") ?? userEmail,
                    ObjectId = GetJsonStringValue(root, "id") ?? GetJsonStringValue(root, "objectId"),
                    GivenName = GetJsonStringValue(root, "givenName"),
                    Surname = GetJsonStringValue(root, "surname"),
                    StreetAddress = GetJsonStringValue(root, "streetAddress"),
                    City = GetJsonStringValue(root, "city"),
                    StateProvince = GetJsonStringValue(root, "state") ?? GetJsonStringValue(root, "stateProvince"),
                    CountryOrRegion = GetJsonStringValue(root, "country") ?? GetJsonStringValue(root, "countryOrRegion")
                };

                return View(userProfile);
            }
            catch (HttpRequestException ex)
            {
                _logger.LogError(ex, "HTTP request exception when calling external API for edit profile");
                return Error($"Network error: {ex.Message}");
            }
            catch (JsonException ex)
            {
                _logger.LogError(ex, "JSON parsing exception when processing external API response for edit profile");
                return Error($"Invalid response format: {ex.Message}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error accessing external API for edit profile");
                return Error($"Error accessing external API: {ex.Message}");
            }
        }



        [Authorize]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> UpdateProfile(UserProfile model)
        {
            try
            {
                _logger.LogInformation("Starting profile update for user");
                _logger.LogInformation("Model data: {@ModelData}", model);

                // Clear any existing model state errors
                ModelState.Clear();

                // Validate only required fields
                if (string.IsNullOrWhiteSpace(model.Name))
                {
                    ModelState.AddModelError("Name", "Display Name is required");
                }

                if (!ModelState.IsValid)
                {
                    _logger.LogWarning("Model state is invalid: {@ModelState}", ModelState.Values
                        .SelectMany(v => v.Errors)
                        .Select(e => e.ErrorMessage));
                    return View("EditProfile", model);
                }

                // Get user's email from claims with multiple fallback options
                var userEmail = User.Claims.FirstOrDefault(c => 
                    c.Type == "email" || 
                    c.Type == "preferred_username" || 
                    c.Type == "emails" ||
                    c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress" ||
                    c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn" ||
                    c.Type == "upn" ||
                    c.Type == ClaimTypes.Email ||
                    c.Type == ClaimTypes.Upn
                )?.Value;

                _logger.LogInformation("Initial userEmail from claims for update: {UserEmail}", userEmail);

                // Check if this is a GUID-based email (common with App3)
                bool isGuidEmail = false;
                if (!string.IsNullOrEmpty(userEmail) && userEmail.Contains("@"))
                {
                    var emailPart = userEmail.Split('@')[0];
                    isGuidEmail = Guid.TryParse(emailPart, out _);
                    _logger.LogInformation("Email appears to be GUID-based for update: {IsGuidEmail}", isGuidEmail);
                }

                // If email not found in claims OR it's a GUID-based email, try to get real email from Microsoft Graph API
                if (string.IsNullOrEmpty(userEmail) || isGuidEmail)
                {
                    _logger.LogWarning("Email not found in claims or is GUID-based for update, attempting to get real email from Microsoft Graph API");
                    try
                    {
                        var graphClient = await _graphApiService.GetDelegatedGraphClientAsync();
                        var user = await graphClient.Me.GetAsync();
                        
                        if (user != null)
                        {
                            var realEmail = user.Mail ?? user.UserPrincipalName;
                            if (!string.IsNullOrEmpty(realEmail))
                            {
                                _logger.LogInformation("Successfully retrieved real email from Graph API for update: {RealEmail} (was: {OriginalEmail})", realEmail, userEmail);
                                userEmail = realEmail;
                            }
                            else
                            {
                                _logger.LogWarning("Graph API returned user but no email found for update. User.Mail: {Mail}, User.UserPrincipalName: {UPN}", user.Mail, user.UserPrincipalName);
                            }
                        }
                        else
                        {
                            _logger.LogWarning("Graph API returned null user for update");
                        }
                    }
                    catch (Exception graphEx)
                    {
                        _logger.LogError(graphEx, "Failed to get email from Graph API for update");
                    }
                }

                if (string.IsNullOrEmpty(userEmail))
                {
                    _logger.LogError("User email not found for profile update");
                    ModelState.AddModelError("", "User email not found. Cannot update profile.");
                    return View("EditProfile", model);
                }

                // Get access token for API authentication
                string accessToken = null;
                try
                {
                    accessToken = await HttpContext.GetTokenAsync("access_token");
                    if (string.IsNullOrEmpty(accessToken))
                    {
                        var authScheme = User.Claims.FirstOrDefault(c => c.Type == "auth_scheme")?.Value;
                        if (!string.IsNullOrEmpty(authScheme))
                        {
                            accessToken = await HttpContext.GetTokenAsync(authScheme, "access_token");
                        }
                    }
                }
                catch (Exception tokenEx)
                {
                    _logger.LogWarning(tokenEx, "Failed to retrieve access token for update");
                }

                // Create update payload based on your API requirements
                var updatePayload = new Dictionary<string, object>();
                
                // Add fields that are not null or empty
                if (!string.IsNullOrWhiteSpace(model.Name))
                    updatePayload["displayName"] = model.Name;
                if (!string.IsNullOrWhiteSpace(model.GivenName))
                    updatePayload["givenName"] = model.GivenName;
                if (!string.IsNullOrWhiteSpace(model.Surname))
                    updatePayload["surname"] = model.Surname;
                if (!string.IsNullOrWhiteSpace(model.StreetAddress))
                    updatePayload["streetAddress"] = model.StreetAddress;
                if (!string.IsNullOrWhiteSpace(model.City))
                    updatePayload["city"] = model.City;
                if (!string.IsNullOrWhiteSpace(model.StateProvince))
                    updatePayload["state"] = model.StateProvince;
                if (!string.IsNullOrWhiteSpace(model.CountryOrRegion))
                    updatePayload["country"] = model.CountryOrRegion;

                _logger.LogInformation("Preparing update request with payload: {@UpdatePayload}", updatePayload);

                // Call external REST API for update
                var httpClient = _httpClientFactory.CreateClient();
                
                // Add authentication header if access token is available
                if (!string.IsNullOrEmpty(accessToken))
                {
                    httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
                }
                
                var baseUrl = _configuration["MultiAppConfig:ExternalApi:BaseUrl"];
                var endpoint = _configuration["MultiAppConfig:ExternalApi:UpdateUserByEmailEndpoint"];
                var apiUrl = $"{baseUrl}{endpoint}?email={Uri.EscapeDataString(userEmail)}";
                
                _logger.LogInformation("Calling external API for update: {ApiUrl}", apiUrl);
                
                // Convert payload to JSON
                var jsonContent = System.Text.Json.JsonSerializer.Serialize(updatePayload);
                var content = new StringContent(
                    jsonContent,
                    System.Text.Encoding.UTF8,
                    "application/json"
                );

                // Make PATCH request
                var request = new HttpRequestMessage(HttpMethod.Patch, apiUrl)
                {
                    Content = content
                };
                var response = await httpClient.SendAsync(request);
                
                if (response.IsSuccessStatusCode)
                {
                    var responseContent = await response.Content.ReadAsStringAsync();
                    _logger.LogInformation("Profile updated successfully via external API: {Response}", responseContent);
                    TempData["SuccessMessage"] = "Profile updated successfully!";
                    return RedirectToAction("Profile");
                }
                else
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    _logger.LogError("External API update failed with status {StatusCode}: {ErrorContent}", response.StatusCode, errorContent);
                    ModelState.AddModelError("", $"Failed to update profile: {response.StatusCode} - {errorContent}");
                    return View("EditProfile", model);
                }
            }
            catch (HttpRequestException ex)
            {
                _logger.LogError(ex, "HTTP request exception during profile update");
                ModelState.AddModelError("", $"Network error during update: {ex.Message}");
                return View("EditProfile", model);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in UpdateProfile action: {Message}", ex.Message);
                ModelState.AddModelError("", "An unexpected error occurred. Please try again.");
                return View("EditProfile", model);
            }
        }




        // Helper class for Graph API error responses
        private class GraphError
        {
            public GraphErrorDetail Error { get; set; }
        }



        private class GraphErrorDetail
        {
            public string Code { get; set; }
            public string Message { get; set; }
            public string InnerError { get; set; }
        }



        [Authorize]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(string newPassword)
        {
            try
            {
                _logger.LogInformation("Starting password reset for user");

                // Validate the new password
                if (string.IsNullOrWhiteSpace(newPassword))
                {
                    TempData["Error"] = "New password is required.";
                    return RedirectToAction("Profile");
                }

                if (newPassword.Length < 8)
                {
                    TempData["Error"] = "Password must be at least 8 characters long.";
                    return RedirectToAction("Profile");
                }

                // Get user's email from claims with multiple fallback options
                var userEmail = User.Claims.FirstOrDefault(c => 
                    c.Type == "email" || 
                    c.Type == "preferred_username" || 
                    c.Type == "emails" ||
                    c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress" ||
                    c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn" ||
                    c.Type == "upn" ||
                    c.Type == ClaimTypes.Email ||
                    c.Type == ClaimTypes.Upn
                )?.Value;

                _logger.LogInformation("Initial userEmail from claims for password reset: {UserEmail}", userEmail);

                // Check if this is a GUID-based email (common with App3)
                bool isGuidEmail = false;
                if (!string.IsNullOrEmpty(userEmail) && userEmail.Contains("@"))
                {
                    var emailPart = userEmail.Split('@')[0];
                    isGuidEmail = Guid.TryParse(emailPart, out _);
                    _logger.LogInformation("Email appears to be GUID-based for password reset: {IsGuidEmail}", isGuidEmail);
                }

                // If email not found in claims OR it's a GUID-based email, try to get real email from Microsoft Graph API
                if (string.IsNullOrEmpty(userEmail) || isGuidEmail)
                {
                    _logger.LogWarning("Email not found in claims or is GUID-based for password reset, attempting to get real email from Microsoft Graph API");
                    try
                    {
                        var graphClient = await _graphApiService.GetDelegatedGraphClientAsync();
                        var user = await graphClient.Me.GetAsync();
                        
                        if (user != null)
                        {
                            var realEmail = user.Mail ?? user.UserPrincipalName;
                            if (!string.IsNullOrEmpty(realEmail))
                            {
                                _logger.LogInformation("Successfully retrieved real email from Graph API for password reset: {RealEmail} (was: {OriginalEmail})", realEmail, userEmail);
                                userEmail = realEmail;
                            }
                            else
                            {
                                _logger.LogWarning("Graph API returned user but no email found for password reset. User.Mail: {Mail}, User.UserPrincipalName: {UPN}", user.Mail, user.UserPrincipalName);
                            }
                        }
                        else
                        {
                            _logger.LogWarning("Graph API returned null user for password reset");
                        }
                    }
                    catch (Exception graphEx)
                    {
                        _logger.LogError(graphEx, "Failed to get email from Graph API for password reset");
                    }
                }

                if (string.IsNullOrEmpty(userEmail))
                {
                    _logger.LogError("User email not found for password reset");
                    TempData["Error"] = "User email not found. Cannot reset password.";
                    return RedirectToAction("Profile");
                }

                // Get access token for API authentication
                string accessToken = null;
                try
                {
                    accessToken = await HttpContext.GetTokenAsync("access_token");
                    if (string.IsNullOrEmpty(accessToken))
                    {
                        var authScheme = User.Claims.FirstOrDefault(c => c.Type == "auth_scheme")?.Value;
                        if (!string.IsNullOrEmpty(authScheme))
                        {
                            accessToken = await HttpContext.GetTokenAsync(authScheme, "access_token");
                        }
                    }
                }
                catch (Exception tokenEx)
                {
                    _logger.LogWarning(tokenEx, "Failed to retrieve access token for password reset");
                }

                // Create password reset payload
                var resetPayload = new Dictionary<string, object>
                {
                    ["newPassword"] = newPassword
                };

                _logger.LogInformation("Preparing password reset request for email: {Email}", userEmail);

                // Call external REST API for password reset
                var httpClient = _httpClientFactory.CreateClient();
                
                // Add authentication header if access token is available
                if (!string.IsNullOrEmpty(accessToken))
                {
                    httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
                }
                else
                {
                    _logger.LogWarning("No access token available for password reset API call");
                }
                
                var baseUrl = _configuration["MultiAppConfig:ExternalApi:BaseUrl"];
                var endpoint = _configuration["MultiAppConfig:ExternalApi:ResetPasswordByEmailEndpoint"];
                var apiUrl = $"{baseUrl}{endpoint}?email={Uri.EscapeDataString(userEmail)}";
                
                _logger.LogInformation("Calling external API for password reset: {ApiUrl}", apiUrl);
                
                // Convert payload to JSON
                var jsonContent = System.Text.Json.JsonSerializer.Serialize(resetPayload);
                var content = new StringContent(
                    jsonContent,
                    System.Text.Encoding.UTF8,
                    "application/json"
                );

                // Make PATCH request
                var request = new HttpRequestMessage(HttpMethod.Patch, apiUrl)
                {
                    Content = content
                };
                var response = await httpClient.SendAsync(request);
                
                if (response.IsSuccessStatusCode)
                {
                    var responseContent = await response.Content.ReadAsStringAsync();
                    _logger.LogInformation("Password reset successfully via external API: {Response}", responseContent);
                    TempData["SuccessMessage"] = "Password reset successfully! Please use your new password for future logins.";
                    return RedirectToAction("Profile");
                }
                else
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    _logger.LogError("External API password reset failed with status {StatusCode}: {ErrorContent}", response.StatusCode, errorContent);
                    
                    var errorMessage = response.StatusCode switch
                    {
                        HttpStatusCode.NotFound => $"User not found in external API. Email used: '{userEmail}'. Please ensure this user exists in the external system.",
                        HttpStatusCode.Unauthorized => "Authentication failed. Please check if the access token is valid.",
                        HttpStatusCode.Forbidden => "Access denied. Please check API permissions for password reset.",
                        HttpStatusCode.BadRequest => $"Invalid password format or other validation error: {errorContent}",
                        _ => $"Password reset failed: {response.StatusCode} - {errorContent}"
                    };
                    
                    TempData["Error"] = errorMessage;
                    return RedirectToAction("Profile");
                }
            }
            catch (HttpRequestException ex)
            {
                _logger.LogError(ex, "HTTP request exception during password reset");
                TempData["Error"] = $"Network error during password reset: {ex.Message}";
                return RedirectToAction("Profile");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in ResetPassword action: {Message}", ex.Message);
                TempData["Error"] = "An unexpected error occurred during password reset. Please try again.";
                return RedirectToAction("Profile");
            }
        }



        [Authorize]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteProfile()
        {
            try
            {
                _logger.LogInformation("Starting profile deletion for user");

                // Get user's email from claims with multiple fallback options
                var userEmail = User.Claims.FirstOrDefault(c => 
                    c.Type == "email" || 
                    c.Type == "preferred_username" || 
                    c.Type == "emails" ||
                    c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress" ||
                    c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn" ||
                    c.Type == "upn" ||
                    c.Type == ClaimTypes.Email ||
                    c.Type == ClaimTypes.Upn
                )?.Value;

                _logger.LogInformation("Initial userEmail from claims for profile deletion: {UserEmail}", userEmail);

                // Check if this is a GUID-based email (common with App3)
                bool isGuidEmail = false;
                if (!string.IsNullOrEmpty(userEmail) && userEmail.Contains("@"))
                {
                    var emailPart = userEmail.Split('@')[0];
                    isGuidEmail = Guid.TryParse(emailPart, out _);
                    _logger.LogInformation("Email appears to be GUID-based for profile deletion: {IsGuidEmail}", isGuidEmail);
                }

                // If email not found in claims OR it's a GUID-based email, try to get real email from Microsoft Graph API
                if (string.IsNullOrEmpty(userEmail) || isGuidEmail)
                {
                    _logger.LogWarning("Email not found in claims or is GUID-based for profile deletion, attempting to get real email from Microsoft Graph API");
                    try
                    {
                        var graphClient = await _graphApiService.GetDelegatedGraphClientAsync();
                        var user = await graphClient.Me.GetAsync();
                        
                        if (user != null)
                        {
                            var realEmail = user.Mail ?? user.UserPrincipalName;
                            if (!string.IsNullOrEmpty(realEmail))
                            {
                                _logger.LogInformation("Successfully retrieved real email from Graph API for profile deletion: {RealEmail} (was: {OriginalEmail})", realEmail, userEmail);
                                userEmail = realEmail;
                            }
                            else
                            {
                                _logger.LogWarning("Graph API returned user but no email found for profile deletion. User.Mail: {Mail}, User.UserPrincipalName: {UPN}", user.Mail, user.UserPrincipalName);
                            }
                        }
                        else
                        {
                            _logger.LogWarning("Graph API returned null user for profile deletion");
                        }
                    }
                    catch (Exception graphEx)
                    {
                        _logger.LogError(graphEx, "Failed to get email from Graph API for profile deletion");
                    }
                }

                if (string.IsNullOrEmpty(userEmail))
                {
                    _logger.LogError("User email not found for profile deletion");
                    TempData["Error"] = "User email not found. Cannot delete profile.";
                    return RedirectToAction("Profile");
                }

                // Get access token for API authentication
                string accessToken = null;
                try
                {
                    accessToken = await HttpContext.GetTokenAsync("access_token");
                    if (string.IsNullOrEmpty(accessToken))
                    {
                        var authScheme = User.Claims.FirstOrDefault(c => c.Type == "auth_scheme")?.Value;
                        if (!string.IsNullOrEmpty(authScheme))
                        {
                            accessToken = await HttpContext.GetTokenAsync(authScheme, "access_token");
                        }
                    }
                }
                catch (Exception tokenEx)
                {
                    _logger.LogWarning(tokenEx, "Failed to retrieve access token for profile deletion");
                }

                // Call external REST API for profile deletion
                var httpClient = _httpClientFactory.CreateClient();
                
                // Add authentication header if access token is available
                if (!string.IsNullOrEmpty(accessToken))
                {
                    httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
                }
                else
                {
                    _logger.LogWarning("No access token available for profile deletion API call");
                }
                
                var baseUrl = _configuration["MultiAppConfig:ExternalApi:BaseUrl"];
                var endpoint = _configuration["MultiAppConfig:ExternalApi:DeleteUserByEmailEndpoint"];
                var apiUrl = $"{baseUrl}{endpoint}?email={Uri.EscapeDataString(userEmail)}";
                
                _logger.LogInformation("Calling external API for profile deletion: {ApiUrl}", apiUrl);
                
                // Make DELETE request
                var response = await httpClient.DeleteAsync(apiUrl);
                
                if (response.IsSuccessStatusCode)
                {
                    var responseContent = await response.Content.ReadAsStringAsync();
                    _logger.LogInformation("Profile deleted successfully via external API: {Response}", responseContent);
                    
                    // Sign out the user after successful deletion
                    await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                    await HttpContext.SignOutAsync("App1Scheme");
                    await HttpContext.SignOutAsync("App2Scheme");
                    await HttpContext.SignOutAsync("App3Scheme");

                    // Clear session
                    HttpContext.Session.Clear();

                    // Redirect to home page with success message
                    TempData["SuccessMessage"] = "Your profile has been successfully deleted.";
                    return RedirectToAction("Index", "Home");
                }
                else
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    _logger.LogError("External API profile deletion failed with status {StatusCode}: {ErrorContent}", response.StatusCode, errorContent);
                    
                    var errorMessage = response.StatusCode switch
                    {
                        HttpStatusCode.NotFound => $"User not found in external API. Email used: '{userEmail}'. Please ensure this user exists in the external system.",
                        HttpStatusCode.Unauthorized => "Authentication failed. Please check if the access token is valid.",
                        HttpStatusCode.Forbidden => "Access denied. Please check API permissions for profile deletion.",
                        HttpStatusCode.Conflict => "Profile deletion failed due to existing dependencies or constraints.",
                        _ => $"Profile deletion failed: {response.StatusCode} - {errorContent}"
                    };
                    
                    TempData["Error"] = errorMessage;
                    return RedirectToAction("Profile");
                }
            }
            catch (HttpRequestException ex)
            {
                _logger.LogError(ex, "HTTP request exception during profile deletion");
                TempData["Error"] = $"Network error during profile deletion: {ex.Message}";
                return RedirectToAction("Profile");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in DeleteProfile action: {Message}", ex.Message);
                TempData["Error"] = "An unexpected error occurred during profile deletion. Please try again.";
                return RedirectToAction("Profile");
            }
        }




        private class SimpleAuthProvider : IAuthenticationProvider
        {
            private readonly string _token;

            public SimpleAuthProvider(string token)
            {
                _token = token;
            }

            public Task AuthenticateRequestAsync(RequestInformation request, Dictionary<string, object>? additionalAuthenticationContext = null, CancellationToken cancellationToken = default)
            {
                request.Headers.Add("Authorization", $"Bearer {_token}");
                return Task.CompletedTask;
            }
        }



        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error(string message = null)
        {
            var errorViewModel = new ErrorViewModel
            {
                RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier,
                ErrorMessage = message
            };
            return View("Error", errorViewModel);
        }



        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult ProfileError(string message = null)
        {
            var errorViewModel = new ErrorViewModel
            {
                RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier,
                ErrorMessage = message
            };
            return View("Error", errorViewModel);
        }



        [Authorize]
        public async Task<IActionResult> CheckMfaStatus()
        {
            try
            {
                // Use delegated permissions for /me request
                var graphClient = await _graphApiService.GetDelegatedGraphClientAsync();
                var user = await graphClient.Me.GetAsync();

                // Get authentication methods
                var authMethods = await graphClient.Users[user.Id]
                    .Authentication.Methods.GetAsync();

                var mfaStatus = new
                {
                    IsMfaEnabled = authMethods?.Value?.Any(m => m.GetType().Name.Contains("MicrosoftAuthenticator")) ?? false,
                    AvailableMethods = authMethods?.Value?.Select(m => new
                    {
                        MethodType = GetMethodTypeDisplayName(m.GetType().Name),
                        MethodId = m.Id,
                        IsEnabled = true, // Since we can get the method, it's enabled
                        LastUsed = GetLastUsedDate(m) // Add last used date if available
                    }).ToList(),
                    UserId = user.Id,
                    UserPrincipalName = user.UserPrincipalName
                };

                return View(mfaStatus);
            }
            catch (ServiceException ex)
            {
                _logger.LogError(ex, "Graph API Service Exception while checking MFA status");
                return Error($"Error checking MFA status: {ex.Message}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking MFA status");
                return Error($"Error checking MFA status: {ex.Message}");
            }
        }



        private string GetMethodTypeDisplayName(string typeName)
        {
            return typeName switch
            {
                var name when name.Contains("MicrosoftAuthenticator") => "Microsoft Authenticator App",
                var name when name.Contains("Phone") => "Phone Authentication",
                var name when name.Contains("Email") => "Email Authentication",
                var name when name.Contains("Fido") => "FIDO2 Security Key",
                var name when name.Contains("WindowsHello") => "Windows Hello",
                _ => typeName
            };
        }



        private string GetLastUsedDate(AuthenticationMethod method)
        {
            // Try to get the last used date if available
            try
            {
                var lastUsedProperty = method.GetType().GetProperty("LastUsedDateTime");
                if (lastUsedProperty != null)
                {
                    var lastUsed = lastUsedProperty.GetValue(method);
                    if (lastUsed != null)
                    {
                        return ((DateTimeOffset)lastUsed).ToString("g");
                    }
                }
            }
            catch
            {
                // If we can't get the last used date, return "Unknown"
            }
            return "Unknown";
        }





        [Authorize]
        public async Task<IActionResult> MultiAppInfo()
        {
            try
            {
                var viewModel = new MultiAppAuthViewModel
                {
                    IsAuthenticated = User.Identity?.IsAuthenticated ?? false,
                    Claims = User.Claims.Select(c => new UserClaim { Type = c.Type, Value = c.Value }).ToList()
                };

                if (User.Identity?.IsAuthenticated == true)
                {
                    // Get authentication scheme information
                    var authScheme = User.Claims.FirstOrDefault(c => c.Type == "auth_scheme")?.Value ?? "Default";
                    viewModel.AuthenticationScheme = authScheme;

                    // Get user information
                    var displayName = User.Claims.FirstOrDefault(c => c.Type == "name")?.Value ?? User.Identity.Name ?? "Unknown";
                    viewModel.AuthenticatedUser = displayName;

                    // Determine which application was used based on the authentication scheme
                    viewModel.ApplicationName = authScheme switch
                    {
                        "App1Scheme" => "Application 1",
                        "App2Scheme" => "Application 2",
                        "App3Scheme" => "Application 3",
                        _ => "Unknown Application"
                    };

                    // Get client ID based on the scheme
                    viewModel.ClientId = authScheme switch
                    {
                        "App1Scheme" => _configuration["MultiAppConfig:App1:ClientId"],
                        "App2Scheme" => _configuration["MultiAppConfig:App2:ClientId"],
                        "App3Scheme" => _configuration["MultiAppConfig:App3:ClientId"],
                        _ => "Unknown"
                    };

                    // Test Graph API connection
                    try
                    {
                        var graphClient = await _graphApiService.GetDelegatedGraphClientAsync();
                        var user = await graphClient.Me.GetAsync();
                        viewModel.GraphApiInfo = new GraphApiInfo
                        {
                            DisplayName = user.DisplayName,
                            UserPrincipalName = user.UserPrincipalName,
                            Id = user.Id,
                            Mail = user.Mail,
                            JobTitle = user.JobTitle,
                            Department = user.Department,
                            IsConnected = true
                        };
                    }
                    catch (Exception ex)
                    {
                        viewModel.GraphApiInfo = new GraphApiInfo
                        {
                            IsConnected = false,
                            ErrorMessage = ex.Message
                        };
                    }
                }

                return View(viewModel);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in MultiAppInfo action");
                return Error($"Error getting multi-app information: {ex.Message}");
            }
        }



        [Authorize]
        public async Task<IActionResult> UserDifferentiationDemo()
        {
            try
            {
                var userInfo = new
                {
                    // User Identity (preserved regardless of which app was used)
                    UserName = User.Identity?.Name,
                    UserEmail = User.Claims.FirstOrDefault(c => c.Type == "email")?.Value,
                    UserObjectId = User.Claims.FirstOrDefault(c => c.Type == "oid")?.Value,
                    UserDisplayName = User.Claims.FirstOrDefault(c => c.Type == "name")?.Value,

                    // Application Context (shows which app was used)
                    AuthenticationScheme = User.Claims.FirstOrDefault(c => c.Type == "auth_scheme")?.Value ?? "Unknown",
                    ClientId = User.Claims.FirstOrDefault(c => c.Type == "aud")?.Value,

                    // Graph API Recognition
                    GraphApiUser = await GetGraphApiUserInfo()
                };

                return View("UserDifferentiationDemo", userInfo);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in UserDifferentiationDemo");
                return Error($"Error demonstrating user differentiation: {ex.Message}");
            }
        }


        [Authorize]
        public async Task<IActionResult> DebugProfileApi()
        {
            try
            {
                var debugInfo = new Dictionary<string, object>();
                
                // Get authentication scheme
                var authScheme = User.Claims.FirstOrDefault(c => c.Type == "auth_scheme")?.Value;
                debugInfo["AuthenticationScheme"] = authScheme;
                
                // Get all email-related claims
                var emailClaims = new Dictionary<string, string>();
                var possibleEmailClaimTypes = new[] {
                    "email", "preferred_username", "emails",
                    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
                    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn",
                    "upn", ClaimTypes.Email, ClaimTypes.Upn, "unique_name"
                };
                
                foreach (var claimType in possibleEmailClaimTypes)
                {
                    var claimValue = User.Claims.FirstOrDefault(c => c.Type == claimType)?.Value;
                    if (!string.IsNullOrEmpty(claimValue))
                    {
                        emailClaims[claimType] = claimValue;
                    }
                }
                debugInfo["EmailClaims"] = emailClaims;
                
                // Try to extract email using the same logic as Profile method
                var userEmail = User.Claims.FirstOrDefault(c => 
                    c.Type == "email" || 
                    c.Type == "preferred_username" || 
                    c.Type == "emails" ||
                    c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress" ||
                    c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn" ||
                    c.Type == "upn" ||
                    c.Type == ClaimTypes.Email ||
                    c.Type == ClaimTypes.Upn
                )?.Value;
                
                debugInfo["ExtractedEmail"] = userEmail;
                
                // Try to get email from Graph API if not found in claims
                if (string.IsNullOrEmpty(userEmail))
                {
                    try
                    {
                        var graphClient = await _graphApiService.GetDelegatedGraphClientAsync();
                        var user = await graphClient.Me.GetAsync();
                        userEmail = user.Mail ?? user.UserPrincipalName;
                        debugInfo["GraphApiEmail"] = userEmail;
                        debugInfo["GraphApiUser"] = new
                        {
                            DisplayName = user.DisplayName,
                            Mail = user.Mail,
                            UserPrincipalName = user.UserPrincipalName,
                            Id = user.Id
                        };
                    }
                    catch (Exception graphEx)
                    {
                        debugInfo["GraphApiError"] = graphEx.Message;
                    }
                }
                
                if (string.IsNullOrEmpty(userEmail))
                {
                    debugInfo["Error"] = "No email found in claims or Graph API";
                    return Json(debugInfo);
                }
                
                // Get access token
                string accessToken = null;
                try
                {
                    accessToken = await HttpContext.GetTokenAsync("access_token");
                    if (string.IsNullOrEmpty(accessToken) && !string.IsNullOrEmpty(authScheme))
                    {
                        accessToken = await HttpContext.GetTokenAsync(authScheme, "access_token");
                    }
                    debugInfo["HasAccessToken"] = !string.IsNullOrEmpty(accessToken);
                    debugInfo["AccessTokenPreview"] = !string.IsNullOrEmpty(accessToken) ? 
                        accessToken.Substring(0, Math.Min(50, accessToken.Length)) + "..." : null;
                }
                catch (Exception tokenEx)
                {
                    debugInfo["TokenError"] = tokenEx.Message;
                }
                
                // Test the external API call
                var httpClient = _httpClientFactory.CreateClient();
                
                // Add authentication header if access token is available
                if (!string.IsNullOrEmpty(accessToken))
                {
                    httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
                }
                
                var baseUrl = _configuration["MultiAppConfig:ExternalApi:BaseUrl"];
                var endpoint = _configuration["MultiAppConfig:ExternalApi:GetUserByEmailEndpoint"];
                var apiUrl = $"{baseUrl}{endpoint}?email={Uri.EscapeDataString(userEmail)}";
                
                debugInfo["ApiCall"] = new
                {
                    BaseUrl = baseUrl,
                    Endpoint = endpoint,
                    FullUrl = apiUrl,
                    EmailParameter = userEmail,
                    EncodedEmail = Uri.EscapeDataString(userEmail)
                };
                
                try
                {
                    var response = await httpClient.GetAsync(apiUrl);
                    var responseContent = await response.Content.ReadAsStringAsync();
                    
                    debugInfo["ApiResponse"] = new
                    {
                        StatusCode = (int)response.StatusCode,
                        StatusDescription = response.StatusCode.ToString(),
                        IsSuccess = response.IsSuccessStatusCode,
                        Headers = response.Headers.ToDictionary(h => h.Key, h => string.Join(", ", h.Value)),
                        ContentLength = responseContent?.Length ?? 0,
                        ResponseBody = responseContent
                    };
                }
                catch (Exception apiEx)
                {
                    debugInfo["ApiError"] = apiEx.Message;
                }
                
                return Json(debugInfo);
            }
            catch (Exception ex)
            {
                return Json(new { Error = ex.Message, StackTrace = ex.StackTrace });
            }
        }

        [Authorize]
        public async Task<IActionResult> DebugTokens()
        {
            try
            {
                var tokenInfo = new Dictionary<string, object>();
                
                // Try to get various tokens
                var tokenTypes = new[] { "access_token", "id_token", "refresh_token" };
                var schemes = new[] { "App1Scheme", "App2Scheme", "App3Scheme" };
                
                // Check general tokens
                foreach (var tokenType in tokenTypes)
                {
                    try
                    {
                        var token = await HttpContext.GetTokenAsync(tokenType);
                        tokenInfo[$"General_{tokenType}"] = new 
                        {
                            HasToken = !string.IsNullOrEmpty(token),
                            Preview = !string.IsNullOrEmpty(token) ? token.Substring(0, Math.Min(20, token.Length)) + "..." : null
                        };
                    }
                    catch (Exception ex)
                    {
                        tokenInfo[$"General_{tokenType}"] = new { Error = ex.Message };
                    }
                }
                
                // Check scheme-specific tokens
                foreach (var scheme in schemes)
                {
                    foreach (var tokenType in tokenTypes)
                    {
                        try
                        {
                            var token = await HttpContext.GetTokenAsync(scheme, tokenType);
                            tokenInfo[$"{scheme}_{tokenType}"] = new 
                            {
                                HasToken = !string.IsNullOrEmpty(token),
                                Preview = !string.IsNullOrEmpty(token) ? token.Substring(0, Math.Min(20, token.Length)) + "..." : null
                            };
                        }
                        catch (Exception ex)
                        {
                            tokenInfo[$"{scheme}_{tokenType}"] = new { Error = ex.Message };
                        }
                    }
                }
                
                return Json(new
                {
                    AuthenticationScheme = User.Claims.FirstOrDefault(c => c.Type == "auth_scheme")?.Value,
                    IsAuthenticated = User.Identity?.IsAuthenticated ?? false,
                    Tokens = tokenInfo
                });
            }
            catch (Exception ex)
            {
                return Json(new { Error = ex.Message });
            }
        }
        
        [Authorize]
        public IActionResult DebugClaims()
        {
            var claims = User.Claims.Select(c => new 
            {
                Type = c.Type,
                Value = c.Value,
                Issuer = c.Issuer
            }).ToList();

            return Json(new 
            {
                IsAuthenticated = User.Identity?.IsAuthenticated ?? false,
                AuthenticationType = User.Identity?.AuthenticationType,
                Name = User.Identity?.Name,
                ClaimsCount = claims.Count,
                Claims = claims,
                // Test email extraction
                EmailTests = new 
                {
                    Email = User.Claims.FirstOrDefault(c => c.Type == "email")?.Value,
                    PreferredUsername = User.Claims.FirstOrDefault(c => c.Type == "preferred_username")?.Value,
                    Emails = User.Claims.FirstOrDefault(c => c.Type == "emails")?.Value,
                    EmailAddress = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value,
                    Upn = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Upn)?.Value,
                    Name = User.Claims.FirstOrDefault(c => c.Type == "name")?.Value,
                    Oid = User.Claims.FirstOrDefault(c => c.Type == "oid")?.Value
                }
            });
        }

        private async Task<object> GetGraphApiUserInfo()
        {
            try
            {
                var graphClient = await _graphApiService.GetDelegatedGraphClientAsync();
                var user = await graphClient.Me.GetAsync();
                return new
                {
                    DisplayName = user.DisplayName,
                    UserPrincipalName = user.UserPrincipalName,
                    Id = user.Id,
                    Mail = user.Mail,
                    JobTitle = user.JobTitle,
                    Department = user.Department,
                    IsRecognized = true
                };
            }
            catch (Exception ex)
            {
                return new
                {
                    Error = ex.Message,
                    IsRecognized = false
                };
            }
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
