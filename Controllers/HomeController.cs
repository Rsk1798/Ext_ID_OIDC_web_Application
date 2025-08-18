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

namespace Ext_ID_OIDC_web_Application.Controllers
{
    public class HomeController : Controller
    {
        private readonly GraphServiceClient _graphClient;
        private readonly ILogger<HomeController> _logger;
        private readonly IConfiguration _configuration;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly ITokenAcquisition _tokenAcquisition;
        private readonly IGraphApiService _graphApiService;
        private static readonly Dictionary<string, (int Count, DateTime LastAttempt)> _loginAttempts = new();
        private const int MaxLoginAttempts = 5;
        private const int LoginAttemptWindowMinutes = 15;



        public HomeController(GraphServiceClient graphClient,
        ILogger<HomeController> logger,
        IConfiguration configuration,
        IHttpClientFactory httpClientFactory,
        ITokenAcquisition tokenAcquisition,
        IGraphApiService graphApiService)
        {
            _graphClient = graphClient;
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
                "DefaultScheme" => "Default Application",
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


        public IActionResult SignInDefault()
        {
            LogSecurityEvent("SignInAttempt", "User attempting to sign in with Default App");
            return Challenge(new AuthenticationProperties
            {
                RedirectUri = Url.Action("Index", "Home"),
                Items = { { "scheme", "DefaultScheme" } }
            }, "DefaultScheme");
        }



        [Authorize]
        public async Task<IActionResult> Profile()
        {
            AddSecurityHeaders();
            try
            {
                // Get user profile from Graph API with additional fields
                var user = await _graphClient.Me.GetAsync(requestConfiguration => {
                    requestConfiguration.QueryParameters.Select = new[] {
                    "id",
                    "displayName",
                    "givenName",
                    "surname",
                    "mail",
                    "userPrincipalName",
                    "streetAddress",
                    "city",
                    "state",
                    "country",
                    "postalCode"
                };
                });

                if (user == null)
                {
                    _logger.LogWarning("Graph API returned null user profile");
                    return RedirectToAction("ProfileError", new { message = "Failed to retrieve user profile from Graph API" });
                }

                // Create user profile from Graph API data
                var userProfile = new UserProfile
                {
                    Name = user.DisplayName,
                    Email = user.Mail ?? user.UserPrincipalName,
                    ObjectId = user.Id,
                    GivenName = user.GivenName,
                    Surname = user.Surname,
                    StreetAddress = user.StreetAddress,
                    City = user.City,
                    StateProvince = user.State,
                    CountryOrRegion = user.Country
                };

                // Get updated fields from TempData if available
                if (TempData["UpdatedFields"] != null)
                {
                    var updatedFields = System.Text.Json.JsonSerializer.Deserialize<List<string>>(TempData["UpdatedFields"].ToString());
                    userProfile.UpdatedFields = updatedFields;
                }

                return View(userProfile);
            }
            catch (ServiceException ex)
            {
                _logger.LogError(ex, "Graph API Service Exception");
                var errorMessage = $"Graph API Error: {ex.Message}";
                if (ex.ResponseHeaders != null)
                {
                    errorMessage += $"\nResponse Headers: {string.Join(", ", ex.ResponseHeaders.Select(h => $"{h.Key}={h.Value}"))}";
                }
                return RedirectToAction("ProfileError", new { message = errorMessage });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error accessing Graph API");
                return RedirectToAction("ProfileError", new { message = $"Error accessing Graph API: {ex.Message}" });
            }
        }



        [Authorize]
        public async Task<IActionResult> TestGraphApi()
        {
            try
            {
                // Try to get user profile from Graph API
                var user = await _graphClient.Me.GetAsync();

                if (user == null)
                {
                    _logger.LogWarning("Graph API returned null user profile");
                    return Error("Failed to retrieve user profile from Graph API");
                }

                _logger.LogInformation("Successfully retrieved user profile from Graph API: {DisplayName}", user.DisplayName);

                // Create a view model with the user information
                var viewModel = new
                {
                    DisplayName = user.DisplayName ?? "Not available",
                    UserPrincipalName = user.UserPrincipalName ?? "Not available",
                    Id = user.Id ?? "Not available",
                    Mail = user.Mail ?? "Not available",
                    JobTitle = user.JobTitle ?? "Not available",
                    Department = user.Department ?? "Not available"
                };

                return View("Index", viewModel);
            }
            catch (ServiceException ex)
            {
                _logger.LogError(ex, "Graph API Service Exception");
                var errorMessage = $"Graph API Error: {ex.Message}";
                if (ex.ResponseHeaders != null)
                {
                    errorMessage += $"\nResponse Headers: {string.Join(", ", ex.ResponseHeaders.Select(h => $"{h.Key}={h.Value}"))}";
                }
                return Error(errorMessage);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error accessing Graph API");
                return Error($"Error accessing Graph API: {ex.Message}");
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
                        // Test Graph API connection
                        var user = await _graphClient.Me.GetAsync();
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
                // Get the current user's account
                var user = await _graphClient.Me.GetAsync();
                if (user != null)
                {
                    _logger.LogInformation("User {DisplayName} signing out", user.DisplayName);

                    try
                    {
                        // Revoke all refresh tokens for the user
                        await _graphClient.Users[user.Id].RevokeSignInSessions.PostAsync();
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
                await HttpContext.SignOutAsync("DefaultScheme", authProperties);
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
                    await HttpContext.SignOutAsync("DefaultScheme");
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
                // Get real-time user data from Graph API with specific fields
                var user = await _graphClient.Me.GetAsync(requestConfiguration => {
                    requestConfiguration.QueryParameters.Select = new[] {
                    "id",
                    "displayName",
                    "givenName",
                    "surname",
                    "mail",
                    "userPrincipalName",
                    "streetAddress",
                    "city",
                    "state",
                    "country",
                    "postalCode"
                };
                });

                if (user == null)
                {
                    _logger.LogWarning("Graph API returned null user profile");
                    return Error("Failed to retrieve user profile from Graph API");
                }

                _logger.LogInformation("Retrieved user data: {@UserData}", new
                {
                    DisplayName = user.DisplayName,
                    GivenName = user.GivenName,
                    Surname = user.Surname,
                    StreetAddress = user.StreetAddress,
                    City = user.City,
                    State = user.State,
                    Country = user.Country
                });

                // Create user profile from Graph API data
                var userProfile = new UserProfile
                {
                    Name = user.DisplayName,
                    Email = user.Mail ?? user.UserPrincipalName,
                    ObjectId = user.Id,
                    GivenName = user.GivenName,
                    Surname = user.Surname,
                    StreetAddress = user.StreetAddress,
                    City = user.City,
                    StateProvince = user.State,
                    CountryOrRegion = user.Country
                };

                return View(userProfile);
            }
            catch (ServiceException ex)
            {
                _logger.LogError(ex, "Graph API Service Exception");
                var errorMessage = $"Graph API Error: {ex.Message}";
                if (ex.ResponseHeaders != null)
                {
                    errorMessage += $"\nResponse Headers: {string.Join(", ", ex.ResponseHeaders.Select(h => $"{h.Key}={h.Value}"))}";
                }
                return Error(errorMessage);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error accessing Graph API");
                return Error($"Error accessing Graph API: {ex.Message}");
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

                // Get the current user's ID and verify permissions
                _logger.LogInformation("Fetching current user from Graph API");
                var currentUser = await _graphClient.Me.GetAsync();
                if (currentUser == null)
                {
                    _logger.LogError("Failed to get current user from Graph API");
                    return Error("Failed to get current user information");
                }

                // Use Graph API app (application permissions) for write operations
                var appGraphClient = await _graphApiService.GetGraphClientAsync();

                // Create update user object matching Microsoft Graph API format exactly
                var updateUser = new
                {
                    displayName = model.Name,
                    givenName = model.GivenName,
                    surname = model.Surname,
                    streetAddress = model.StreetAddress,
                    city = model.City,
                    state = model.StateProvince,
                    country = model.CountryOrRegion
                };

                // Log the update request
                _logger.LogInformation("Preparing update request with data: {@UpdateData}", updateUser);

                // Convert to JSON
                var jsonContent = System.Text.Json.JsonSerializer.Serialize(updateUser);

                // Create HTTP content
                var content = new StringContent(
                    jsonContent,
                    System.Text.Encoding.UTF8,
                    "application/json"
                );

                try
                {
                    await appGraphClient.Users[currentUser.Id].PatchAsync(new Microsoft.Graph.Models.User
                    {
                        DisplayName = model.Name,
                        GivenName = model.GivenName,
                        Surname = model.Surname,
                        StreetAddress = model.StreetAddress,
                        City = model.City,
                        State = model.StateProvince,
                        Country = model.CountryOrRegion
                    });

                    TempData["SuccessMessage"] = "Profile updated successfully!";
                    return RedirectToAction("Profile");
                }
                catch (ServiceException ex)
                {
                    _logger.LogError(ex, "Failed to update profile via Graph SDK");
                    ModelState.AddModelError("", ex.Message);
                    return View("EditProfile", model);
                }
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
        public async Task<IActionResult> DeleteProfile()
        {
            try
            {
                // Get current user info
                var user = await _graphClient.Me.GetAsync();
                if (user == null)
                {
                    _logger.LogError("Failed to get current user information");
                    TempData["Error"] = "Failed to get user information. Please try again.";
                    return RedirectToAction(nameof(Profile));
                }

                // Use the application Graph client
                var graphClient = await _graphApiService.GetGraphClientAsync();

                try
                {
                    // Delete the user using the Graph SDK with application permissions
                    await graphClient.Users[user.Id].DeleteAsync();

                    _logger.LogInformation("User {UserId} was successfully deleted", user.Id);

                    // Sign out the user after deletion
                    await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                    await HttpContext.SignOutAsync("DefaultScheme");
                    await HttpContext.SignOutAsync("App1Scheme");
                    await HttpContext.SignOutAsync("App2Scheme");
                    await HttpContext.SignOutAsync("App3Scheme");

                    // Clear session
                    HttpContext.Session.Clear();

                    return RedirectToAction("Index", "Home");
                }
                catch (ServiceException ex)
                {
                    _logger.LogError(ex, "Graph API Service Exception during user deletion");

                    if (ex.ResponseStatusCode == (int)System.Net.HttpStatusCode.Forbidden)
                    {
                        TempData["Error"] = "You don't have sufficient permissions to delete your account. Please contact your administrator.";
                    }
                    else
                    {
                        TempData["Error"] = $"Failed to delete account: {ex.Message}";
                    }

                    return RedirectToAction(nameof(Profile));
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting user profile");
                TempData["Error"] = "An unexpected error occurred. Please try again later.";
                return RedirectToAction(nameof(Profile));
            }
        }



        private async Task<GraphServiceClient> GetGraphClient()
        {
            try
            {
                // Get the access token
                string accessToken = await _tokenAcquisition.GetAccessTokenForUserAsync(
                    new[] {
                    "User.Read",
                    "User.ReadWrite.All",
                    "User.ReadBasic.All"
                    });

                // Create a new GraphServiceClient with the token
                var authProvider = new SimpleAuthProvider(accessToken);
                return new GraphServiceClient(authProvider);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting Graph client");
                throw;
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
                var graphClient = await GetGraphClient();
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
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(string CurrentPassword, string NewPassword, string ConfirmPassword)
        {
            try
            {
                _logger.LogInformation("Starting password reset process");

                // Validate inputs
                if (string.IsNullOrEmpty(CurrentPassword) || string.IsNullOrEmpty(NewPassword) || string.IsNullOrEmpty(ConfirmPassword))
                {
                    TempData["Error"] = "All password fields are required.";
                    return RedirectToAction(nameof(Profile));
                }

                if (NewPassword != ConfirmPassword)
                {
                    TempData["Error"] = "New password and confirmation password do not match.";
                    return RedirectToAction(nameof(Profile));
                }

                // Validate password complexity
                if (!IsPasswordComplex(NewPassword))
                {
                    TempData["Error"] = "New password does not meet complexity requirements.";
                    return RedirectToAction(nameof(Profile));
                }

                // Get the current user
                var user = await _graphClient.Me.GetAsync();
                if (user == null)
                {
                    _logger.LogError("Failed to get current user information");
                    TempData["Error"] = "Failed to get user information. Please try again.";
                    return RedirectToAction(nameof(Profile));
                }

                try
                {
                    // Use application permissions to perform admin-style reset
                    var appGraphClient = await _graphApiService.GetGraphClientAsync();
                    await appGraphClient.Users[user.Id].PatchAsync(new Microsoft.Graph.Models.User
                    {
                        PasswordProfile = new Microsoft.Graph.Models.PasswordProfile
                        {
                            Password = NewPassword,
                            ForceChangePasswordNextSignIn = false
                        }
                    });

                    TempData["SuccessMessage"] = "Password reset. Please sign in again with the new password.";
                    return RedirectToAction(nameof(Profile));
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error resetting password through Graph API App");
                    TempData["Error"] = "An unexpected error occurred while changing your password. Please try again.";
                    return RedirectToAction(nameof(Profile));
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in ResetPassword action");
                TempData["Error"] = "An unexpected error occurred while changing your password. Please try again.";
                return RedirectToAction(nameof(Profile));
            }
        }



        private bool IsPasswordComplex(string password)
        {
            // Password complexity requirements for Azure Entra External ID
            var hasMinLength = password.Length >= 8;
            var hasUpperCase = password.Any(char.IsUpper);
            var hasLowerCase = password.Any(char.IsLower);
            var hasDigit = password.Any(char.IsDigit);
            var hasSpecialChar = password.Any(c => !char.IsLetterOrDigit(c));

            return hasMinLength && hasUpperCase && hasLowerCase && hasDigit && hasSpecialChar;
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
                        _ => "Default Application"
                    };

                    // Get client ID based on the scheme
                    viewModel.ClientId = authScheme switch
                    {
                        "App1Scheme" => _configuration["MultiAppConfig:App1:ClientId"],
                        "App2Scheme" => _configuration["MultiAppConfig:App2:ClientId"],
                        "App3Scheme" => _configuration["MultiAppConfig:App3:ClientId"],
                        _ => _configuration["MultiAppConfig:GraphApiApp:ClientId"]
                    };

                    // Test Graph API connection
                    try
                    {
                        var user = await _graphClient.Me.GetAsync();
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
                    AuthenticationScheme = User.Claims.FirstOrDefault(c => c.Type == "auth_scheme")?.Value ?? "Default",
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


        private async Task<object> GetGraphApiUserInfo()
        {
            try
            {
                var user = await _graphClient.Me.GetAsync();
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
