using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Graph;
using Microsoft.Identity.Web;
using Microsoft.Kiota.Abstractions;
using Microsoft.Kiota.Abstractions.Authentication;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();



// Add session support
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.Cookie.Name = "OIDCDemoApp.Session";
});



// Add HttpClient factory
builder.Services.AddHttpClient();



// Configure multi-app authentication
// Configuration binding is handled inside GraphApiService

// Configure authentication with multiple schemes
builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
    })
    .AddCookie(options =>
    {
        options.Cookie.Name = ".AspNetCore.Cookies";
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.ExpireTimeSpan = TimeSpan.FromHours(1);
        options.SlidingExpiration = true;
    })
    .AddOpenIdConnect("DefaultScheme", options => {
        // Manually configure options instead of using Bind
        options.Authority = "https://volvogroupextid.ciamlogin.com/volvogroupextid.onmicrosoft.com";
        options.MetadataAddress = "https://volvogroupextid.ciamlogin.com/volvogroupextid.onmicrosoft.com/v2.0/.well-known/openid-configuration";
        options.ClientId = "4731edbb-bf60-41dd-ad4e-e912903a6f5f";// "YOUR_DEFAULT_APP_CLIENT_ID";
        options.ClientSecret = "35c8Q~E0I5aDxogG_HDa8KZ30NDI6tTCtx352c6K";// "YOUR_DEFAULT_APP_CLIENT_SECRET";
        options.CallbackPath = "/signin-oidc";
        options.SignedOutCallbackPath = "/signout-callback-oidc";

        // Configure HTTPS requirement
        options.RequireHttpsMetadata = true;

        // Configure sign-out for CIAM
        options.UseTokenLifetime = false;
        options.SaveTokens = true;

        // Configure CIAM-specific options
        options.ResponseType = "code";
        options.ResponseMode = "form_post";
        options.UsePkce = true;

        // Configure cookie options
        options.NonceCookie.SecurePolicy = CookieSecurePolicy.Always;
        options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.Always;

        // Configure prompt behavior for password reset
        options.Prompt = "select_account";

        // Add required scopes
        options.Scope.Clear();
        options.Scope.Add("openid");
        options.Scope.Add("offline_access");
        options.Scope.Add("profile");
        options.Scope.Add("email");
        options.Scope.Add("User.Read");
        options.Scope.Add("User.ReadWrite.All");
        options.Scope.Add("Directory.AccessAsUser.All");

        options.Events = new OpenIdConnectEvents
        {
            OnRedirectToIdentityProvider = context =>
            {
                context.ProtocolMessage.Prompt = "login";
                context.ProtocolMessage.RedirectUri = $"{context.Request.Scheme}://{context.Request.Host}{context.Request.PathBase}/signin-oidc";
                return Task.CompletedTask;
            },
            OnRedirectToIdentityProviderForSignOut = context =>
            {
                context.ProtocolMessage.PostLogoutRedirectUri = $"{context.Request.Scheme}://{context.Request.Host}{context.Request.PathBase}/signout-callback-oidc";
                context.ProtocolMessage.State = Guid.NewGuid().ToString();
                return Task.CompletedTask;
            },
            OnSignedOutCallbackRedirect = async context =>
            {
                context.HttpContext.Session.Clear();
                await context.HttpContext.Session.LoadAsync();

                var cookieOptions = new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Lax,
                    Expires = DateTime.UtcNow.AddYears(-1)
                };

                var cookiesToClear = new[] {
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

                foreach (var cookie in cookiesToClear)
                {
                    context.HttpContext.Response.Cookies.Delete(cookie, cookieOptions);
                }

                context.HttpContext.Response.Headers["Cache-Control"] = "no-cache, no-store, must-revalidate, private, max-age=0";
                context.HttpContext.Response.Headers["Pragma"] = "no-cache";
                context.HttpContext.Response.Headers["Expires"] = "-1";

                context.Response.Redirect("/");
                context.HandleResponse();
            },
            OnAuthenticationFailed = context =>
            {
                if (context.Exception.Message.Contains("MFA"))
                {
                    context.HandleResponse();
                    context.Response.Redirect("/Home/MfaRequired");
                }
                return Task.CompletedTask;
            },
            OnTokenValidated = context =>
            {
                // Add authentication scheme to claims for user differentiation
                var identity = context.Principal.Identity as ClaimsIdentity;
                if (identity != null)
                {
                    identity.AddClaim(new Claim("auth_scheme", "DefaultScheme"));
                }
                return Task.CompletedTask;
            }
        };
    })
    .AddOpenIdConnect("App1Scheme", options => {
        // App1 Configuration
        options.Authority = "https://volvogroupextid.ciamlogin.com/volvogroupextid.onmicrosoft.com";
        options.MetadataAddress = "https://volvogroupextid.ciamlogin.com/volvogroupextid.onmicrosoft.com/v2.0/.well-known/openid-configuration";
        options.ClientId = "6bc083e2-7d23-4506-9197-9efdf15b1447"; // "YOUR_APP1_CLIENT_ID";
        options.ClientSecret = "OWB8Q~JLA_lz3elfmJfDcbzZwatK4Ul.xKedAcla"; // "YOUR_APP1_CLIENT_SECRET";
        options.CallbackPath = "/signin-oidc-app1";
        options.SignedOutCallbackPath = "/signout-callback-oidc-app1";
        options.RequireHttpsMetadata = true;
        options.UseTokenLifetime = false;
        options.SaveTokens = true;
        options.ResponseType = "code";
        options.ResponseMode = "form_post";
        options.UsePkce = true;
        options.NonceCookie.SecurePolicy = CookieSecurePolicy.Always;
        options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Prompt = "select_account";

        // Add required scopes - Basic authentication only
        options.Scope.Clear();
        options.Scope.Add("openid");
        options.Scope.Add("offline_access");
        options.Scope.Add("profile");
        options.Scope.Add("email");
        options.Scope.Add("User.Read"); // Only basic read permission

        options.Events = new OpenIdConnectEvents
        {
            OnRedirectToIdentityProvider = context =>
            {
                context.ProtocolMessage.Prompt = "login";
                context.ProtocolMessage.RedirectUri = $"{context.Request.Scheme}://{context.Request.Host}{context.Request.PathBase}/signin-oidc-app1";
                return Task.CompletedTask;
            },
            OnRedirectToIdentityProviderForSignOut = context =>
            {
                context.ProtocolMessage.PostLogoutRedirectUri = $"{context.Request.Scheme}://{context.Request.Host}{context.Request.PathBase}/signout-callback-oidc-app1";
                context.ProtocolMessage.State = Guid.NewGuid().ToString();
                return Task.CompletedTask;
            },
            OnSignedOutCallbackRedirect = async context =>
            {
                context.HttpContext.Session.Clear();
                await context.HttpContext.Session.LoadAsync();

                var cookieOptions = new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Lax,
                    Expires = DateTime.UtcNow.AddYears(-1)
                };

                var cookiesToClear = new[] {
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

                foreach (var cookie in cookiesToClear)
                {
                    context.HttpContext.Response.Cookies.Delete(cookie, cookieOptions);
                }

                context.HttpContext.Response.Headers["Cache-Control"] = "no-cache, no-store, must-revalidate, private, max-age=0";
                context.HttpContext.Response.Headers["Pragma"] = "no-cache";
                context.HttpContext.Response.Headers["Expires"] = "-1";

                context.Response.Redirect("/");
                context.HandleResponse();
            },
            OnAuthenticationFailed = context =>
            {
                if (context.Exception.Message.Contains("MFA"))
                {
                    context.HandleResponse();
                    context.Response.Redirect("/Home/MfaRequired");
                }
                return Task.CompletedTask;
            }
        };
    })
    .AddOpenIdConnect("App2Scheme", options => {
        // App2 Configuration
        options.Authority = "https://volvogroupextid.ciamlogin.com/volvogroupextid.onmicrosoft.com";
        options.MetadataAddress = "https://volvogroupextid.ciamlogin.com/volvogroupextid.onmicrosoft.com/v2.0/.well-known/openid-configuration";
        options.ClientId = "e99bf39d-2177-4950-9d40-2be7881c90dd"; // "YOUR_APP2_CLIENT_ID";
        options.ClientSecret = "BBN8Q~uvSZ2X5xHFSOSlKksv5EusR1LcolcJJbxe"; // "YOUR_APP2_CLIENT_SECRET";
        options.CallbackPath = "/signin-oidc-app2";
        options.SignedOutCallbackPath = "/signout-callback-oidc-app2";
        options.RequireHttpsMetadata = true;
        options.UseTokenLifetime = false;
        options.SaveTokens = true;
        options.ResponseType = "code";
        options.ResponseMode = "form_post";
        options.UsePkce = true;
        options.NonceCookie.SecurePolicy = CookieSecurePolicy.Always;
        options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Prompt = "select_account";

        // Add required scopes - Basic authentication only
        options.Scope.Clear();
        options.Scope.Add("openid");
        options.Scope.Add("offline_access");
        options.Scope.Add("profile");
        options.Scope.Add("email");
        options.Scope.Add("User.Read"); // Only basic read permission

        options.Events = new OpenIdConnectEvents
        {
            OnRedirectToIdentityProvider = context =>
            {
                context.ProtocolMessage.Prompt = "login";
                context.ProtocolMessage.RedirectUri = $"{context.Request.Scheme}://{context.Request.Host}{context.Request.PathBase}/signin-oidc-app2";
                return Task.CompletedTask;
            },
            OnRedirectToIdentityProviderForSignOut = context =>
            {
                context.ProtocolMessage.PostLogoutRedirectUri = $"{context.Request.Scheme}://{context.Request.Host}{context.Request.PathBase}/signout-callback-oidc-app2";
                context.ProtocolMessage.State = Guid.NewGuid().ToString();
                return Task.CompletedTask;
            },
            OnSignedOutCallbackRedirect = async context =>
            {
                context.HttpContext.Session.Clear();
                await context.HttpContext.Session.LoadAsync();

                var cookieOptions = new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Lax,
                    Expires = DateTime.UtcNow.AddYears(-1)
                };

                var cookiesToClear = new[] {
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

                foreach (var cookie in cookiesToClear)
                {
                    context.HttpContext.Response.Cookies.Delete(cookie, cookieOptions);
                }

                context.HttpContext.Response.Headers["Cache-Control"] = "no-cache, no-store, must-revalidate, private, max-age=0";
                context.HttpContext.Response.Headers["Pragma"] = "no-cache";
                context.HttpContext.Response.Headers["Expires"] = "-1";

                context.Response.Redirect("/");
                context.HandleResponse();
            },
            OnAuthenticationFailed = context =>
            {
                if (context.Exception.Message.Contains("MFA"))
                {
                    context.HandleResponse();
                    context.Response.Redirect("/Home/MfaRequired");
                }
                return Task.CompletedTask;
            },
            OnTokenValidated = context =>
            {
                // Add authentication scheme to claims for user differentiation
                var identity = context.Principal.Identity as ClaimsIdentity;
                if (identity != null)
                {
                    identity.AddClaim(new Claim("auth_scheme", "App2Scheme"));
                }
                return Task.CompletedTask;
            }
        };
    })
    .AddOpenIdConnect("App3Scheme", options => {
        // App3 Configuration
        options.Authority = "https://volvogroupextid.ciamlogin.com/volvogroupextid.onmicrosoft.com";
        options.MetadataAddress = "https://volvogroupextid.ciamlogin.com/volvogroupextid.onmicrosoft.com/v2.0/.well-known/openid-configuration";
        options.ClientId = "d1b2735a-29f9-4ab6-bb8b-fdd15550a767"; // "YOUR_APP3_CLIENT_ID";
        options.ClientSecret = "xpM8Q~Zv2v9aBoW5TlMvTL2d1iO3HhdoAF8h.crU"; // "YOUR_APP3_CLIENT_SECRET";
        options.CallbackPath = "/signin-oidc-app3";
        options.SignedOutCallbackPath = "/signout-callback-oidc-app3";
        options.RequireHttpsMetadata = true;
        options.UseTokenLifetime = false;
        options.SaveTokens = true;
        options.ResponseType = "code";
        options.ResponseMode = "form_post";
        options.UsePkce = true;
        options.NonceCookie.SecurePolicy = CookieSecurePolicy.Always;
        options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Prompt = "select_account";

        // Add required scopes - Basic authentication only
        options.Scope.Clear();
        options.Scope.Add("openid");
        options.Scope.Add("offline_access");
        options.Scope.Add("profile");
        options.Scope.Add("email");
        options.Scope.Add("User.Read"); // Only basic read permission

        options.Events = new OpenIdConnectEvents
        {
            OnRedirectToIdentityProvider = context =>
            {
                context.ProtocolMessage.Prompt = "login";
                context.ProtocolMessage.RedirectUri = $"{context.Request.Scheme}://{context.Request.Host}{context.Request.PathBase}/signin-oidc-app3";
                return Task.CompletedTask;
            },
            OnRedirectToIdentityProviderForSignOut = context =>
            {
                context.ProtocolMessage.PostLogoutRedirectUri = $"{context.Request.Scheme}://{context.Request.Host}{context.Request.PathBase}/signout-callback-oidc-app3";
                context.ProtocolMessage.State = Guid.NewGuid().ToString();
                return Task.CompletedTask;
            },
            OnSignedOutCallbackRedirect = async context =>
            {
                context.HttpContext.Session.Clear();
                await context.HttpContext.Session.LoadAsync();

                var cookieOptions = new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Lax,
                    Expires = DateTime.UtcNow.AddYears(-1)
                };

                var cookiesToClear = new[] {
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

                foreach (var cookie in cookiesToClear)
                {
                    context.HttpContext.Response.Cookies.Delete(cookie, cookieOptions);
                }

                context.HttpContext.Response.Headers["Cache-Control"] = "no-cache, no-store, must-revalidate, private, max-age=0";
                context.HttpContext.Response.Headers["Pragma"] = "no-cache";
                context.HttpContext.Response.Headers["Expires"] = "-1";

                context.Response.Redirect("/");
                context.HandleResponse();
            },
            OnAuthenticationFailed = context =>
            {
                if (context.Exception.Message.Contains("MFA"))
                {
                    context.HandleResponse();
                    context.Response.Redirect("/Home/MfaRequired");
                }
                return Task.CompletedTask;
            },
            OnTokenValidated = context =>
            {
                // Add authentication scheme to claims for user differentiation
                var identity = context.Principal.Identity as ClaimsIdentity;
                if (identity != null)
                {
                    identity.AddClaim(new Claim("auth_scheme", "App3Scheme"));
                }
                return Task.CompletedTask;
            }
        };
    });



// Add token acquisition services
builder.Services.AddScoped<ITokenAcquisition, CustomTokenAcquisition>();
builder.Services.AddMemoryCache();
builder.Services.AddHttpClient();
builder.Services.AddHttpContextAccessor();


// Add cookie policy
builder.Services.Configure<CookiePolicyOptions>(options =>
{
    options.CheckConsentNeeded = context => true;
    options.MinimumSameSitePolicy = SameSiteMode.Lax;
    options.Secure = CookieSecurePolicy.Always;
});



// Add Graph API client with custom configuration
builder.Services.AddScoped(sp =>
{
    var tokenAcquisition = sp.GetRequiredService<ITokenAcquisition>();
    var authProvider = new SimpleAuthProvider(tokenAcquisition);
    var graphClient = new GraphServiceClient(authProvider, "https://graph.microsoft.com/v1.0");

    // Configure the client
    graphClient.RequestAdapter.BaseUrl = "https://graph.microsoft.com/v1.0";

    return graphClient;
});



// Add Graph API service
// builder.Services.AddScoped<OIDCDemoApp.Services.Services.IGraphApiService, OIDCDemoApp.Services.GraphApiService>();
builder.Services.AddScoped<Ext_ID_OIDC_web_Application.Services.IGraphApiService, Ext_ID_OIDC_web_Application.Services.GraphApiService>();

// Add authorization
builder.Services.AddAuthorization(options =>
{
    options.DefaultPolicy = options.DefaultPolicy;
});



// Add HTTPS configuration
builder.WebHost.ConfigureKestrel(serverOptions =>
{
    serverOptions.ConfigureHttpsDefaults(listenOptions =>
    {
        listenOptions.SslProtocols = System.Security.Authentication.SslProtocols.Tls12;
    });
});



// Add Razor Pages (without Microsoft Identity Web UI)
builder.Services.AddRazorPages();

var app = builder.Build();

// Configure the HTTP request pipeline.
//if (!app.Environment.IsDevelopment())
//{
//    app.UseExceptionHandler("/Home/Error");
//    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
//    app.UseHsts();
//}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();



// Add session middleware
app.UseSession();


app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();



// Token acquisition interface
public interface ITokenAcquisition
{
    Task<string> GetAccessTokenForUserAsync(string[] scopes);
    Task<string> GetAccessTokenForAppAsync(string scope);
}



// Custom token acquisition service
public class CustomTokenAcquisition : ITokenAcquisition
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<CustomTokenAcquisition> _logger;

    public CustomTokenAcquisition(IHttpContextAccessor httpContextAccessor, ILogger<CustomTokenAcquisition> logger)
    {
        _httpContextAccessor = httpContextAccessor;
        _logger = logger;
    }

    public async Task<string> GetAccessTokenForUserAsync(string[] scopes)
    {
        try
        {
            var httpContext = _httpContextAccessor.HttpContext;
            if (httpContext?.User?.Identity?.IsAuthenticated != true)
            {
                throw new InvalidOperationException("User is not authenticated");
            }

            // Get the access token from the authentication result
            // Try different authentication schemes
            var accessToken = await httpContext.GetTokenAsync("access_token");
            if (string.IsNullOrEmpty(accessToken))
            {
                // Try to get from OpenID Connect tokens
                accessToken = await httpContext.GetTokenAsync("OpenIdConnect", "access_token");
            }
            if (string.IsNullOrEmpty(accessToken))
            {
                // Try DefaultScheme
                accessToken = await httpContext.GetTokenAsync("DefaultScheme", "access_token");
            }
            if (string.IsNullOrEmpty(accessToken))
            {
                // Try App1Scheme
                accessToken = await httpContext.GetTokenAsync("App1Scheme", "access_token");
            }
            if (string.IsNullOrEmpty(accessToken))
            {
                // Try App2Scheme
                accessToken = await httpContext.GetTokenAsync("App2Scheme", "access_token");
            }
            if (string.IsNullOrEmpty(accessToken))
            {
                // Try App3Scheme
                accessToken = await httpContext.GetTokenAsync("App3Scheme", "access_token");
            }

            if (string.IsNullOrEmpty(accessToken))
            {
                throw new InvalidOperationException("No access token found in authentication result");
            }

            _logger.LogInformation("Successfully retrieved access token for scopes: {Scopes}", string.Join(", ", scopes));
            return accessToken;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting access token");
            throw;
        }
    }

    public async Task<string> GetAccessTokenForAppAsync(string scope)
    {
        try
        {
            // For application permissions, we need to implement client credentials flow
            // For now, we'll use the same approach as user tokens but with different scope
            var httpContext = _httpContextAccessor.HttpContext;
            if (httpContext?.User?.Identity?.IsAuthenticated != true)
            {
                throw new InvalidOperationException("User is not authenticated");
            }

            // Get the access token from the authentication result
            // Try different authentication schemes
            var accessToken = await httpContext.GetTokenAsync("access_token");
            if (string.IsNullOrEmpty(accessToken))
            {
                // Try to get from OpenID Connect tokens
                accessToken = await httpContext.GetTokenAsync("OpenIdConnect", "access_token");
            }
            if (string.IsNullOrEmpty(accessToken))
            {
                // Try DefaultScheme
                accessToken = await httpContext.GetTokenAsync("DefaultScheme", "access_token");
            }
            if (string.IsNullOrEmpty(accessToken))
            {
                // Try App1Scheme
                accessToken = await httpContext.GetTokenAsync("App1Scheme", "access_token");
            }
            if (string.IsNullOrEmpty(accessToken))
            {
                // Try App2Scheme
                accessToken = await httpContext.GetTokenAsync("App2Scheme", "access_token");
            }
            if (string.IsNullOrEmpty(accessToken))
            {
                // Try App3Scheme
                accessToken = await httpContext.GetTokenAsync("App3Scheme", "access_token");
            }

            if (string.IsNullOrEmpty(accessToken))
            {
                throw new InvalidOperationException("No access token found in authentication result");
            }

            _logger.LogInformation("Successfully retrieved application access token for scope: {Scope}", scope);
            return accessToken;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting application access token");
            throw;
        }
    }
}



// Simple authentication provider for Graph API
public class SimpleAuthProvider : IAuthenticationProvider
{
    private readonly ITokenAcquisition _tokenAcquisition;

    public SimpleAuthProvider(ITokenAcquisition tokenAcquisition)
    {
        _tokenAcquisition = tokenAcquisition;
    }

    public async Task AuthenticateRequestAsync(RequestInformation request, Dictionary<string, object>? additionalAuthenticationContext = null, CancellationToken cancellationToken = default)
    {
        try
        {
            // Get the access token for Graph API operations with all required permissions
            var token = await _tokenAcquisition.GetAccessTokenForUserAsync(new[] {
                "User.Read",
                "User.ReadWrite.All",
                "User.ReadBasic.All",
                "Directory.AccessAsUser.All",
                "AuthenticationMethod.Read.All",
                "User.RevokeSessions.All"
            });

            request.Headers.Add("Authorization", $"Bearer {token}");
            request.Headers.Add("Content-Type", "application/json");
        }
        catch (Exception ex)
        {
            throw new Exception("Failed to get access token", ex);
        }
    }
}
