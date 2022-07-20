using Newtonsoft.Json.Linq;
using Microsoft.Owin;
using Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.Configuration;
using System.Security.Claims;
using IdentityModel.Client;
using System.Collections.Generic;
using System.Net.Http;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin.Security.Notifications;
using PingOne_Sample.Models;
using System.Net.Http.Headers;

[assembly: OwinStartup(typeof(PingOne_Sample.Startup))]

namespace PingOne_Sample
{
    public class Startup
    {
        private readonly string _clientId = ConfigurationManager.AppSettings["ClientId"];
        private readonly string _redirectUri = ConfigurationManager.AppSettings["RedirectPath"];
        private readonly string _environmentId = ConfigurationManager.AppSettings["EnvironmentId"];
        private readonly string _authority = $"{ConfigurationManager.AppSettings["AuthBaseUrl"]}/{ConfigurationManager.AppSettings["EnvironmentId"]}/as";
        private readonly string _clientSecret = ConfigurationManager.AppSettings["ClientSecret"];
        private readonly string _postLogoutRedirectUri = ConfigurationManager.AppSettings["PostSignOffRedirectUrl"];

        public void Configuration(IAppBuilder app)
        {
            // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=316888
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);
            app.UseCookieAuthentication(new CookieAuthenticationOptions());

            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                ClientId = _clientId,
                ClientSecret = _clientSecret,
                UsePkce = false,
                Authority = _authority,
                RedirectUri = _redirectUri,
                ResponseType = OpenIdConnectResponseType.Code,
                Scope = OpenIdConnectScope.OpenIdProfile,
                PostLogoutRedirectUri = _postLogoutRedirectUri,
                SaveTokens = true,
                
                //TokenValidationParameters = new TokenValidationParameters
                //{
                //    NameClaimType = "name",
                //    ValidateIssuer = false,
                //},
                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    SecurityTokenValidated = notification =>
                    {
                        var accessToken = notification.ProtocolMessage.AccessToken;

                        // call the "userinfo" API
                        UserInfo userResponse;
                        using (HttpClient _httpClient = new HttpClient())
                        {
                            _httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {accessToken}");
                            var response = _httpClient.PostAsync(_authority + "/userinfo", null).Result;
                            userResponse = response.Content.ReadAsAsync<UserInfo>().Result;
                        }

                        var claims = new List<Claim>
                        {
                            new Claim("given_name", userResponse.GivenName),
                            new Claim("family_name", userResponse.FamilyName),
                            new Claim("preferred_username", userResponse.PreferredUsername),
                            new Claim("id_token", notification.ProtocolMessage.IdToken),
                            new Claim("access_token", accessToken),
                            new Claim("Sub", userResponse.Sub),
                            new Claim("Env", userResponse.Env)
                        };

                        notification.AuthenticationTicket.Identity.AddClaims(claims);
                        return Task.FromResult(0);
                    },
                    AuthorizationCodeReceived = async paramCode =>
                    {
                        //var tokenClient = new TokenClient(_authority + "/token", _clientId, _clientSecret);

                        //var tokenResp = await tokenClient.RequestAuthorizationCodeAsync(paramCode.Code, _redirectUri);
                        //if (tokenResp.IsError)
                        //{
                        //    throw new Exception(tokenResp.Error);
                        //}

                        AuthenticationData tokenObject = null;
                        var tokenResponse = string.Empty;
                        using (HttpClient _httpClient = new HttpClient())
                        {
                            var postData = new List<KeyValuePair<string, string>>
                            {
                                new KeyValuePair<string, string>("grant_type", "authorization_code"),
                                new KeyValuePair<string, string>("client_id", _clientId),
                                new KeyValuePair<string, string>("client_secret", _clientSecret),
                                new KeyValuePair<string, string>("code", paramCode.Code),
                                new KeyValuePair<string, string>("redirect_uri", _redirectUri)
                            };

                            var content = new FormUrlEncodedContent(postData);
                            content.Headers.Clear();
                            content.Headers.Add("Content-Type", "application/x-www-form-urlencoded");
                            var response = _httpClient.PostAsync(_authority + "/token", content).Result;
                            
                            tokenResponse = response.Content.ReadAsStringAsync().Result;
                            tokenObject = JObject.Parse(tokenResponse).ToObject<AuthenticationData>();
                        }

                        //call the "introspect" API
                        TokenIntrospect introspectResp;
                        using (HttpClient _httpClient = new HttpClient())
                        {
                            var postData = new List<KeyValuePair<string, string>>
                            {
                                new KeyValuePair<string, string>("token", tokenObject.AccessToken),
                                new KeyValuePair<string, string>("client_id", _clientId),
                                new KeyValuePair<string, string>("client_secret", _clientSecret)
                            };

                            var content = new FormUrlEncodedContent(postData);
                            content.Headers.Clear();
                            content.Headers.Add("Content-Type", "application/x-www-form-urlencoded");
                            var response = _httpClient.PostAsync(_authority + "/introspect", content).Result;
                            introspectResp = response.Content.ReadAsAsync<TokenIntrospect>().Result;
                        }

                        OpenIdConnectMessage message = new OpenIdConnectMessage(tokenResponse)
                        {
                            ClientId = _clientId,
                            ClientSecret = _clientSecret,
                            Code = paramCode.Code,
                            PostLogoutRedirectUri = _postLogoutRedirectUri,
                            RedirectUri = _redirectUri,
                            Iss = introspectResp.iss,
                            TokenType = introspectResp.TokenType,
                            Sid = introspectResp.sid,
                        };

                        paramCode.HandleCodeRedemption(message);
                        //paramCode.OwinContext.Authentication.User.Claims = claims;

                        return;
                    },

                    RedirectToIdentityProvider = paramCode =>
                    {
                        if (paramCode.ProtocolMessage.RequestType == OpenIdConnectRequestType.Logout)
                        {
                            var logoutUri = $"https://auth.pingone.com/{_environmentId}/as/signoff";
                            paramCode.Response.Redirect(logoutUri);
                            paramCode.HandleResponse();
                        }

                        return Task.CompletedTask;
                    }
                }
            });
        }
    }
}
