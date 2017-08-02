// Microsoft Azure Data Catalog team sample, import asset relationship in batch

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Clients.ActiveDirectory; // Install-Package Microsoft.IdentityModel.Clients.ActiveDirectory

namespace Bulk_Import_Relationship
{
    class Program
    {
        // TODO: Replace the Client ID placeholder with a client ID authorized to access your Azure Active Directory
        // To learn how to register a client app and get a Client ID, see https://msdn.microsoft.com/library/azure/mt403303.aspx
        private const string ClientIdFromAzureAppRegistration = "PLACEHOLDER";

        private static string _relationshipFileName;
        static AuthenticationResult _authResult;
        private const string AdcApi_BaseUrl = "https://api.azuredatacatalog.com/catalogs/DefaultCatalog";
        private const string AdcApi_Resource_JoinRelationship = "relationships/join";
        private const string AdcApi_Version_PublicV1 = "2016-03-30";
        private const string AdcApi_Version_Relationships = "2017-06-30-Preview";
        private const string UriPathSeparator = "/";

        static void Main()
        {
            while (true)
            {
                Console.WriteLine("Please specify relationship file name:");
                _relationshipFileName = Console.ReadLine();

                if (!File.Exists(_relationshipFileName))
                {
                    Console.WriteLine("{0} doesn't exist...", _relationshipFileName);
                }
                else
                {
                    break;
                }
            }

            using (var reader = new StreamReader(_relationshipFileName))
            {
                while (!reader.EndOfStream)
                {
                    string line = reader.ReadLine();
                    string[] values = line.Split(','); // Columns in the CSV file are separated by comma

                    string sourceAsset = values[0];
                    if (!sourceAsset.StartsWith("https"))
                    {
                        continue;
                    }
                    string destAsset = values[1];
                    string sourceColumns = values[2];
                    string destColumns = values[3];
                    string relationType = values[4];
                    string relationName = values[5];

                    if (!ValidateAssetColumns(sourceAsset, sourceColumns) &&
                        !ValidateAssetColumns(destAsset, destColumns))
                    {
                        Console.WriteLine("Invalid input, abort...");
                        return;
                    }
                    
                    string payload = GetRelationshipPayload(sourceAsset, destAsset, sourceColumns, destColumns,
                        relationType, relationName);
                    PublishToCatalog(AdcApi_Resource_JoinRelationship, payload, AdcApi_Version_Relationships);
                }
            }
        }

        private const string RelationshipPayloadTemplate = @"
{{
  ""properties"" : {{
    ""relationshipType"": ""{0}"",
    ""fromAssetId"": ""{1}"",
    ""toAssetId"": ""{2}"",
    ""mappings"": [
      {{
        ""mapId"": ""{3}"",
        ""mapFrom"": [{4}],
        ""mapTo"": [{5}]
      }}
    ],
    ""lastRegisteredBy"": {{
      ""upn"": ""{6}"",
      ""firstName"": ""{7}"",
      ""lastName"": ""{8}""
    }}
  }}
}}
";
        private static string GetRelationshipPayload(string sourceAsset, string destAsset, string sourceColumns,
            string destColumns, string relationType, string relationName)
        {
            return string.Format(RelationshipPayloadTemplate, relationType, sourceAsset, destAsset, relationName,
                string.Join(",", sourceColumns.Split('|').Select(s => "\"" + s + "\"")),
                string.Join(",", destColumns.Split('|').Select(s => "\"" + s + "\"")),
                AccessToken().Result.UserInfo.DisplayableId,
                AccessToken().Result.UserInfo.GivenName,
                AccessToken().Result.UserInfo.FamilyName);
        }

        private static bool ValidateAssetColumns(string asset, string columns = null)
        {
            HttpWebResponse response = GetFromCatalog(asset);
            if (response.StatusCode == HttpStatusCode.NotFound)
            {
                Console.WriteLine("Asset {0} doesn't exist...", asset);
                return false;
            }

            if (columns != null)
            {
                string content;
                using (Stream responseStream = response.GetResponseStream())
                {
                    using (TextReader reader = new StreamReader(responseStream))
                    {
                        content = reader.ReadToEnd();
                    }
                }
                
                foreach (string col in columns.Split('|')) // Table columns are separated by vertical bar
                {
                    string pat = @"annotations.+schema.+properties.+columns.+name.+" + col;
                    Regex r = new Regex(pat, RegexOptions.IgnoreCase);
                    Match m = r.Match(content);
                    if (!m.Success)
                    {
                        Console.WriteLine("Column {0} doesn't exist in asset {1}", col, asset);
                        return false;
                    }
                }
            }

            return true;
        }
        
        private static string PublishToCatalog(string resourceId, string payload, string apiVersion = AdcApi_Version_PublicV1)
        {
            string address = string.Join(UriPathSeparator, AdcApi_BaseUrl, resourceId);

            IDictionary<string, string> queryParameters = new Dictionary<string, string>();
            AddApiVersion(queryParameters, apiVersion);

            IDictionary<string, string> headers = new Dictionary<string, string>();
            AddAuthorizationHeader(headers);

            string publishedLocation;
            using (HttpWebResponse response = SendRequest("POST", address, queryParameters, headers, payload))
            {
                publishedLocation = response.Headers["Location"];
            }
            return publishedLocation;
        }

        private static HttpWebResponse GetFromCatalog(string address, string apiVersion = AdcApi_Version_PublicV1, IDictionary<string, string> queryParameters = null)
        {
            if (queryParameters == null)
            {
                queryParameters = new Dictionary<string, string>();
            }
            AddApiVersion(queryParameters, apiVersion);

            IDictionary<string, string> headers = new Dictionary<string, string>();
            AddAuthorizationHeader(headers);

            HttpWebResponse response = SendRequest("GET", address, queryParameters, headers);
            return response;
        }

        private static HttpWebResponse SendRequest(string verb, string address, IDictionary<string, string> queryParameters, IDictionary<string, string> headers, string requestBody = null)
        {
            UriBuilder uri = new UriBuilder(address);
            uri.Scheme = Uri.UriSchemeHttps;
            if (queryParameters != null)
            {
                uri.Query = string.Join("&",
                    queryParameters.Select(item => string.Format("{0}={1}", WebUtility.UrlEncode(item.Key), WebUtility.UrlEncode(item.Value))));
            }

            HttpWebRequest request = WebRequest.CreateHttp(uri.ToString());
            request.Method = verb;
            if (headers != null)
            {
                foreach (var entry in headers)
                {
                    request.Headers[entry.Key] = entry.Value;
                }
            }

            if (!string.IsNullOrEmpty(requestBody))
            {
                byte[] content = Encoding.UTF8.GetBytes(requestBody);
                request.ContentLength = content.Length;
                request.ContentType = "application/json";

                using (Stream requestStream = request.GetRequestStream())
                {
                    requestStream.Write(content, 0, content.Length);
                }
            }

            try
            {
                return (HttpWebResponse)request.GetResponse();
            }
            catch (WebException ex)
            {
                var response = (HttpWebResponse) ex.Response;
                if (response.StatusCode == HttpStatusCode.NotFound)
                {
                    return response;
                }

                string content;
                using (Stream responseStream = ex.Response.GetResponseStream())
                using (TextReader reader = new StreamReader(responseStream))
                {
                    content = reader.ReadToEnd();
                }
                Console.Error.WriteLine(content);
                throw;
            }
        }

        private static void AddApiVersion(IDictionary<string, string> queryParameters, string apiVersion)
        {
            const string QueryParameter_ApiVersion = "api-version";

            queryParameters[QueryParameter_ApiVersion] = apiVersion;
        }

        private static void AddAuthorizationHeader(IDictionary<string, string> headers)
        {
            const string Header_Authorization = "Authorization";

            AuthenticationResult token = AccessToken().Result;
            headers[Header_Authorization] = token.CreateAuthorizationHeader();
        }

        // Get access token:
        // To call a Data Catalog REST operation, create an instance of AuthenticationContext and call AcquireToken
        // AuthenticationContext is part of the Active Directory Authentication Library NuGet package
        // To install the Active Directory Authentication Library NuGet package in Visual Studio, 
        // run "Install-Package Microsoft.IdentityModel.Clients.ActiveDirectory" from the NuGet Package Manager Console.
        static async Task<AuthenticationResult> AccessToken()
        {
            if (_authResult == null)
            {
                // Resource Uri for Data Catalog API
                string resourceUri = "https://api.azuredatacatalog.com";

                // To learn how to register a client app and get a Client ID, see https://msdn.microsoft.com/en-us/library/azure/mt403303.aspx#clientID   
                string clientId = ClientIdFromAzureAppRegistration;

                // A redirect uri gives AAD more details about the specific application that it will authenticate.
                // Since a client app does not have an external service to redirect to, this Uri is the standard placeholder for a client app.
                string redirectUri = "https://login.live.com/oauth20_desktop.srf";

                // Create an instance of AuthenticationContext to acquire an Azure access token
                // OAuth2 authority Uri
                string authorityUri = "https://login.windows.net/common/oauth2/authorize";
                AuthenticationContext authContext = new AuthenticationContext(authorityUri);

                // Call AcquireToken to get an Azure token from Azure Active Directory token issuance endpoint
                // AcquireToken takes a Client Id that Azure AD creates when you register your client app.
                _authResult = await authContext.AcquireTokenAsync(resourceUri, clientId, new Uri(redirectUri), new PlatformParameters(PromptBehavior.Always));
            }

            return _authResult;
        }
    }
}
