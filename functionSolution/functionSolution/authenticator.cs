using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Microsoft.Extensions.Primitives;
using Microsoft.Azure.Devices;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace functionSolution
{
    public static class Authenticator
    {
        [FunctionName("Authenticator")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            log.LogInformation($"{DateTime.UtcNow.ToString()}: function started");

            StringValues authorizationString;
            if (!req.Headers.TryGetValue("Authorization", out authorizationString))
            {
                return new BadRequestResult();
            }

            AuthorizationHeaderHandler authHeader = AuthorizationHeaderHandler.CreateFromReceivedHeader(authorizationString);

            string primaryKey = await GetModulePrimaryKey(authHeader.requestedResource);

            if (!string.IsNullOrEmpty(primaryKey) && authHeader.IsValid(primaryKey, log))
            {
                log.LogInformation($"{DateTime.Now.ToString()}: successfully checked identity and integrity of message received from {authHeader.requestedResource.deviceId}");
                return new JsonResult($"Request authorized for method {authHeader.requestedResource.method} for device {authHeader.requestedResource.deviceId}");
            }
            else
            {
                log.LogInformation($"{DateTime.Now.ToString()}: returned unauthorized for {authHeader.requestedResource.deviceId}");
                return new UnauthorizedResult();
            }
        }

        private static async Task<string> GetModulePrimaryKey(RequestedResource sr)
        {
            //IoT Hub connection string should be retrieved from an environment variable named as the IoT Hub Hostname itself
            string iotHubConnString = Environment.GetEnvironmentVariable(sr.iotHubHostname);
            RegistryManager registryManager = RegistryManager.CreateFromConnectionString(iotHubConnString);

            var modulesOnDevice = await registryManager.GetModuleAsync(sr.deviceId, sr.moduleId);

            return !string.IsNullOrEmpty(modulesOnDevice.Authentication.SymmetricKey.PrimaryKey) ? modulesOnDevice.Authentication.SymmetricKey.PrimaryKey : null;
        }
    }

    public class AuthorizationHeaderHandler
    {
        public RequestedResource requestedResource { get; private set; }
        public string expiry { get; private set; }
        public string signature { get; private set; }

        private AuthorizationHeaderHandler(RequestedResource sr, string se, string sig)
        {
            requestedResource = sr;
            expiry = se;
            signature = sig;
        }

        public static AuthorizationHeaderHandler CreateFromReceivedHeader(string receivedHeader)
        {
            try
            {
                receivedHeader = System.Net.WebUtility.UrlDecode(receivedHeader);
                IDictionary<string, string> parsedFields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                string[] fields = receivedHeader.Replace("SharedAccessSignature ", "").Trim().Split("&", StringSplitOptions.None);

                foreach (string field in fields)
                {
                    if (field != string.Empty)
                    {
                        string[] fieldParts = field.Split("=", StringSplitOptions.None);
                        if (fieldParts[0].Equals("sig"))
                        {
                            //Replace switched characters and properly pad the base64 signature
                            fieldParts[1] = fieldParts[1].Replace('-', '+').Replace('_', '/');
                            if (fieldParts[1].Length % 4 == 2) fieldParts[1] += "==";
                            else if (fieldParts[1].Length % 4 == 3) fieldParts[1] += "=";
                        }
                        parsedFields.Add(fieldParts[0], fieldParts[1]);
                    }
                }
                return new AuthorizationHeaderHandler(new RequestedResource(parsedFields["sr"]), parsedFields["se"], parsedFields["sig"]);
            }
            catch (Exception)
            {
                throw new Exception("Invalid header received");
            }
        }



        public bool IsValid(string key, ILogger log)
        {
            //are the fields properly populated?
            if (string.IsNullOrEmpty(this.expiry) || this.requestedResource == null || string.IsNullOrEmpty(this.signature) || string.IsNullOrEmpty(key))
            {
                log.LogInformation("badrequest");
                return false;
            }

            //is request expired?
            double expiryDouble;
            if (double.TryParse(this.expiry, out expiryDouble))
            {
                if (expiryDouble < (DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds)
                {
                    log.LogInformation("expired");
                    return false;
                }
            }
            else
            {
                log.LogInformation("error parsing");
                return false;
            }

            string stringToSign = System.Web.HttpUtility.UrlEncode(this.requestedResource.ToString()) + "\n" + this.expiry;

            System.Security.Cryptography.HMACSHA256 hmac = new System.Security.Cryptography.HMACSHA256(Convert.FromBase64String(key));
            string computedSignature = Convert.ToBase64String(hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(stringToSign)));

            return string.Equals(this.signature, computedSignature);
        }
    }

    public class RequestedResource
    {
        private readonly string requestedResourceRegex = @"(?<IOTHUBHOSTNAME>[\d\D]+)\/devices\/(?<DEVICEID>[\d\D]+)\/modules\/(?<MODULEID>[\d\D]+)\/methods\/(?<METHOD>[\d\D]+)";

        public string iotHubHostname { get; private set; }
        public string deviceId { get; private set; }
        public string moduleId { get; private set; }
        public string method { get; private set; }

        public RequestedResource(string sr)
        {
            var match = Regex.Match(sr, requestedResourceRegex);
            if (match.Success)
            {
                iotHubHostname = match.Groups["IOTHUBHOSTNAME"].Value;
                deviceId = match.Groups["DEVICEID"].Value;
                moduleId = match.Groups["MODULEID"].Value;
                method = match.Groups["METHOD"].Value;
            }
            else
            {
                throw new FormatException("A different format was expected for \"sr\" field");
            }
        }

        public override string ToString()
        {
            return string.Format("{0}/devices/{1}/modules/{2}/methods/{3}", iotHubHostname, deviceId, moduleId, method);
        }
    }


}
