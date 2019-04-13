using System;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;

namespace functionSolution
{
    public class AuthorizationHeaderHandler
    {
        public RequestedResource requestedResource { get; private set; }
        public string expiry { get; private set; }
        public string signature { get; private set; }
        public AuthorizationHeaderHandler(string receivedHeader)
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
                requestedResource = new RequestedResource(parsedFields["sr"]);
                expiry = parsedFields["se"];
                signature = parsedFields["sig"];
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


}
