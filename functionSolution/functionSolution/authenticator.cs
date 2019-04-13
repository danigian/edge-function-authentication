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

namespace functionSolution
{
    public class Authenticator
    {
        [FunctionName("Authenticator")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            log.LogInformation($"{DateTime.UtcNow.ToString()}: function started");
            Helpers _helpers = new Helpers();
            
            StringValues authorizationString;
            if (!req.Headers.TryGetValue("Authorization", out authorizationString))
            {
                return new BadRequestResult();
            }

            AuthorizationHeaderHandler authHeader = new AuthorizationHeaderHandler(authorizationString);

            string primaryKey = await _helpers.GetModulePrimaryKey(authHeader.requestedResource);

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
    }
}
