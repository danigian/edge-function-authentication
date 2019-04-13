using Microsoft.Azure.Devices;
using Microsoft.Azure.Management.Fluent;
using Microsoft.Azure.Management.IotHub;
using Microsoft.Azure.Management.ResourceManager.Fluent;
using Microsoft.Azure.Management.ResourceManager.Fluent.Authentication;
using Microsoft.Azure.Management.ResourceManager.Fluent.Core;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Rest;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Linq;

namespace functionSolution
{
    class Helpers
    {
        public async Task<string> GetModulePrimaryKey(RequestedResource sr)
        {
            var credentials = SdkContext.AzureCredentialsFactory.FromMSI(new MSILoginInformation(MSIResourceType.AppService), 
                                                                         AzureEnvironment.AzureGlobalCloud);
            var azure = Azure
                .Configure()
                .WithLogLevel(HttpLoggingDelegatingHandler.Level.Basic)
                .Authenticate(credentials)
                .WithDefaultSubscription();

            string iothubowner = string.Empty;
            
            var azureServiceTokenProvider = new AzureServiceTokenProvider();
            string accessToken = await azureServiceTokenProvider.GetAccessTokenAsync("https://management.azure.com");

            IotHubClient hubClient = new IotHubClient(new TokenCredentials(accessToken))
            {
                SubscriptionId = azure.GetCurrentSubscription().SubscriptionId
            };
            var listHubs = await hubClient.IotHubResource.ListBySubscriptionAsync();

            do
            {
                var hub = listHubs.Where(iothub => string.Equals(iothub.Name, sr.iotHubName)).FirstOrDefault();
                if (!string.IsNullOrEmpty(hub.Id))
                {
                    iothubowner = (await hubClient.IotHubResource.GetKeysForKeyNameAsync(GetResourceGroupName(hub.Id), hub.Name, "iothubowner")).PrimaryKey;
                    break;
                }
            } while (!string.IsNullOrEmpty(listHubs.NextPageLink));

            if (string.IsNullOrEmpty(iothubowner))
            {
                throw new Exception("Failed to retrieve IoT Hub Primary Key string");
            }

            string iotHubConnString = IotHubConnectionStringBuilder.Create(sr.iotHubFQDN, new ServiceAuthenticationWithSharedAccessPolicyKey("iothubowner", iothubowner)).ToString();

            RegistryManager registryManager = RegistryManager.CreateFromConnectionString(iotHubConnString);

            var modulesOnDevice = await registryManager.GetModuleAsync(sr.deviceId, sr.moduleId);

            return !string.IsNullOrEmpty(modulesOnDevice.Authentication.SymmetricKey.PrimaryKey) ? modulesOnDevice.Authentication.SymmetricKey.PrimaryKey : null;
        }

        public string GetResourceGroupName(string resourceId)
        {
            string resourceIdRegex = @"\/subscriptions\/(?<SUBSCRIPTIONID>[\d\D]+)\/resourceGroups\/(?<RGNAME>[\d\D]+)\/providers\/Microsoft.Devices\/IotHubs\/(?<HUBNAME>[\d\D]+)";
            var match = Regex.Match(resourceId, resourceIdRegex);
            if (match.Success)
            {
                return match.Groups["RGNAME"].Value;
            }
            else
            {
                throw new FormatException("A different format was expected for \"resourceId\" field");
            }
        }
    }
}
