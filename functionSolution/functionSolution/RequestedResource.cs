using System;
using System.Text.RegularExpressions;

namespace functionSolution
{
    public class RequestedResource
    {
        private readonly string requestedResourceRegex = @"(?<IOTHUBHOSTNAME>[\d\D]+)\/devices\/(?<DEVICEID>[\d\D]+)\/modules\/(?<MODULEID>[\d\D]+)\/methods\/(?<METHOD>[\d\D]+)";

        public string iotHubFQDN { get; private set; }
        public string iotHubName { get; private set; }
        public string deviceId { get; private set; }
        public string moduleId { get; private set; }
        public string method { get; private set; }

        public RequestedResource(string sr)
        {
            var match = Regex.Match(sr, requestedResourceRegex);
            if (match.Success)
            {
                iotHubFQDN = match.Groups["IOTHUBHOSTNAME"].Value;
                deviceId = match.Groups["DEVICEID"].Value;
                moduleId = match.Groups["MODULEID"].Value;
                method = match.Groups["METHOD"].Value;
                iotHubName = iotHubFQDN.Split('.')[0];
            }
            else
            {
                throw new FormatException("A different format was expected for \"sr\" field");
            }
        }

        public override string ToString()
        {
            return string.Format("{0}/devices/{1}/modules/{2}/methods/{3}", iotHubFQDN, deviceId, moduleId, method);
        }
    }


}
