// 
// POST {AZURE_FUNCTIONS_URL} 
// Headers:
//  Authorization: SharedAccessSignature sr={resourceUri}&sig={base64Signed}&se={expiryTime}
// 
// Security token fields:
// sr={IOTEDGE_IOTHUBHOSTNAME}/devices/{IOTEDGE_DEVICEID}/modules/{IOTEDGE_MODULEID}/methods/{METHOD_NAME}
// se=epoch + 30 minutes
// sig=sign(System.Web.HttpUtility.UrlEncode(sr) + "\n" + se)
// 

namespace authenticator
{
    using System;
    using System.IO;
    using System.Net;
    using System.Net.Http;
    using System.Net.Sockets;
    using System.Runtime.InteropServices;
    using System.Runtime.Loader;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.Azure.Devices.Client;
    using Microsoft.Azure.Devices.Client.Transport.Mqtt;
    using Microsoft.Azure.Devices.Shared;

    class Program
    {
        static void Main(string[] args)
        {
            Init().Wait();

            // Wait until the app unloads or is cancelled
            var cts = new CancellationTokenSource();
            AssemblyLoadContext.Default.Unloading += (ctx) => cts.Cancel();
            Console.CancelKeyPress += (sender, cpe) => cts.Cancel();
            WhenCancelled(cts.Token).Wait();
        }

        /// <summary>
        /// Handles cleanup operations when app is cancelled or unloads
        /// </summary>
        public static Task WhenCancelled(CancellationToken cancellationToken)
        {
            var tcs = new TaskCompletionSource<bool>();
            cancellationToken.Register(s => ((TaskCompletionSource<bool>)s).SetResult(true), tcs);
            return tcs.Task;
        }

        /// <summary>
        /// Initializes the ModuleClient and sets up the callback to receive
        /// messages containing temperature information
        /// </summary>
        static async Task Init()
        {
            AmqpTransportSettings amqpSetting = new AmqpTransportSettings(TransportType.Amqp_Tcp_Only);
            ITransportSettings[] settings = { amqpSetting };

            ModuleClient ioTHubModuleClient = await ModuleClient.CreateFromEnvironmentAsync(settings);
            await ioTHubModuleClient.OpenAsync();
            Console.WriteLine($"{DateTime.UtcNow.ToString()}: IoT Hub module client initialized.");

            await ioTHubModuleClient.SetDesiredPropertyUpdateCallbackAsync(desiredPropertyUpdateHandler, ioTHubModuleClient);
            Console.WriteLine($"{DateTime.UtcNow.ToString()}: Set DesiredPropertyUpdate Callback done.");
        }

        private static async Task desiredPropertyUpdateHandler(TwinCollection desiredProperties, object userContext)
        {
            if (desiredProperties.Contains("update"))
            {
                Console.WriteLine($"{DateTime.UtcNow.ToString()}: Update triggered");

                string METHOD_NAME = "update";

                //Retrieving needed Environment Variables
                string IOTEDGE_IOTHUBHOSTNAME = Environment.GetEnvironmentVariable("IOTEDGE_IOTHUBHOSTNAME");
                string IOTEDGE_DEVICEID = Environment.GetEnvironmentVariable("IOTEDGE_DEVICEID");
                string IOTEDGE_MODULEID = Environment.GetEnvironmentVariable("IOTEDGE_MODULEID");
                string AZURE_FUNCTIONS_URL = Environment.GetEnvironmentVariable("AZURE_FUNCTIONS_URL");

                //Calculating expiry time
                int sinceEpoch = (int)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
                int thirtyMinutesInSeconds = 60 * 30;
                string expiryTime = Convert.ToString(sinceEpoch + thirtyMinutesInSeconds);

                string resourceUri = $"{IOTEDGE_IOTHUBHOSTNAME}/devices/{IOTEDGE_DEVICEID}/modules/{IOTEDGE_MODULEID}/methods/{METHOD_NAME}";
                string toSign = System.Web.HttpUtility.UrlEncode(resourceUri) + "\n" + expiryTime;
                string base64toSign = Convert.ToBase64String(Encoding.UTF8.GetBytes(toSign));

                //Retrieving the HMACSHA256 digest of the string to sign
                string base64Signed = await Signer(base64toSign);

                if (!string.IsNullOrEmpty(base64Signed))
                {
                    string sigForURLEncoding = base64Signed.TrimEnd('=').Replace('+', '-').Replace('/', '_');
                    string authHeader = $"SharedAccessSignature sr={resourceUri}&sig={sigForURLEncoding}&se={expiryTime}";
                    authHeader = WebUtility.UrlEncode(authHeader);

                    using (HttpClient client = new HttpClient())
                    {
                        client.DefaultRequestHeaders.TryAddWithoutValidation("Authorization", authHeader);

                        var resp = await client.PostAsync(AZURE_FUNCTIONS_URL, new StringContent("PostBody", Encoding.UTF8));

                        if (resp.StatusCode == HttpStatusCode.OK)
                        {
                            //Do something smarter with the response from the function
                            Console.WriteLine($"{DateTime.UtcNow.ToString()}: {await resp.Content.ReadAsStringAsync()}");
                            var moduleClient = userContext as ModuleClient;
                            await moduleClient.SendEventAsync("propertyhandleroutput", new Message(await resp.Content.ReadAsByteArrayAsync()));
                        }else{
                            Console.WriteLine($"{DateTime.UtcNow.ToString()}: {resp.StatusCode}");
                        }
                    }
                }
            }
        }


        static async Task<string> Signer(string base64String)
        {
            if (string.IsNullOrEmpty(base64String))
            {
                return null;
            }
            try
            {
                string IOTEDGE_MODULEID = Environment.GetEnvironmentVariable("IOTEDGE_MODULEID");
                string IOTEDGE_MODULEGENERATIONID = Environment.GetEnvironmentVariable("IOTEDGE_MODULEGENERATIONID");
                string IOTEDGE_WORKLOADURI = Environment.GetEnvironmentVariable("IOTEDGE_WORKLOADURI").Replace("unix://", "");

                UnixEndPoint unixEndpoint = new UnixEndPoint(IOTEDGE_WORKLOADURI);
                Socket unixSocket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.IP);
                unixSocket.Connect(unixEndpoint);


                string httpRequestURI = $"http://localhost/modules/{IOTEDGE_MODULEID}/genid/{IOTEDGE_MODULEGENERATIONID}/sign?api-version=2018-06-28";
                string requestContent = "{\"keyId\": \"primary\", \"algo\": \"HMACSHA256\", \"data\": \"" + base64String + "\"}";
                HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, httpRequestURI);
                request.Content = new StringContent(requestContent, Encoding.UTF8, "application/json");

                HttpRequestResponseSerializer serializer = new HttpRequestResponseSerializer();
                byte[] requestBytes = serializer.SerializeRequest(request);

                HttpBufferedStream stream = new HttpBufferedStream(new NetworkStream(unixSocket, true));
                await stream.WriteAsync(requestBytes, 0, requestBytes.Length, CancellationToken.None).ConfigureAwait(false);
                if (request.Content != null)
                {
                    await request.Content.CopyToAsync(stream).ConfigureAwait(false);
                }

                HttpResponseMessage response = await serializer.DeserializeResponse(stream, CancellationToken.None).ConfigureAwait(false);

                string responseString = await response.Content.ReadAsStringAsync();
                var responseObject = Newtonsoft.Json.Linq.JObject.Parse(responseString);

                return responseObject.Value<string>("digest");
            }
            catch (System.Exception ex)
            {
                Console.WriteLine(ex.Message);
                return null;
            }
        }
    }
}
