# Authenticate Edge Module calls to Azure Functions

Imagine a scenario in which you need to trigger a [firmware update to your Edge Device](https://docs.microsoft.com/en-us/azure/iot-hub/tutorial-firmware-update#start-the-firmware-update). 
To accomplish this, if you want to have private access to your firmware repository, you may send a [temporary, short-term expiring, storage resource url](https://docs.microsoft.com/en-us/azure/storage/common/storage-dotnet-shared-access-signature-part-1) to your IoT Edge device, via a change in Desired Properties of your module twin.

Let's say that your device will be offline for hours, before receiving the desired twin change and triggering the firmware update. 

What if, when the device gets back online, the previously set token ***has expired***? You would not be able to download the firmware.

Of course, instead of injecting a storage URL you could just call an Azure Function to retrieve the Storage URL (with Shared Access Signature) and go on with the firmware update process. How to authenticate this call? How to make sure that this is an authenticated and authorized call?

Of course, this is not the only scenario covered here: it's up to your imagination what you could achieve with this kind of authentication.

---

The idea behind the repository is to reuse the [security tokens logic behind IoT Hub itself](https://docs.microsoft.com/en-us/azure/iot-hub/iot-hub-devguide-security#security-tokens): a IoT Edge Device could create a SharedAccessSignature and use it to let an Azure Functions verify data integrity and authentication of incoming HTTP requests from the Edge Device itself.

Given this, the sample uses a SharedAccessSignature like the following

    SharedAccessSignature sr={resourceUri}&sig={signature}&se={expiryTime}

where

    resourceUri = {IoTHubHostname}/devices/{DeviceID}/modules/{ModuleID}/methods/{MethodName}
    expiryTime = epoch + 30 minutes
    signature = HMACSHA256 Signature of (UrlEncode(sr) + "\n" + se)

This GitHub repository contains two projects:

- **edgeSolution**: IoT Edge Solution with the required logic to react to a Desired Property change in Twin. If something changes, the module will:
  - Create a SharedAccessSignature with the signature being provided by [Workload API](https://github.com/Azure/iotedge/blob/master/edgelet/api/workloadVersion_2018_06_28.yaml) from IoT Edge
  - Call an Azure Function, properly setting the Authorization header to be the previously created SharedAccessSignature. (***you need to set the AZURE_FUNCTIONS_URL environment variable in the deployment.template.json file***)
  - Forward to module *propertyhandleroutput* the response received from the Azure Function.

- **functionSolution**: Azure Functions Solution with the required logic to check authenticity of the incoming HTTP requests:
  - The incoming Authorization header is parsed to extract useful informations like IoT Hub Hostname, Device ID, Module ID
  - The Azure Function retrieves, using the IoT Hub Service SDK, the primaryKey for the given module of the specific device registered in the IoT Hub specified in the Authorization header. (***you need to properly set a environment variable here: key is the IoT Hub Hostname, value is the connection string to IoT Hub itself***)
  - Using the retrieved primaryKey, the Azure Function signs *(UrlEncode(sr) + "\n" + se)* and compares it with the signature received in Authorization header; if the two are equal, then the message received is a valid one and the call is authorized.
---
## FAQ

- **Q: Can I have more documentation on Workload API?**
  - Sure. You can find it [here](https://github.com/Azure/iotedge/tree/master/edgelet/workload)
- **Q: I am interested in trying other methods of the Workload API. How can I try REST calls in my dev environment?**
  - [Have a look here](https://github.com/Azure/iotedge/blob/master/edgelet/doc/testiotedgedapi.md) and remember that TCP mode disables authorization, therefore it is definitely *not* appropriate for production scenarios