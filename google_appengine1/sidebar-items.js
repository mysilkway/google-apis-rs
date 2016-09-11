initSidebarItems({"enum":[["Error",""],["Scope","Identifies the an OAuth2 authorization scope. A scope is needed when requesting an authorization token."]],"fn":[["remove_json_null_values",""]],"struct":[["ApiConfigHandler","Google Cloud Endpoints configuration for API handlers."],["ApiEndpointHandler","Uses Google Cloud Endpoints to handle requests."],["AppGetCall","Gets information about an application."],["AppLocationGetCall","Get information about a location."],["AppLocationListCall","Lists information about the supported locations for this service."],["AppMethods","A builder providing access to all methods supported on *app* resources. It is not used directly, but through the `Appengine` hub."],["AppOperationGetCall","Gets the latest state of a long-running operation. Clients can use this method to poll the operation result at intervals as recommended by the API service."],["AppOperationListCall","Lists operations that match the specified filter in the request. If the server doesn't support this method, it returns `UNIMPLEMENTED`. NOTE: the `name` binding below allows API services to override the binding to use different resource name schemes, such as `users/*/operations`."],["AppRepairCall","Recreates the required App Engine features for the application in your project, for example a Cloud Storage bucket or App Engine service account. Use this method if you receive an error message about a missing feature, for example \"*Error retrieving the App Engine service account*\"."],["AppServiceDeleteCall","Deletes the specified service and all enclosed versions."],["AppServiceGetCall","Gets the current configuration of the specified service."],["AppServiceListCall","Lists all the services in the application."],["AppServicePatchCall","Updates the configuration of the specified service."],["AppServiceVersionCreateCall","Deploys code and resource files to a new version."],["AppServiceVersionDeleteCall","Deletes an existing Version resource."],["AppServiceVersionGetCall","Gets the specified Version resource. By default, only a `BASIC_VIEW` will be returned. Specify the `FULL_VIEW` parameter to get the full resource."],["AppServiceVersionInstanceDebugCall","Enables debugging on a VM instance. This allows you to use the SSH command to connect to the virtual machine where the instance lives. While in \"debug mode\", the instance continues to serve live traffic. You should delete the instance when you are done debugging and then allow the system to take over and determine if another instance should be started. Only applicable for instances in App Engine flexible environment."],["AppServiceVersionInstanceDeleteCall","Stops a running instance."],["AppServiceVersionInstanceGetCall","Gets instance information."],["AppServiceVersionInstanceListCall","Lists the instances of a version."],["AppServiceVersionListCall","Lists the versions of a service."],["AppServiceVersionPatchCall","Updates the specified Version resource. You can specify the following fields depending on the App Engine environment and type of scaling that the version resource uses: * `serving_status`: For Version resources that use basic scaling, manual scaling, or run in the App Engine flexible environment. * `instance_class`: For Version resources that run in the App Engine standard environment. * `automatic_scaling.min_idle_instances`: For Version resources that use automatic scaling and run in the App Engine standard environment. * `automatic_scaling.max_idle_instances`: For Version resources that use automatic scaling and run in the App Engine standard environment."],["Appengine","Central instance to access all Appengine related resource activities"],["Application","An Application resource contains the top-level configuration of an App Engine application."],["AutomaticScaling","Automatic scaling is based on request rate, response latencies, and other application metrics."],["BasicScaling","A service with basic scaling will create an instance when the application receives a request. The instance will be turned down when the app becomes idle. Basic scaling is ideal for work that is intermittent or driven by user activity."],["ContainerInfo","Docker image that is used to start a VM container for the version you deploy."],["CpuUtilization","Target scaling by CPU usage."],["DebugInstanceRequest","Request message for `Instances.DebugInstance`."],["DefaultDelegate","A delegate with a conservative default implementation, which is used if no other delegate is set."],["Deployment","Code and application artifacts used to deploy a version to App Engine."],["DiskUtilization","Target scaling by disk usage. Only applicable for VM runtimes."],["ErrorHandler","Custom static error page to be served when an error occurs."],["ErrorResponse","A utility to represent detailed errors we might see in case there are BadRequests. The latter happen if the sent parameters or request structures are unsound"],["FileInfo","Single source file that is part of the version to be deployed. Each source file that is deployed must be specified separately."],["HealthCheck","Health checking configuration for VM instances. Unhealthy instances are killed and replaced with new instances. Only applicable for instances in App Engine flexible environment."],["Instance","An Instance resource is the computing unit that App Engine uses to automatically scale an application."],["Library","Third-party Python runtime library that is required by the application."],["ListInstancesResponse","Response message for `Instances.ListInstances`."],["ListLocationsResponse","The response message for LocationService.ListLocations."],["ListOperationsResponse","The response message for Operations.ListOperations."],["ListServicesResponse","Response message for `Services.ListServices`."],["ListVersionsResponse","Response message for `Versions.ListVersions`."],["Location","A resource that represents Google Cloud Platform location."],["ManualScaling","A service with manual scaling runs continuously, allowing you to perform complex initialization and rely on the state of its memory over time."],["MethodInfo","Contains information about an API request."],["MultiPartReader","Provides a `Read` interface that converts multiple parts into the protocol identified by RFC2387. **Note**: This implementation is just as rich as it needs to be to perform uploads to google APIs, and might not be a fully-featured implementation."],["Network","Extra network settings. Only applicable for VM runtimes."],["NetworkUtilization","Target scaling by network usage. Only applicable for VM runtimes."],["Operation","This resource represents a long-running operation that is the result of a network API call."],["RepairApplicationRequest","Request message for 'Applications.RepairApplication'."],["RequestUtilization","Target scaling by request utilization. Only applicable for VM runtimes."],["Resources","Machine resources for a version."],["ScriptHandler","Executes a script to handle the request that matches the URL pattern."],["Service","A Service resource is a logical component of an application that can share state and communicate in a secure fashion with other services. For example, an application that handles customer requests might include separate services to handle tasks such as backend data analysis or API requests from mobile devices. Each service has a collection of versions that define a specific set of code used to implement the functionality of that service."],["StaticFilesHandler","Files served directly to the user for a given URL, such as images, CSS stylesheets, or JavaScript source files. Static file handlers describe which files in the application directory are static files, and which URLs serve them."],["Status","The `Status` type defines a logical error model that is suitable for different programming environments, including REST APIs and RPC APIs. It is used by gRPC. The error model is designed to be: - Simple to use and understand for most users - Flexible enough to meet unexpected needs # Overview The `Status` message contains three pieces of data: error code, error message, and error details. The error code should be an enum value of google.rpc.Code, but it may accept additional error codes if needed. The error message should be a developer-facing English message that helps developers *understand* and *resolve* the error. If a localized user-facing error message is needed, put the localized message in the error details or localize it in the client. The optional error details may contain arbitrary information about the error. There is a predefined set of error detail types in the package `google.rpc` which can be used for common error conditions. # Language mapping The `Status` message is the logical representation of the error model, but it is not necessarily the actual wire format. When the `Status` message is exposed in different client libraries and different wire protocols, it can be mapped differently. For example, it will likely be mapped to some exceptions in Java, but more likely mapped to some error codes in C. # Other uses The error model and the `Status` message can be used in a variety of environments, either with or without APIs, to provide a consistent developer experience across different environments. Example uses of this error model include: - Partial errors. If a service needs to return partial errors to the client, it may embed the `Status` in the normal response to indicate the partial errors. - Workflow errors. A typical workflow has multiple steps. Each step may have a `Status` message for error reporting purpose. - Batch operations. If a client uses batch request and batch response, the `Status` message should be used directly inside batch response, one for each error sub-response. - Asynchronous operations. If an API call embeds asynchronous operation results in its response, the status of those operations should be represented directly using the `Status` message. - Logging. If some API errors are stored in logs, the message `Status` could be used directly after any stripping needed for security/privacy reasons."],["TrafficSplit","Traffic routing configuration for versions within a single service. Traffic splits define how traffic directed to the service is assigned to versions."],["UrlDispatchRule","Rules to match an HTTP request and dispatch that request to a service."],["UrlMap","URL pattern and description of how the URL should be handled. App Engine can handle URLs by executing application code or by serving static files uploaded with the version, such as images, CSS, or JavaScript."],["Version","A Version resource is a specific set of source code and configuration files that are deployed into a service."],["ZipInfo","There is no detailed description."]],"trait":[["CallBuilder","Identifies types which represent builders for a particular resource method"],["Delegate","A trait specifying functionality to help controlling any request performed by the API. The trait has a conservative default implementation."],["Hub","Identifies the Hub. There is only one per library, this trait is supposed to make intended use more explicit. The hub allows to access all resource methods more easily."],["MethodsBuilder","Identifies types for building methods of a particular resource type"],["NestedType","Identifies types which are only used by other types internally. They have no special meaning, this trait just marks them for completeness."],["Part","Identifies types which are only used as part of other types, which usually are carrying the `Resource` trait."],["ReadSeek","A utility to specify reader types which provide seeking capabilities too"],["RequestValue","Identifies types which are used in API requests."],["Resource","Identifies types which can be inserted and deleted. Types with this trait are most commonly used by clients of this API."],["ResponseResult","Identifies types which are used in API responses."],["ToParts","A trait for all types that can convert themselves into a *parts* string"]],"type":[["Result","A universal result type used as return for all calls."]]});