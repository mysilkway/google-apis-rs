use std::collections::HashMap;
use std::cell::RefCell;
use std::borrow::BorrowMut;
use std::default::Default;
use std::collections::BTreeMap;
use serde_json as json;
use std::io;
use std::fs;
use std::mem;
use std::thread::sleep;

use crate::client;

// ##############
// UTILITIES ###
// ############




// ########
// HUB ###
// ######

/// Central instance to access all HomeGraphService related resource activities
///
/// # Examples
///
/// Instantiate a new hub
///
/// ```test_harness,no_run
/// extern crate hyper;
/// extern crate hyper_rustls;
/// extern crate yup_oauth2 as oauth2;
/// extern crate google_homegraph1 as homegraph1;
/// use homegraph1::api::QueryRequest;
/// use homegraph1::{Result, Error};
/// # #[test] fn egal() {
/// use std::default::Default;
/// use oauth2;
/// use homegraph1::HomeGraphService;
/// 
/// // Get an ApplicationSecret instance by some means. It contains the `client_id` and 
/// // `client_secret`, among other things.
/// let secret: ApplicationSecret = Default::default();
/// // Instantiate the authenticator. It will choose a suitable authentication flow for you, 
/// // unless you replace  `None` with the desired Flow.
/// // Provide your own `AuthenticatorDelegate` to adjust the way it operates and get feedback about 
/// // what's going on. You probably want to bring in your own `TokenStorage` to persist tokens and
/// // retrieve them from storage.
/// let auth = yup_oauth2::InstalledFlowAuthenticator::builder(
///         secret,
///         yup_oauth2::InstalledFlowReturnMethod::HTTPRedirect,
///     ).build().await.unwrap();
/// let mut hub = HomeGraphService::new(hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())), auth);
/// // As the method needs a request, you would usually fill it with the desired information
/// // into the respective structure. Some of the parts shown here might not be applicable !
/// // Values shown here are possibly random and not representative !
/// let mut req = QueryRequest::default();
/// 
/// // You can configure optional parameters by calling the respective setters at will, and
/// // execute the final call using `doit()`.
/// // Values shown here are possibly random and not representative !
/// let result = hub.devices().query(req)
///              .doit();
/// 
/// match result {
///     Err(e) => match e {
///         // The Error enum provides details about what exactly happened.
///         // You can also just use its `Debug`, `Display` or `Error` traits
///          Error::HttpError(_)
///         |Error::MissingAPIKey
///         |Error::MissingToken(_)
///         |Error::Cancelled
///         |Error::UploadSizeLimitExceeded(_, _)
///         |Error::Failure(_)
///         |Error::BadRequest(_)
///         |Error::FieldClash(_)
///         |Error::JsonDecodeError(_, _) => println!("{}", e),
///     },
///     Ok(res) => println!("Success: {:?}", res),
/// }
/// # }
/// ```
pub struct HomeGraphService<C> {
    client: RefCell<C>,
    auth: RefCell<oauth2::authenticator::Authenticator<hyper_rustls::HttpsConnector<hyper::client::connect::HttpConnector>>>,
    _user_agent: String,
    _base_url: String,
    _root_url: String,
}

impl<'a, C> client::Hub for HomeGraphService<C> {}

impl<'a, C> HomeGraphService<C>
    where  C: BorrowMut<hyper::Client<hyper_rustls::HttpsConnector<hyper::client::connect::HttpConnector>, hyper::body::Body>> {

    pub fn new(client: C, authenticator: oauth2::authenticator::Authenticator<hyper_rustls::HttpsConnector<hyper::client::connect::HttpConnector>>) -> HomeGraphService<C> {
        HomeGraphService {
            client: RefCell::new(client),
            auth: RefCell::new(authenticator),
            _user_agent: "google-api-rust-client/1.0.14".to_string(),
            _base_url: "https://homegraph.googleapis.com/".to_string(),
            _root_url: "https://homegraph.googleapis.com/".to_string(),
        }
    }

    pub fn agent_users(&'a self) -> AgentUserMethods<'a, C> {
        AgentUserMethods { hub: &self }
    }
    pub fn devices(&'a self) -> DeviceMethods<'a, C> {
        DeviceMethods { hub: &self }
    }

    /// Set the user-agent header field to use in all requests to the server.
    /// It defaults to `google-api-rust-client/1.0.14`.
    ///
    /// Returns the previously set user-agent.
    pub fn user_agent(&mut self, agent_name: String) -> String {
        mem::replace(&mut self._user_agent, agent_name)
    }

    /// Set the base url to use in all requests to the server.
    /// It defaults to `https://homegraph.googleapis.com/`.
    ///
    /// Returns the previously set base url.
    pub fn base_url(&mut self, new_base_url: String) -> String {
        mem::replace(&mut self._base_url, new_base_url)
    }

    /// Set the root url to use in all requests to the server.
    /// It defaults to `https://homegraph.googleapis.com/`.
    ///
    /// Returns the previously set root url.
    pub fn root_url(&mut self, new_root_url: String) -> String {
        mem::replace(&mut self._root_url, new_root_url)
    }
}


// ############
// SCHEMAS ###
// ##########
/// Third-party device ID for one device.
/// 
/// This type is not used in any activity, and only used as *part* of another schema.
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct AgentDeviceId {
    /// Third-party device ID.
    pub id: Option<String>,
}

impl client::Part for AgentDeviceId {}


/// Alternate third-party device ID.
/// 
/// This type is not used in any activity, and only used as *part* of another schema.
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct AgentOtherDeviceId {
    /// Project ID for your smart home Action.
    #[serde(rename="agentId")]
    pub agent_id: Option<String>,
    /// Unique third-party device ID.
    #[serde(rename="deviceId")]
    pub device_id: Option<String>,
}

impl client::Part for AgentOtherDeviceId {}


/// Third-party device definition.
/// 
/// # Activities
/// 
/// This type is used in activities, which are methods you may call on this type or where this type is involved in. 
/// The list links the activity name, along with information about where it is used (one of *request* and *response*).
/// 
/// * [query devices](DeviceQueryCall) (none)
/// * [report state and notification devices](DeviceReportStateAndNotificationCall) (none)
/// * [request sync devices](DeviceRequestSyncCall) (none)
/// * [sync devices](DeviceSyncCall) (none)
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct Device {
    /// Attributes for the traits supported by the device.
    pub attributes: Option<HashMap<String, String>>,
    /// Custom device attributes stored in Home Graph and provided to your
    /// smart home Action in each
    /// [QUERY](https://developers.google.com/assistant/smarthome/reference/intent/query)
    /// and
    /// [EXECUTE](https://developers.google.com/assistant/smarthome/reference/intent/execute)
    /// intent.
    #[serde(rename="customData")]
    pub custom_data: Option<HashMap<String, String>>,
    /// Device manufacturer, model, hardware version, and software version.
    #[serde(rename="deviceInfo")]
    pub device_info: Option<DeviceInfo>,
    /// Third-party device ID.
    pub id: Option<String>,
    /// Names given to this device by your smart home Action.
    pub name: Option<DeviceNames>,
    /// Indicates whether your smart home Action will report notifications
    /// to Google for this device via
    /// ReportStateAndNotification.
    /// 
    /// If your smart home Action enables users to control device notifications,
    /// you should update this field and call
    /// RequestSyncDevices.
    #[serde(rename="notificationSupportedByAgent")]
    pub notification_supported_by_agent: Option<bool>,
    /// Alternate IDs associated with this device.
    /// This is used to identify cloud synced devices enabled for [local
    /// fulfillment](https://developers.google.com/assistant/smarthome/concepts/local).
    #[serde(rename="otherDeviceIds")]
    pub other_device_ids: Option<Vec<AgentOtherDeviceId>>,
    /// Suggested name for the room where this device is installed.
    /// Google attempts to use this value during user setup.
    #[serde(rename="roomHint")]
    pub room_hint: Option<String>,
    /// Suggested name for the structure where this device is installed.
    /// Google attempts to use this value during user setup.
    #[serde(rename="structureHint")]
    pub structure_hint: Option<String>,
    /// Traits supported by the device.
    /// See [device
    /// traits](https://developers.google.com/assistant/smarthome/traits).
    pub traits: Option<Vec<String>>,
    /// Hardware type of the device.
    /// See [device
    /// types](https://developers.google.com/assistant/smarthome/guides).
    #[serde(rename="type")]
    pub type_: Option<String>,
    /// Indicates whether your smart home Action will report state of this device
    /// to Google via
    /// ReportStateAndNotification.
    #[serde(rename="willReportState")]
    pub will_report_state: Option<bool>,
}

impl client::Resource for Device {}


/// Device information.
/// 
/// This type is not used in any activity, and only used as *part* of another schema.
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// Device hardware version.
    #[serde(rename="hwVersion")]
    pub hw_version: Option<String>,
    /// Device manufacturer.
    pub manufacturer: Option<String>,
    /// Device model.
    pub model: Option<String>,
    /// Device software version.
    #[serde(rename="swVersion")]
    pub sw_version: Option<String>,
}

impl client::Part for DeviceInfo {}


/// Identifiers used to describe the device.
/// 
/// This type is not used in any activity, and only used as *part* of another schema.
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct DeviceNames {
    /// List of names provided by the manufacturer rather than the user, such as
    /// serial numbers, SKUs, etc.
    #[serde(rename="defaultNames")]
    pub default_names: Option<Vec<String>>,
    /// Primary name of the device, generally provided by the user.
    pub name: Option<String>,
    /// Additional names provided by the user for the device.
    pub nicknames: Option<Vec<String>>,
}

impl client::Part for DeviceNames {}


/// A generic empty message that you can re-use to avoid defining duplicated
/// empty messages in your APIs. A typical example is to use it as the request
/// or the response type of an API method. For instance:
/// 
/// ````text
/// service Foo {
///   rpc Bar(google.protobuf.Empty) returns (google.protobuf.Empty);
/// }
/// ````
/// 
/// The JSON representation for `Empty` is empty JSON object `{}`.
/// 
/// # Activities
/// 
/// This type is used in activities, which are methods you may call on this type or where this type is involved in. 
/// The list links the activity name, along with information about where it is used (one of *request* and *response*).
/// 
/// * [delete agent users](AgentUserDeleteCall) (response)
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct Empty { _never_set: Option<bool> }

impl client::ResponseResult for Empty {}


/// Request type for the
/// [`Query`](#google.home.graph.v1.HomeGraphApiService.Query) call.
/// 
/// # Activities
/// 
/// This type is used in activities, which are methods you may call on this type or where this type is involved in. 
/// The list links the activity name, along with information about where it is used (one of *request* and *response*).
/// 
/// * [query devices](DeviceQueryCall) (request)
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct QueryRequest {
    /// Required. Third-party user ID.
    #[serde(rename="agentUserId")]
    pub agent_user_id: Option<String>,
    /// Required. Inputs containing third-party device IDs for which to
    /// get the device states.
    pub inputs: Option<Vec<QueryRequestInput>>,
    /// Request ID used for debugging.
    #[serde(rename="requestId")]
    pub request_id: Option<String>,
}

impl client::RequestValue for QueryRequest {}


/// Device ID inputs to QueryRequest.
/// 
/// This type is not used in any activity, and only used as *part* of another schema.
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct QueryRequestInput {
    /// Payload containing third-party device IDs.
    pub payload: Option<QueryRequestPayload>,
}

impl client::Part for QueryRequestInput {}


/// Payload containing device IDs.
/// 
/// This type is not used in any activity, and only used as *part* of another schema.
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct QueryRequestPayload {
    /// Third-party device IDs for which to get the device states.
    pub devices: Option<Vec<AgentDeviceId>>,
}

impl client::Part for QueryRequestPayload {}


/// Response type for the
/// [`Query`](#google.home.graph.v1.HomeGraphApiService.Query) call.
/// This should follow the same format as the Google smart home
/// `action.devices.QUERY`
/// [response](https://developers.google.com/assistant/smarthome/reference/intent/query).
/// 
/// # Example
/// 
/// ````textjson
/// {
///   "requestId": "ff36a3cc-ec34-11e6-b1a0-64510650abcf",
///   "payload": {
///     "devices": {
///       "123": {
///         "on": true,
///         "online": true
///       },
///       "456": {
///         "on": true,
///         "online": true,
///         "brightness": 80,
///         "color": {
///           "name": "cerulean",
///           "spectrumRGB": 31655
///         }
///       }
///     }
///   }
/// }
/// ````
/// 
/// # Activities
/// 
/// This type is used in activities, which are methods you may call on this type or where this type is involved in. 
/// The list links the activity name, along with information about where it is used (one of *request* and *response*).
/// 
/// * [query devices](DeviceQueryCall) (response)
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct QueryResponse {
    /// Device states for the devices given in the request.
    pub payload: Option<QueryResponsePayload>,
    /// Request ID used for debugging. Copied from the request.
    #[serde(rename="requestId")]
    pub request_id: Option<String>,
}

impl client::ResponseResult for QueryResponse {}


/// Payload containing device states information.
/// 
/// This type is not used in any activity, and only used as *part* of another schema.
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct QueryResponsePayload {
    /// States of the devices. Map of third-party device ID to struct of device
    /// states.
    pub devices: Option<HashMap<String, HashMap<String, String>>>,
}

impl client::Part for QueryResponsePayload {}


/// The states and notifications specific to a device.
/// 
/// This type is not used in any activity, and only used as *part* of another schema.
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct ReportStateAndNotificationDevice {
    /// Notifications metadata for devices. See the **Device NOTIFICATIONS**
    /// section of the individual trait [reference
    /// guides](https://developers.google.com/assistant/smarthome/traits).
    pub notifications: Option<HashMap<String, String>>,
    /// States of devices to update. See the **Device STATES** section
    /// of the individual trait [reference
    /// guides](https://developers.google.com/assistant/smarthome/traits).
    pub states: Option<HashMap<String, String>>,
}

impl client::Part for ReportStateAndNotificationDevice {}


/// Request type for the
/// [`ReportStateAndNotification`](#google.home.graph.v1.HomeGraphApiService.ReportStateAndNotification)
/// call. It may include states, notifications, or both. States and notifications
/// are defined per `device_id` (for example, "123" and "456" in the following
/// example).
/// 
/// # Example
/// 
/// ````textjson
/// {
///   "requestId": "ff36a3cc-ec34-11e6-b1a0-64510650abcf",
///   "agentUserId": "1234",
///   "payload": {
///     "devices": {
///       "states": {
///         "123": {
///           "on": true
///         },
///         "456": {
///           "on": true,
///           "brightness": 10
///         }
///       },
///     }
///   }
/// }
/// ````
/// 
/// # Activities
/// 
/// This type is used in activities, which are methods you may call on this type or where this type is involved in. 
/// The list links the activity name, along with information about where it is used (one of *request* and *response*).
/// 
/// * [report state and notification devices](DeviceReportStateAndNotificationCall) (request)
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct ReportStateAndNotificationRequest {
    /// Required. Third-party user ID.
    #[serde(rename="agentUserId")]
    pub agent_user_id: Option<String>,
    /// Unique identifier per event (for example, a doorbell press).
    #[serde(rename="eventId")]
    pub event_id: Option<String>,
    /// Token to maintain state in the follow up notification response.
    /// Deprecated. See the [notifications
    /// guide](https://developers.google.com/assistant/smarthome/develop/notifications)
    /// for details on implementing follow up notifications.
    #[serde(rename="followUpToken")]
    pub follow_up_token: Option<String>,
    /// Required. State of devices to update and notification metadata for devices.
    pub payload: Option<StateAndNotificationPayload>,
    /// Request ID used for debugging.
    #[serde(rename="requestId")]
    pub request_id: Option<String>,
}

impl client::RequestValue for ReportStateAndNotificationRequest {}


/// Response type for the
/// [`ReportStateAndNotification`](#google.home.graph.v1.HomeGraphApiService.ReportStateAndNotification)
/// call.
/// 
/// # Activities
/// 
/// This type is used in activities, which are methods you may call on this type or where this type is involved in. 
/// The list links the activity name, along with information about where it is used (one of *request* and *response*).
/// 
/// * [report state and notification devices](DeviceReportStateAndNotificationCall) (response)
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct ReportStateAndNotificationResponse {
    /// Request ID copied from ReportStateAndNotificationRequest.
    #[serde(rename="requestId")]
    pub request_id: Option<String>,
}

impl client::ResponseResult for ReportStateAndNotificationResponse {}


/// Request type for the
/// [`RequestSyncDevices`](#google.home.graph.v1.HomeGraphApiService.RequestSyncDevices)
/// call.
/// 
/// # Activities
/// 
/// This type is used in activities, which are methods you may call on this type or where this type is involved in. 
/// The list links the activity name, along with information about where it is used (one of *request* and *response*).
/// 
/// * [request sync devices](DeviceRequestSyncCall) (request)
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct RequestSyncDevicesRequest {
    /// Required. Third-party user ID.
    #[serde(rename="agentUserId")]
    pub agent_user_id: Option<String>,
    /// Optional. If set, the request will be added to a queue and a response will
    /// be returned immediately. This enables concurrent requests for the given
    /// `agent_user_id`, but the caller will not receive any error responses.
    pub async: Option<bool>,
}

impl client::RequestValue for RequestSyncDevicesRequest {}


/// Response type for the
/// [`RequestSyncDevices`](#google.home.graph.v1.HomeGraphApiService.RequestSyncDevices)
/// call.
/// 
/// Intentionally empty upon success. An HTTP response code is returned
/// with more details upon failure.
/// 
/// # Activities
/// 
/// This type is used in activities, which are methods you may call on this type or where this type is involved in. 
/// The list links the activity name, along with information about where it is used (one of *request* and *response*).
/// 
/// * [request sync devices](DeviceRequestSyncCall) (response)
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct RequestSyncDevicesResponse { _never_set: Option<bool> }

impl client::ResponseResult for RequestSyncDevicesResponse {}


/// Payload containing the state and notification information for devices.
/// 
/// This type is not used in any activity, and only used as *part* of another schema.
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct StateAndNotificationPayload {
    /// The devices for updating state and sending notifications.
    pub devices: Option<ReportStateAndNotificationDevice>,
}

impl client::Part for StateAndNotificationPayload {}


/// Request type for the [`Sync`](#google.home.graph.v1.HomeGraphApiService.Sync)
/// call.
/// 
/// # Activities
/// 
/// This type is used in activities, which are methods you may call on this type or where this type is involved in. 
/// The list links the activity name, along with information about where it is used (one of *request* and *response*).
/// 
/// * [sync devices](DeviceSyncCall) (request)
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct SyncRequest {
    /// Required. Third-party user ID.
    #[serde(rename="agentUserId")]
    pub agent_user_id: Option<String>,
    /// Request ID used for debugging.
    #[serde(rename="requestId")]
    pub request_id: Option<String>,
}

impl client::RequestValue for SyncRequest {}


/// Response type for the
/// [`Sync`](#google.home.graph.v1.HomeGraphApiService.Sync) call.
/// This should follow the same format as the Google smart home
/// `action.devices.SYNC`
/// [response](https://developers.google.com/assistant/smarthome/reference/intent/sync).
/// 
/// # Example
/// 
/// ````textjson
/// {
///   "requestId": "ff36a3cc-ec34-11e6-b1a0-64510650abcf",
///   "payload": {
///     "agentUserId": "1836.15267389",
///     "devices": [{
///       "id": "123",
///       "type": "action.devices.types.OUTLET",
///       "traits": [
///         "action.devices.traits.OnOff"
///       ],
///       "name": {
///         "defaultNames": ["My Outlet 1234"],
///         "name": "Night light",
///         "nicknames": ["wall plug"]
///       },
///       "willReportState": false,
///       "deviceInfo": {
///         "manufacturer": "lights-out-inc",
///         "model": "hs1234",
///         "hwVersion": "3.2",
///         "swVersion": "11.4"
///       },
///       "customData": {
///         "fooValue": 74,
///         "barValue": true,
///         "bazValue": "foo"
///       }
///     }]
///   }
/// }
/// ````
/// 
/// # Activities
/// 
/// This type is used in activities, which are methods you may call on this type or where this type is involved in. 
/// The list links the activity name, along with information about where it is used (one of *request* and *response*).
/// 
/// * [sync devices](DeviceSyncCall) (response)
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct SyncResponse {
    /// Devices associated with the third-party user.
    pub payload: Option<SyncResponsePayload>,
    /// Request ID used for debugging. Copied from the request.
    #[serde(rename="requestId")]
    pub request_id: Option<String>,
}

impl client::ResponseResult for SyncResponse {}


/// Payload containing device information.
/// 
/// This type is not used in any activity, and only used as *part* of another schema.
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct SyncResponsePayload {
    /// Third-party user ID
    #[serde(rename="agentUserId")]
    pub agent_user_id: Option<String>,
    /// Devices associated with the third-party user.
    pub devices: Option<Vec<Device>>,
}

impl client::Part for SyncResponsePayload {}



// ###################
// MethodBuilders ###
// #################

/// A builder providing access to all methods supported on *agentUser* resources.
/// It is not used directly, but through the `HomeGraphService` hub.
///
/// # Example
///
/// Instantiate a resource builder
///
/// ```test_harness,no_run
/// extern crate hyper;
/// extern crate hyper_rustls;
/// extern crate yup_oauth2 as oauth2;
/// extern crate google_homegraph1 as homegraph1;
/// 
/// # #[test] fn egal() {
/// use std::default::Default;
/// use oauth2;
/// use homegraph1::HomeGraphService;
/// 
/// let secret: ApplicationSecret = Default::default();
/// let auth = yup_oauth2::InstalledFlowAuthenticator::builder(
///         secret,
///         yup_oauth2::InstalledFlowReturnMethod::HTTPRedirect,
///     ).build().await.unwrap();
/// let mut hub = HomeGraphService::new(hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())), auth);
/// // Usually you wouldn't bind this to a variable, but keep calling *CallBuilders*
/// // like `delete(...)`
/// // to build up your call.
/// let rb = hub.agent_users();
/// # }
/// ```
pub struct AgentUserMethods<'a, C>
    where C: 'a {

    hub: &'a HomeGraphService<C>,
}

impl<'a, C> client::MethodsBuilder for AgentUserMethods<'a, C> {}

impl<'a, C> AgentUserMethods<'a, C> {
    
    /// Create a builder to help you perform the following task:
    ///
    /// Unlinks the given third-party user from your smart home Action.
    /// All data related to this user will be deleted.
    /// 
    /// For more details on how users link their accounts, see
    /// [fulfillment and
    /// authentication](https://developers.google.com/assistant/smarthome/concepts/fulfillment-authentication).
    /// 
    /// The third-party user's identity is passed in via the `agent_user_id`
    /// (see DeleteAgentUserRequest).
    /// This request must be authorized using service account credentials from your
    /// Actions console project.
    /// 
    /// # Arguments
    ///
    /// * `agentUserId` - Required. Third-party user ID.
    pub fn delete(&self, agent_user_id: &str) -> AgentUserDeleteCall<'a, C> {
        AgentUserDeleteCall {
            hub: self.hub,
            _agent_user_id: agent_user_id.to_string(),
            _request_id: Default::default(),
            _delegate: Default::default(),
            _additional_params: Default::default(),
        }
    }
}



/// A builder providing access to all methods supported on *device* resources.
/// It is not used directly, but through the `HomeGraphService` hub.
///
/// # Example
///
/// Instantiate a resource builder
///
/// ```test_harness,no_run
/// extern crate hyper;
/// extern crate hyper_rustls;
/// extern crate yup_oauth2 as oauth2;
/// extern crate google_homegraph1 as homegraph1;
/// 
/// # #[test] fn egal() {
/// use std::default::Default;
/// use oauth2;
/// use homegraph1::HomeGraphService;
/// 
/// let secret: ApplicationSecret = Default::default();
/// let auth = yup_oauth2::InstalledFlowAuthenticator::builder(
///         secret,
///         yup_oauth2::InstalledFlowReturnMethod::HTTPRedirect,
///     ).build().await.unwrap();
/// let mut hub = HomeGraphService::new(hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())), auth);
/// // Usually you wouldn't bind this to a variable, but keep calling *CallBuilders*
/// // like `query(...)`, `report_state_and_notification(...)`, `request_sync(...)` and `sync(...)`
/// // to build up your call.
/// let rb = hub.devices();
/// # }
/// ```
pub struct DeviceMethods<'a, C>
    where C: 'a {

    hub: &'a HomeGraphService<C>,
}

impl<'a, C> client::MethodsBuilder for DeviceMethods<'a, C> {}

impl<'a, C> DeviceMethods<'a, C> {
    
    /// Create a builder to help you perform the following task:
    ///
    /// Gets the current states in Home Graph for the given set of the third-party
    /// user's devices.
    /// 
    /// The third-party user's identity is passed in via the `agent_user_id`
    /// (see QueryRequest).
    /// This request must be authorized using service account credentials from your
    /// Actions console project.
    /// 
    /// # Arguments
    ///
    /// * `request` - No description provided.
    pub fn query(&self, request: QueryRequest) -> DeviceQueryCall<'a, C> {
        DeviceQueryCall {
            hub: self.hub,
            _request: request,
            _delegate: Default::default(),
            _additional_params: Default::default(),
        }
    }
    
    /// Create a builder to help you perform the following task:
    ///
    /// Reports device state and optionally sends device notifications.
    /// Called by your smart home Action when the state of a third-party device
    /// changes or you need to send a notification about the device.
    /// See [Implement Report
    /// State](https://developers.google.com/assistant/smarthome/develop/report-state)
    /// for more information.
    /// 
    /// This method updates the device state according to its declared
    /// [traits](https://developers.google.com/assistant/smarthome/concepts/devices-traits).
    /// Publishing a new state value outside of these traits will result in an
    /// `INVALID_ARGUMENT` error response.
    /// 
    /// The third-party user's identity is passed in via the `agent_user_id`
    /// (see ReportStateAndNotificationRequest).
    /// This request must be authorized using service account credentials from your
    /// Actions console project.
    /// 
    /// # Arguments
    ///
    /// * `request` - No description provided.
    pub fn report_state_and_notification(&self, request: ReportStateAndNotificationRequest) -> DeviceReportStateAndNotificationCall<'a, C> {
        DeviceReportStateAndNotificationCall {
            hub: self.hub,
            _request: request,
            _delegate: Default::default(),
            _additional_params: Default::default(),
        }
    }
    
    /// Create a builder to help you perform the following task:
    ///
    /// Requests Google to send an `action.devices.SYNC`
    /// [intent](https://developers.google.com/assistant/smarthome/reference/intent/sync)
    /// to your smart home Action to update device metadata for the given user.
    /// 
    /// 
    /// The third-party user's identity is passed via the `agent_user_id`
    /// (see RequestSyncDevicesRequest).
    /// This request must be authorized using service account credentials from your
    /// Actions console project.
    /// 
    /// # Arguments
    ///
    /// * `request` - No description provided.
    pub fn request_sync(&self, request: RequestSyncDevicesRequest) -> DeviceRequestSyncCall<'a, C> {
        DeviceRequestSyncCall {
            hub: self.hub,
            _request: request,
            _delegate: Default::default(),
            _additional_params: Default::default(),
        }
    }
    
    /// Create a builder to help you perform the following task:
    ///
    /// Gets all the devices associated with the given third-party user.
    /// 
    /// The third-party user's identity is passed in via the `agent_user_id`
    /// (see SyncRequest).
    /// This request must be authorized using service account credentials from your
    /// Actions console project.
    /// 
    /// # Arguments
    ///
    /// * `request` - No description provided.
    pub fn sync(&self, request: SyncRequest) -> DeviceSyncCall<'a, C> {
        DeviceSyncCall {
            hub: self.hub,
            _request: request,
            _delegate: Default::default(),
            _additional_params: Default::default(),
        }
    }
}





// ###################
// CallBuilders   ###
// #################

/// Unlinks the given third-party user from your smart home Action.
/// All data related to this user will be deleted.
/// 
/// For more details on how users link their accounts, see
/// [fulfillment and
/// authentication](https://developers.google.com/assistant/smarthome/concepts/fulfillment-authentication).
/// 
/// The third-party user's identity is passed in via the `agent_user_id`
/// (see DeleteAgentUserRequest).
/// This request must be authorized using service account credentials from your
/// Actions console project.
///
/// A builder for the *delete* method supported by a *agentUser* resource.
/// It is not used directly, but through a `AgentUserMethods` instance.
///
/// # Example
///
/// Instantiate a resource method builder
///
/// ```test_harness,no_run
/// # extern crate hyper;
/// # extern crate hyper_rustls;
/// # extern crate yup_oauth2 as oauth2;
/// # extern crate google_homegraph1 as homegraph1;
/// # #[test] fn egal() {
/// # use std::default::Default;
/// # use oauth2;
/// # use homegraph1::HomeGraphService;
/// 
/// # let secret: ApplicationSecret = Default::default();
/// # let auth = yup_oauth2::InstalledFlowAuthenticator::builder(
/// #         secret,
/// #         yup_oauth2::InstalledFlowReturnMethod::HTTPRedirect,
/// #     ).build().await.unwrap();
/// # let mut hub = HomeGraphService::new(hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())), auth);
/// // You can configure optional parameters by calling the respective setters at will, and
/// // execute the final call using `doit()`.
/// // Values shown here are possibly random and not representative !
/// let result = hub.agent_users().delete("agentUserId")
///              .request_id("magna")
///              .doit();
/// # }
/// ```
pub struct AgentUserDeleteCall<'a, C>
    where C: 'a {

    hub: &'a HomeGraphService<C>,
    _agent_user_id: String,
    _request_id: Option<String>,
    _delegate: Option<&'a mut dyn client::Delegate>,
    _additional_params: HashMap<String, String>,
}

impl<'a, C> client::CallBuilder for AgentUserDeleteCall<'a, C> {}

impl<'a, C> AgentUserDeleteCall<'a, C> where C: BorrowMut<hyper::Client<hyper_rustls::HttpsConnector<hyper::client::connect::HttpConnector>, hyper::body::Body>> {


    /// Perform the operation you have build so far.
    pub async fn doit(mut self) -> client::Result<(hyper::Response<hyper::body::Body>, Empty)> {
        use url::percent_encoding::{percent_encode, DEFAULT_ENCODE_SET};
        use std::io::{Read, Seek};
        use hyper::header::{CONTENT_TYPE, CONTENT_LENGTH, AUTHORIZATION, USER_AGENT, LOCATION};
        use client::ToParts;
        let mut dd = client::DefaultDelegate;
        let mut dlg: &mut dyn client::Delegate = match self._delegate {
            Some(d) => d,
            None => &mut dd
        };
        dlg.begin(client::MethodInfo { id: "homegraph.agentUsers.delete",
                               http_method: hyper::Method::DELETE });
        let mut params: Vec<(&str, String)> = Vec::with_capacity(4 + self._additional_params.len());
        params.push(("agentUserId", self._agent_user_id.to_string()));
        if let Some(value) = self._request_id {
            params.push(("requestId", value.to_string()));
        }
        for &field in ["alt", "agentUserId", "requestId"].iter() {
            if self._additional_params.contains_key(field) {
                dlg.finished(false);
                return Err(client::Error::FieldClash(field));
            }
        }
        for (name, value) in self._additional_params.iter() {
            params.push((&name, value.clone()));
        }

        params.push(("alt", "json".to_string()));

        let mut url = self.hub._base_url.clone() + "v1/{+agentUserId}";
        
        let mut key = self.hub.auth.borrow_mut().api_key();
        if key.is_none() {
            key = dlg.api_key();
        }
        match key {
            Some(value) => params.push(("key", value)),
            None => {
                dlg.finished(false);
                return Err(client::Error::MissingAPIKey)
            }
        }

        for &(find_this, param_name) in [("{+agentUserId}", "agentUserId")].iter() {
            let mut replace_with = String::new();
            for &(name, ref value) in params.iter() {
                if name == param_name {
                    replace_with = value.to_string();
                    break;
                }
            }
            if find_this.as_bytes()[1] == '+' as u8 {
                replace_with = percent_encode(replace_with.as_bytes(), DEFAULT_ENCODE_SET).to_string();
            }
            url = url.replace(find_this, &replace_with);
        }
        {
            let mut indices_for_removal: Vec<usize> = Vec::with_capacity(1);
            for param_name in ["agentUserId"].iter() {
                if let Some(index) = params.iter().position(|t| &t.0 == param_name) {
                    indices_for_removal.push(index);
                }
            }
            for &index in indices_for_removal.iter() {
                params.remove(index);
            }
        }

        let url = url::Url::parse_with_params(&url, params).unwrap();



        loop {
            let mut req_result = {
                let mut client = &mut *self.hub.client.borrow_mut();
                dlg.pre_request();
                let mut req_builder = hyper::Request::builder().method(hyper::Method::DELETE).uri(url.clone().into_string())
                        .header(USER_AGENT, self.hub._user_agent.clone());


                        let request = req_builder
                        .body(hyper::body::Body::empty());

                client.borrow_mut().request(request.unwrap()).await
                
            };

            match req_result {
                Err(err) => {
                    if let client::Retry::After(d) = dlg.http_error(&err) {
                        sleep(d);
                        continue;
                    }
                    dlg.finished(false);
                    return Err(client::Error::HttpError(err))
                }
                Ok(mut res) => {
                    let (res_parts, res_body) = res.into_parts();
                    let res_body_string: String = String::from_utf8(
                        hyper::body::to_bytes(res_body)
                            .await
                            .unwrap()
                            .into_iter()
                            .collect(),
                    )
                    .unwrap();
                    let reconstructed_result =
                        hyper::Response::from_parts(res_parts, res_body_string.clone().into());

                    if !reconstructed_result.status().is_success() {
                        let json_server_error = json::from_str::<client::JsonServerError>(&res_body_string).ok();
                        let server_error = json::from_str::<client::ServerError>(&res_body_string)
                            .or_else(|_| json::from_str::<client::ErrorResponse>(&res_body_string).map(|r| r.error))
                            .ok();

                        if let client::Retry::After(d) = dlg.http_failure(&reconstructed_result,
                                                              json_server_error,
                                                              server_error) {
                            sleep(d);
                            continue;
                        }
                        dlg.finished(false);
                        return match json::from_str::<client::ErrorResponse>(&res_body_string){
                            Err(_) => Err(client::Error::Failure(reconstructed_result)),
                            Ok(serr) => Err(client::Error::BadRequest(serr))
                        }
                    }
                    let result_value = {
                        match json::from_str(&res_body_string) {
                            Ok(decoded) => (reconstructed_result, decoded),
                            Err(err) => {
                                dlg.response_json_decode_error(&res_body_string, &err);
                                return Err(client::Error::JsonDecodeError(res_body_string, err));
                            }
                        }
                    };

                    dlg.finished(true);
                    return Ok(result_value)
                }
            }
        }
    }


    /// Required. Third-party user ID.
    ///
    /// Sets the *agent user id* path property to the given value.
    ///
    /// Even though the property as already been set when instantiating this call,
    /// we provide this method for API completeness.
    pub fn agent_user_id(mut self, new_value: &str) -> AgentUserDeleteCall<'a, C> {
        self._agent_user_id = new_value.to_string();
        self
    }
    /// Request ID used for debugging.
    ///
    /// Sets the *request id* query property to the given value.
    pub fn request_id(mut self, new_value: &str) -> AgentUserDeleteCall<'a, C> {
        self._request_id = Some(new_value.to_string());
        self
    }
    /// The delegate implementation is consulted whenever there is an intermediate result, or if something goes wrong
    /// while executing the actual API request.
    /// 
    /// It should be used to handle progress information, and to implement a certain level of resilience.
    ///
    /// Sets the *delegate* property to the given value.
    pub fn delegate(mut self, new_value: &'a mut dyn client::Delegate) -> AgentUserDeleteCall<'a, C> {
        self._delegate = Some(new_value);
        self
    }

    /// Set any additional parameter of the query string used in the request.
    /// It should be used to set parameters which are not yet available through their own
    /// setters.
    ///
    /// Please note that this method must not be used to set any of the known parameters
    /// which have their own setter method. If done anyway, the request will fail.
    ///
    /// # Additional Parameters
    ///
    /// * *$.xgafv* (query-string) - V1 error format.
    /// * *access_token* (query-string) - OAuth access token.
    /// * *alt* (query-string) - Data format for response.
    /// * *callback* (query-string) - JSONP
    /// * *fields* (query-string) - Selector specifying which fields to include in a partial response.
    /// * *key* (query-string) - API key. Your API key identifies your project and provides you with API access, quota, and reports. Required unless you provide an OAuth 2.0 token.
    /// * *oauth_token* (query-string) - OAuth 2.0 token for the current user.
    /// * *prettyPrint* (query-boolean) - Returns response with indentations and line breaks.
    /// * *quotaUser* (query-string) - Available to use for quota purposes for server-side applications. Can be any arbitrary string assigned to a user, but should not exceed 40 characters.
    /// * *uploadType* (query-string) - Legacy upload protocol for media (e.g. "media", "multipart").
    /// * *upload_protocol* (query-string) - Upload protocol for media (e.g. "raw", "multipart").
    pub fn param<T>(mut self, name: T, value: T) -> AgentUserDeleteCall<'a, C>
                                                        where T: AsRef<str> {
        self._additional_params.insert(name.as_ref().to_string(), value.as_ref().to_string());
        self
    }

}


/// Gets the current states in Home Graph for the given set of the third-party
/// user's devices.
/// 
/// The third-party user's identity is passed in via the `agent_user_id`
/// (see QueryRequest).
/// This request must be authorized using service account credentials from your
/// Actions console project.
///
/// A builder for the *query* method supported by a *device* resource.
/// It is not used directly, but through a `DeviceMethods` instance.
///
/// # Example
///
/// Instantiate a resource method builder
///
/// ```test_harness,no_run
/// # extern crate hyper;
/// # extern crate hyper_rustls;
/// # extern crate yup_oauth2 as oauth2;
/// # extern crate google_homegraph1 as homegraph1;
/// use homegraph1::api::QueryRequest;
/// # #[test] fn egal() {
/// # use std::default::Default;
/// # use oauth2;
/// # use homegraph1::HomeGraphService;
/// 
/// # let secret: ApplicationSecret = Default::default();
/// # let auth = yup_oauth2::InstalledFlowAuthenticator::builder(
/// #         secret,
/// #         yup_oauth2::InstalledFlowReturnMethod::HTTPRedirect,
/// #     ).build().await.unwrap();
/// # let mut hub = HomeGraphService::new(hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())), auth);
/// // As the method needs a request, you would usually fill it with the desired information
/// // into the respective structure. Some of the parts shown here might not be applicable !
/// // Values shown here are possibly random and not representative !
/// let mut req = QueryRequest::default();
/// 
/// // You can configure optional parameters by calling the respective setters at will, and
/// // execute the final call using `doit()`.
/// // Values shown here are possibly random and not representative !
/// let result = hub.devices().query(req)
///              .doit();
/// # }
/// ```
pub struct DeviceQueryCall<'a, C>
    where C: 'a {

    hub: &'a HomeGraphService<C>,
    _request: QueryRequest,
    _delegate: Option<&'a mut dyn client::Delegate>,
    _additional_params: HashMap<String, String>,
}

impl<'a, C> client::CallBuilder for DeviceQueryCall<'a, C> {}

impl<'a, C> DeviceQueryCall<'a, C> where C: BorrowMut<hyper::Client<hyper_rustls::HttpsConnector<hyper::client::connect::HttpConnector>, hyper::body::Body>> {


    /// Perform the operation you have build so far.
    pub async fn doit(mut self) -> client::Result<(hyper::Response<hyper::body::Body>, QueryResponse)> {
        use std::io::{Read, Seek};
        use hyper::header::{CONTENT_TYPE, CONTENT_LENGTH, AUTHORIZATION, USER_AGENT, LOCATION};
        use client::ToParts;
        let mut dd = client::DefaultDelegate;
        let mut dlg: &mut dyn client::Delegate = match self._delegate {
            Some(d) => d,
            None => &mut dd
        };
        dlg.begin(client::MethodInfo { id: "homegraph.devices.query",
                               http_method: hyper::Method::POST });
        let mut params: Vec<(&str, String)> = Vec::with_capacity(3 + self._additional_params.len());
        for &field in ["alt"].iter() {
            if self._additional_params.contains_key(field) {
                dlg.finished(false);
                return Err(client::Error::FieldClash(field));
            }
        }
        for (name, value) in self._additional_params.iter() {
            params.push((&name, value.clone()));
        }

        params.push(("alt", "json".to_string()));

        let mut url = self.hub._base_url.clone() + "v1/devices:query";
        
        let mut key = self.hub.auth.borrow_mut().api_key();
        if key.is_none() {
            key = dlg.api_key();
        }
        match key {
            Some(value) => params.push(("key", value)),
            None => {
                dlg.finished(false);
                return Err(client::Error::MissingAPIKey)
            }
        }


        let url = url::Url::parse_with_params(&url, params).unwrap();

        let mut json_mime_type: mime::Mime = "application/json".parse().unwrap();
        let mut request_value_reader =
            {
                let mut value = json::value::to_value(&self._request).expect("serde to work");
                client::remove_json_null_values(&mut value);
                let mut dst = io::Cursor::new(Vec::with_capacity(128));
                json::to_writer(&mut dst, &value).unwrap();
                dst
            };
        let request_size = request_value_reader.seek(io::SeekFrom::End(0)).unwrap();
        request_value_reader.seek(io::SeekFrom::Start(0)).unwrap();


        loop {
            request_value_reader.seek(io::SeekFrom::Start(0)).unwrap();
            let mut req_result = {
                let mut client = &mut *self.hub.client.borrow_mut();
                dlg.pre_request();
                let mut req_builder = hyper::Request::builder().method(hyper::Method::POST).uri(url.clone().into_string())
                        .header(USER_AGENT, self.hub._user_agent.clone());


                        let request = req_builder
                        .header(CONTENT_TYPE, format!("{}", json_mime_type))
                        .header(CONTENT_LENGTH, request_size as u64)
                        .body(hyper::body::Body::from(request_value_reader.get_ref().clone()));

                client.borrow_mut().request(request.unwrap()).await
                
            };

            match req_result {
                Err(err) => {
                    if let client::Retry::After(d) = dlg.http_error(&err) {
                        sleep(d);
                        continue;
                    }
                    dlg.finished(false);
                    return Err(client::Error::HttpError(err))
                }
                Ok(mut res) => {
                    let (res_parts, res_body) = res.into_parts();
                    let res_body_string: String = String::from_utf8(
                        hyper::body::to_bytes(res_body)
                            .await
                            .unwrap()
                            .into_iter()
                            .collect(),
                    )
                    .unwrap();
                    let reconstructed_result =
                        hyper::Response::from_parts(res_parts, res_body_string.clone().into());

                    if !reconstructed_result.status().is_success() {
                        let json_server_error = json::from_str::<client::JsonServerError>(&res_body_string).ok();
                        let server_error = json::from_str::<client::ServerError>(&res_body_string)
                            .or_else(|_| json::from_str::<client::ErrorResponse>(&res_body_string).map(|r| r.error))
                            .ok();

                        if let client::Retry::After(d) = dlg.http_failure(&reconstructed_result,
                                                              json_server_error,
                                                              server_error) {
                            sleep(d);
                            continue;
                        }
                        dlg.finished(false);
                        return match json::from_str::<client::ErrorResponse>(&res_body_string){
                            Err(_) => Err(client::Error::Failure(reconstructed_result)),
                            Ok(serr) => Err(client::Error::BadRequest(serr))
                        }
                    }
                    let result_value = {
                        match json::from_str(&res_body_string) {
                            Ok(decoded) => (reconstructed_result, decoded),
                            Err(err) => {
                                dlg.response_json_decode_error(&res_body_string, &err);
                                return Err(client::Error::JsonDecodeError(res_body_string, err));
                            }
                        }
                    };

                    dlg.finished(true);
                    return Ok(result_value)
                }
            }
        }
    }


    ///
    /// Sets the *request* property to the given value.
    ///
    /// Even though the property as already been set when instantiating this call,
    /// we provide this method for API completeness.
    pub fn request(mut self, new_value: QueryRequest) -> DeviceQueryCall<'a, C> {
        self._request = new_value;
        self
    }
    /// The delegate implementation is consulted whenever there is an intermediate result, or if something goes wrong
    /// while executing the actual API request.
    /// 
    /// It should be used to handle progress information, and to implement a certain level of resilience.
    ///
    /// Sets the *delegate* property to the given value.
    pub fn delegate(mut self, new_value: &'a mut dyn client::Delegate) -> DeviceQueryCall<'a, C> {
        self._delegate = Some(new_value);
        self
    }

    /// Set any additional parameter of the query string used in the request.
    /// It should be used to set parameters which are not yet available through their own
    /// setters.
    ///
    /// Please note that this method must not be used to set any of the known parameters
    /// which have their own setter method. If done anyway, the request will fail.
    ///
    /// # Additional Parameters
    ///
    /// * *$.xgafv* (query-string) - V1 error format.
    /// * *access_token* (query-string) - OAuth access token.
    /// * *alt* (query-string) - Data format for response.
    /// * *callback* (query-string) - JSONP
    /// * *fields* (query-string) - Selector specifying which fields to include in a partial response.
    /// * *key* (query-string) - API key. Your API key identifies your project and provides you with API access, quota, and reports. Required unless you provide an OAuth 2.0 token.
    /// * *oauth_token* (query-string) - OAuth 2.0 token for the current user.
    /// * *prettyPrint* (query-boolean) - Returns response with indentations and line breaks.
    /// * *quotaUser* (query-string) - Available to use for quota purposes for server-side applications. Can be any arbitrary string assigned to a user, but should not exceed 40 characters.
    /// * *uploadType* (query-string) - Legacy upload protocol for media (e.g. "media", "multipart").
    /// * *upload_protocol* (query-string) - Upload protocol for media (e.g. "raw", "multipart").
    pub fn param<T>(mut self, name: T, value: T) -> DeviceQueryCall<'a, C>
                                                        where T: AsRef<str> {
        self._additional_params.insert(name.as_ref().to_string(), value.as_ref().to_string());
        self
    }

}


/// Reports device state and optionally sends device notifications.
/// Called by your smart home Action when the state of a third-party device
/// changes or you need to send a notification about the device.
/// See [Implement Report
/// State](https://developers.google.com/assistant/smarthome/develop/report-state)
/// for more information.
/// 
/// This method updates the device state according to its declared
/// [traits](https://developers.google.com/assistant/smarthome/concepts/devices-traits).
/// Publishing a new state value outside of these traits will result in an
/// `INVALID_ARGUMENT` error response.
/// 
/// The third-party user's identity is passed in via the `agent_user_id`
/// (see ReportStateAndNotificationRequest).
/// This request must be authorized using service account credentials from your
/// Actions console project.
///
/// A builder for the *reportStateAndNotification* method supported by a *device* resource.
/// It is not used directly, but through a `DeviceMethods` instance.
///
/// # Example
///
/// Instantiate a resource method builder
///
/// ```test_harness,no_run
/// # extern crate hyper;
/// # extern crate hyper_rustls;
/// # extern crate yup_oauth2 as oauth2;
/// # extern crate google_homegraph1 as homegraph1;
/// use homegraph1::api::ReportStateAndNotificationRequest;
/// # #[test] fn egal() {
/// # use std::default::Default;
/// # use oauth2;
/// # use homegraph1::HomeGraphService;
/// 
/// # let secret: ApplicationSecret = Default::default();
/// # let auth = yup_oauth2::InstalledFlowAuthenticator::builder(
/// #         secret,
/// #         yup_oauth2::InstalledFlowReturnMethod::HTTPRedirect,
/// #     ).build().await.unwrap();
/// # let mut hub = HomeGraphService::new(hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())), auth);
/// // As the method needs a request, you would usually fill it with the desired information
/// // into the respective structure. Some of the parts shown here might not be applicable !
/// // Values shown here are possibly random and not representative !
/// let mut req = ReportStateAndNotificationRequest::default();
/// 
/// // You can configure optional parameters by calling the respective setters at will, and
/// // execute the final call using `doit()`.
/// // Values shown here are possibly random and not representative !
/// let result = hub.devices().report_state_and_notification(req)
///              .doit();
/// # }
/// ```
pub struct DeviceReportStateAndNotificationCall<'a, C>
    where C: 'a {

    hub: &'a HomeGraphService<C>,
    _request: ReportStateAndNotificationRequest,
    _delegate: Option<&'a mut dyn client::Delegate>,
    _additional_params: HashMap<String, String>,
}

impl<'a, C> client::CallBuilder for DeviceReportStateAndNotificationCall<'a, C> {}

impl<'a, C> DeviceReportStateAndNotificationCall<'a, C> where C: BorrowMut<hyper::Client<hyper_rustls::HttpsConnector<hyper::client::connect::HttpConnector>, hyper::body::Body>> {


    /// Perform the operation you have build so far.
    pub async fn doit(mut self) -> client::Result<(hyper::Response<hyper::body::Body>, ReportStateAndNotificationResponse)> {
        use std::io::{Read, Seek};
        use hyper::header::{CONTENT_TYPE, CONTENT_LENGTH, AUTHORIZATION, USER_AGENT, LOCATION};
        use client::ToParts;
        let mut dd = client::DefaultDelegate;
        let mut dlg: &mut dyn client::Delegate = match self._delegate {
            Some(d) => d,
            None => &mut dd
        };
        dlg.begin(client::MethodInfo { id: "homegraph.devices.reportStateAndNotification",
                               http_method: hyper::Method::POST });
        let mut params: Vec<(&str, String)> = Vec::with_capacity(3 + self._additional_params.len());
        for &field in ["alt"].iter() {
            if self._additional_params.contains_key(field) {
                dlg.finished(false);
                return Err(client::Error::FieldClash(field));
            }
        }
        for (name, value) in self._additional_params.iter() {
            params.push((&name, value.clone()));
        }

        params.push(("alt", "json".to_string()));

        let mut url = self.hub._base_url.clone() + "v1/devices:reportStateAndNotification";
        
        let mut key = self.hub.auth.borrow_mut().api_key();
        if key.is_none() {
            key = dlg.api_key();
        }
        match key {
            Some(value) => params.push(("key", value)),
            None => {
                dlg.finished(false);
                return Err(client::Error::MissingAPIKey)
            }
        }


        let url = url::Url::parse_with_params(&url, params).unwrap();

        let mut json_mime_type: mime::Mime = "application/json".parse().unwrap();
        let mut request_value_reader =
            {
                let mut value = json::value::to_value(&self._request).expect("serde to work");
                client::remove_json_null_values(&mut value);
                let mut dst = io::Cursor::new(Vec::with_capacity(128));
                json::to_writer(&mut dst, &value).unwrap();
                dst
            };
        let request_size = request_value_reader.seek(io::SeekFrom::End(0)).unwrap();
        request_value_reader.seek(io::SeekFrom::Start(0)).unwrap();


        loop {
            request_value_reader.seek(io::SeekFrom::Start(0)).unwrap();
            let mut req_result = {
                let mut client = &mut *self.hub.client.borrow_mut();
                dlg.pre_request();
                let mut req_builder = hyper::Request::builder().method(hyper::Method::POST).uri(url.clone().into_string())
                        .header(USER_AGENT, self.hub._user_agent.clone());


                        let request = req_builder
                        .header(CONTENT_TYPE, format!("{}", json_mime_type))
                        .header(CONTENT_LENGTH, request_size as u64)
                        .body(hyper::body::Body::from(request_value_reader.get_ref().clone()));

                client.borrow_mut().request(request.unwrap()).await
                
            };

            match req_result {
                Err(err) => {
                    if let client::Retry::After(d) = dlg.http_error(&err) {
                        sleep(d);
                        continue;
                    }
                    dlg.finished(false);
                    return Err(client::Error::HttpError(err))
                }
                Ok(mut res) => {
                    let (res_parts, res_body) = res.into_parts();
                    let res_body_string: String = String::from_utf8(
                        hyper::body::to_bytes(res_body)
                            .await
                            .unwrap()
                            .into_iter()
                            .collect(),
                    )
                    .unwrap();
                    let reconstructed_result =
                        hyper::Response::from_parts(res_parts, res_body_string.clone().into());

                    if !reconstructed_result.status().is_success() {
                        let json_server_error = json::from_str::<client::JsonServerError>(&res_body_string).ok();
                        let server_error = json::from_str::<client::ServerError>(&res_body_string)
                            .or_else(|_| json::from_str::<client::ErrorResponse>(&res_body_string).map(|r| r.error))
                            .ok();

                        if let client::Retry::After(d) = dlg.http_failure(&reconstructed_result,
                                                              json_server_error,
                                                              server_error) {
                            sleep(d);
                            continue;
                        }
                        dlg.finished(false);
                        return match json::from_str::<client::ErrorResponse>(&res_body_string){
                            Err(_) => Err(client::Error::Failure(reconstructed_result)),
                            Ok(serr) => Err(client::Error::BadRequest(serr))
                        }
                    }
                    let result_value = {
                        match json::from_str(&res_body_string) {
                            Ok(decoded) => (reconstructed_result, decoded),
                            Err(err) => {
                                dlg.response_json_decode_error(&res_body_string, &err);
                                return Err(client::Error::JsonDecodeError(res_body_string, err));
                            }
                        }
                    };

                    dlg.finished(true);
                    return Ok(result_value)
                }
            }
        }
    }


    ///
    /// Sets the *request* property to the given value.
    ///
    /// Even though the property as already been set when instantiating this call,
    /// we provide this method for API completeness.
    pub fn request(mut self, new_value: ReportStateAndNotificationRequest) -> DeviceReportStateAndNotificationCall<'a, C> {
        self._request = new_value;
        self
    }
    /// The delegate implementation is consulted whenever there is an intermediate result, or if something goes wrong
    /// while executing the actual API request.
    /// 
    /// It should be used to handle progress information, and to implement a certain level of resilience.
    ///
    /// Sets the *delegate* property to the given value.
    pub fn delegate(mut self, new_value: &'a mut dyn client::Delegate) -> DeviceReportStateAndNotificationCall<'a, C> {
        self._delegate = Some(new_value);
        self
    }

    /// Set any additional parameter of the query string used in the request.
    /// It should be used to set parameters which are not yet available through their own
    /// setters.
    ///
    /// Please note that this method must not be used to set any of the known parameters
    /// which have their own setter method. If done anyway, the request will fail.
    ///
    /// # Additional Parameters
    ///
    /// * *$.xgafv* (query-string) - V1 error format.
    /// * *access_token* (query-string) - OAuth access token.
    /// * *alt* (query-string) - Data format for response.
    /// * *callback* (query-string) - JSONP
    /// * *fields* (query-string) - Selector specifying which fields to include in a partial response.
    /// * *key* (query-string) - API key. Your API key identifies your project and provides you with API access, quota, and reports. Required unless you provide an OAuth 2.0 token.
    /// * *oauth_token* (query-string) - OAuth 2.0 token for the current user.
    /// * *prettyPrint* (query-boolean) - Returns response with indentations and line breaks.
    /// * *quotaUser* (query-string) - Available to use for quota purposes for server-side applications. Can be any arbitrary string assigned to a user, but should not exceed 40 characters.
    /// * *uploadType* (query-string) - Legacy upload protocol for media (e.g. "media", "multipart").
    /// * *upload_protocol* (query-string) - Upload protocol for media (e.g. "raw", "multipart").
    pub fn param<T>(mut self, name: T, value: T) -> DeviceReportStateAndNotificationCall<'a, C>
                                                        where T: AsRef<str> {
        self._additional_params.insert(name.as_ref().to_string(), value.as_ref().to_string());
        self
    }

}


/// Requests Google to send an `action.devices.SYNC`
/// [intent](https://developers.google.com/assistant/smarthome/reference/intent/sync)
/// to your smart home Action to update device metadata for the given user.
/// 
/// 
/// The third-party user's identity is passed via the `agent_user_id`
/// (see RequestSyncDevicesRequest).
/// This request must be authorized using service account credentials from your
/// Actions console project.
///
/// A builder for the *requestSync* method supported by a *device* resource.
/// It is not used directly, but through a `DeviceMethods` instance.
///
/// # Example
///
/// Instantiate a resource method builder
///
/// ```test_harness,no_run
/// # extern crate hyper;
/// # extern crate hyper_rustls;
/// # extern crate yup_oauth2 as oauth2;
/// # extern crate google_homegraph1 as homegraph1;
/// use homegraph1::api::RequestSyncDevicesRequest;
/// # #[test] fn egal() {
/// # use std::default::Default;
/// # use oauth2;
/// # use homegraph1::HomeGraphService;
/// 
/// # let secret: ApplicationSecret = Default::default();
/// # let auth = yup_oauth2::InstalledFlowAuthenticator::builder(
/// #         secret,
/// #         yup_oauth2::InstalledFlowReturnMethod::HTTPRedirect,
/// #     ).build().await.unwrap();
/// # let mut hub = HomeGraphService::new(hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())), auth);
/// // As the method needs a request, you would usually fill it with the desired information
/// // into the respective structure. Some of the parts shown here might not be applicable !
/// // Values shown here are possibly random and not representative !
/// let mut req = RequestSyncDevicesRequest::default();
/// 
/// // You can configure optional parameters by calling the respective setters at will, and
/// // execute the final call using `doit()`.
/// // Values shown here are possibly random and not representative !
/// let result = hub.devices().request_sync(req)
///              .doit();
/// # }
/// ```
pub struct DeviceRequestSyncCall<'a, C>
    where C: 'a {

    hub: &'a HomeGraphService<C>,
    _request: RequestSyncDevicesRequest,
    _delegate: Option<&'a mut dyn client::Delegate>,
    _additional_params: HashMap<String, String>,
}

impl<'a, C> client::CallBuilder for DeviceRequestSyncCall<'a, C> {}

impl<'a, C> DeviceRequestSyncCall<'a, C> where C: BorrowMut<hyper::Client<hyper_rustls::HttpsConnector<hyper::client::connect::HttpConnector>, hyper::body::Body>> {


    /// Perform the operation you have build so far.
    pub async fn doit(mut self) -> client::Result<(hyper::Response<hyper::body::Body>, RequestSyncDevicesResponse)> {
        use std::io::{Read, Seek};
        use hyper::header::{CONTENT_TYPE, CONTENT_LENGTH, AUTHORIZATION, USER_AGENT, LOCATION};
        use client::ToParts;
        let mut dd = client::DefaultDelegate;
        let mut dlg: &mut dyn client::Delegate = match self._delegate {
            Some(d) => d,
            None => &mut dd
        };
        dlg.begin(client::MethodInfo { id: "homegraph.devices.requestSync",
                               http_method: hyper::Method::POST });
        let mut params: Vec<(&str, String)> = Vec::with_capacity(3 + self._additional_params.len());
        for &field in ["alt"].iter() {
            if self._additional_params.contains_key(field) {
                dlg.finished(false);
                return Err(client::Error::FieldClash(field));
            }
        }
        for (name, value) in self._additional_params.iter() {
            params.push((&name, value.clone()));
        }

        params.push(("alt", "json".to_string()));

        let mut url = self.hub._base_url.clone() + "v1/devices:requestSync";
        
        let mut key = self.hub.auth.borrow_mut().api_key();
        if key.is_none() {
            key = dlg.api_key();
        }
        match key {
            Some(value) => params.push(("key", value)),
            None => {
                dlg.finished(false);
                return Err(client::Error::MissingAPIKey)
            }
        }


        let url = url::Url::parse_with_params(&url, params).unwrap();

        let mut json_mime_type: mime::Mime = "application/json".parse().unwrap();
        let mut request_value_reader =
            {
                let mut value = json::value::to_value(&self._request).expect("serde to work");
                client::remove_json_null_values(&mut value);
                let mut dst = io::Cursor::new(Vec::with_capacity(128));
                json::to_writer(&mut dst, &value).unwrap();
                dst
            };
        let request_size = request_value_reader.seek(io::SeekFrom::End(0)).unwrap();
        request_value_reader.seek(io::SeekFrom::Start(0)).unwrap();


        loop {
            request_value_reader.seek(io::SeekFrom::Start(0)).unwrap();
            let mut req_result = {
                let mut client = &mut *self.hub.client.borrow_mut();
                dlg.pre_request();
                let mut req_builder = hyper::Request::builder().method(hyper::Method::POST).uri(url.clone().into_string())
                        .header(USER_AGENT, self.hub._user_agent.clone());


                        let request = req_builder
                        .header(CONTENT_TYPE, format!("{}", json_mime_type))
                        .header(CONTENT_LENGTH, request_size as u64)
                        .body(hyper::body::Body::from(request_value_reader.get_ref().clone()));

                client.borrow_mut().request(request.unwrap()).await
                
            };

            match req_result {
                Err(err) => {
                    if let client::Retry::After(d) = dlg.http_error(&err) {
                        sleep(d);
                        continue;
                    }
                    dlg.finished(false);
                    return Err(client::Error::HttpError(err))
                }
                Ok(mut res) => {
                    let (res_parts, res_body) = res.into_parts();
                    let res_body_string: String = String::from_utf8(
                        hyper::body::to_bytes(res_body)
                            .await
                            .unwrap()
                            .into_iter()
                            .collect(),
                    )
                    .unwrap();
                    let reconstructed_result =
                        hyper::Response::from_parts(res_parts, res_body_string.clone().into());

                    if !reconstructed_result.status().is_success() {
                        let json_server_error = json::from_str::<client::JsonServerError>(&res_body_string).ok();
                        let server_error = json::from_str::<client::ServerError>(&res_body_string)
                            .or_else(|_| json::from_str::<client::ErrorResponse>(&res_body_string).map(|r| r.error))
                            .ok();

                        if let client::Retry::After(d) = dlg.http_failure(&reconstructed_result,
                                                              json_server_error,
                                                              server_error) {
                            sleep(d);
                            continue;
                        }
                        dlg.finished(false);
                        return match json::from_str::<client::ErrorResponse>(&res_body_string){
                            Err(_) => Err(client::Error::Failure(reconstructed_result)),
                            Ok(serr) => Err(client::Error::BadRequest(serr))
                        }
                    }
                    let result_value = {
                        match json::from_str(&res_body_string) {
                            Ok(decoded) => (reconstructed_result, decoded),
                            Err(err) => {
                                dlg.response_json_decode_error(&res_body_string, &err);
                                return Err(client::Error::JsonDecodeError(res_body_string, err));
                            }
                        }
                    };

                    dlg.finished(true);
                    return Ok(result_value)
                }
            }
        }
    }


    ///
    /// Sets the *request* property to the given value.
    ///
    /// Even though the property as already been set when instantiating this call,
    /// we provide this method for API completeness.
    pub fn request(mut self, new_value: RequestSyncDevicesRequest) -> DeviceRequestSyncCall<'a, C> {
        self._request = new_value;
        self
    }
    /// The delegate implementation is consulted whenever there is an intermediate result, or if something goes wrong
    /// while executing the actual API request.
    /// 
    /// It should be used to handle progress information, and to implement a certain level of resilience.
    ///
    /// Sets the *delegate* property to the given value.
    pub fn delegate(mut self, new_value: &'a mut dyn client::Delegate) -> DeviceRequestSyncCall<'a, C> {
        self._delegate = Some(new_value);
        self
    }

    /// Set any additional parameter of the query string used in the request.
    /// It should be used to set parameters which are not yet available through their own
    /// setters.
    ///
    /// Please note that this method must not be used to set any of the known parameters
    /// which have their own setter method. If done anyway, the request will fail.
    ///
    /// # Additional Parameters
    ///
    /// * *$.xgafv* (query-string) - V1 error format.
    /// * *access_token* (query-string) - OAuth access token.
    /// * *alt* (query-string) - Data format for response.
    /// * *callback* (query-string) - JSONP
    /// * *fields* (query-string) - Selector specifying which fields to include in a partial response.
    /// * *key* (query-string) - API key. Your API key identifies your project and provides you with API access, quota, and reports. Required unless you provide an OAuth 2.0 token.
    /// * *oauth_token* (query-string) - OAuth 2.0 token for the current user.
    /// * *prettyPrint* (query-boolean) - Returns response with indentations and line breaks.
    /// * *quotaUser* (query-string) - Available to use for quota purposes for server-side applications. Can be any arbitrary string assigned to a user, but should not exceed 40 characters.
    /// * *uploadType* (query-string) - Legacy upload protocol for media (e.g. "media", "multipart").
    /// * *upload_protocol* (query-string) - Upload protocol for media (e.g. "raw", "multipart").
    pub fn param<T>(mut self, name: T, value: T) -> DeviceRequestSyncCall<'a, C>
                                                        where T: AsRef<str> {
        self._additional_params.insert(name.as_ref().to_string(), value.as_ref().to_string());
        self
    }

}


/// Gets all the devices associated with the given third-party user.
/// 
/// The third-party user's identity is passed in via the `agent_user_id`
/// (see SyncRequest).
/// This request must be authorized using service account credentials from your
/// Actions console project.
///
/// A builder for the *sync* method supported by a *device* resource.
/// It is not used directly, but through a `DeviceMethods` instance.
///
/// # Example
///
/// Instantiate a resource method builder
///
/// ```test_harness,no_run
/// # extern crate hyper;
/// # extern crate hyper_rustls;
/// # extern crate yup_oauth2 as oauth2;
/// # extern crate google_homegraph1 as homegraph1;
/// use homegraph1::api::SyncRequest;
/// # #[test] fn egal() {
/// # use std::default::Default;
/// # use oauth2;
/// # use homegraph1::HomeGraphService;
/// 
/// # let secret: ApplicationSecret = Default::default();
/// # let auth = yup_oauth2::InstalledFlowAuthenticator::builder(
/// #         secret,
/// #         yup_oauth2::InstalledFlowReturnMethod::HTTPRedirect,
/// #     ).build().await.unwrap();
/// # let mut hub = HomeGraphService::new(hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())), auth);
/// // As the method needs a request, you would usually fill it with the desired information
/// // into the respective structure. Some of the parts shown here might not be applicable !
/// // Values shown here are possibly random and not representative !
/// let mut req = SyncRequest::default();
/// 
/// // You can configure optional parameters by calling the respective setters at will, and
/// // execute the final call using `doit()`.
/// // Values shown here are possibly random and not representative !
/// let result = hub.devices().sync(req)
///              .doit();
/// # }
/// ```
pub struct DeviceSyncCall<'a, C>
    where C: 'a {

    hub: &'a HomeGraphService<C>,
    _request: SyncRequest,
    _delegate: Option<&'a mut dyn client::Delegate>,
    _additional_params: HashMap<String, String>,
}

impl<'a, C> client::CallBuilder for DeviceSyncCall<'a, C> {}

impl<'a, C> DeviceSyncCall<'a, C> where C: BorrowMut<hyper::Client<hyper_rustls::HttpsConnector<hyper::client::connect::HttpConnector>, hyper::body::Body>> {


    /// Perform the operation you have build so far.
    pub async fn doit(mut self) -> client::Result<(hyper::Response<hyper::body::Body>, SyncResponse)> {
        use std::io::{Read, Seek};
        use hyper::header::{CONTENT_TYPE, CONTENT_LENGTH, AUTHORIZATION, USER_AGENT, LOCATION};
        use client::ToParts;
        let mut dd = client::DefaultDelegate;
        let mut dlg: &mut dyn client::Delegate = match self._delegate {
            Some(d) => d,
            None => &mut dd
        };
        dlg.begin(client::MethodInfo { id: "homegraph.devices.sync",
                               http_method: hyper::Method::POST });
        let mut params: Vec<(&str, String)> = Vec::with_capacity(3 + self._additional_params.len());
        for &field in ["alt"].iter() {
            if self._additional_params.contains_key(field) {
                dlg.finished(false);
                return Err(client::Error::FieldClash(field));
            }
        }
        for (name, value) in self._additional_params.iter() {
            params.push((&name, value.clone()));
        }

        params.push(("alt", "json".to_string()));

        let mut url = self.hub._base_url.clone() + "v1/devices:sync";
        
        let mut key = self.hub.auth.borrow_mut().api_key();
        if key.is_none() {
            key = dlg.api_key();
        }
        match key {
            Some(value) => params.push(("key", value)),
            None => {
                dlg.finished(false);
                return Err(client::Error::MissingAPIKey)
            }
        }


        let url = url::Url::parse_with_params(&url, params).unwrap();

        let mut json_mime_type: mime::Mime = "application/json".parse().unwrap();
        let mut request_value_reader =
            {
                let mut value = json::value::to_value(&self._request).expect("serde to work");
                client::remove_json_null_values(&mut value);
                let mut dst = io::Cursor::new(Vec::with_capacity(128));
                json::to_writer(&mut dst, &value).unwrap();
                dst
            };
        let request_size = request_value_reader.seek(io::SeekFrom::End(0)).unwrap();
        request_value_reader.seek(io::SeekFrom::Start(0)).unwrap();


        loop {
            request_value_reader.seek(io::SeekFrom::Start(0)).unwrap();
            let mut req_result = {
                let mut client = &mut *self.hub.client.borrow_mut();
                dlg.pre_request();
                let mut req_builder = hyper::Request::builder().method(hyper::Method::POST).uri(url.clone().into_string())
                        .header(USER_AGENT, self.hub._user_agent.clone());


                        let request = req_builder
                        .header(CONTENT_TYPE, format!("{}", json_mime_type))
                        .header(CONTENT_LENGTH, request_size as u64)
                        .body(hyper::body::Body::from(request_value_reader.get_ref().clone()));

                client.borrow_mut().request(request.unwrap()).await
                
            };

            match req_result {
                Err(err) => {
                    if let client::Retry::After(d) = dlg.http_error(&err) {
                        sleep(d);
                        continue;
                    }
                    dlg.finished(false);
                    return Err(client::Error::HttpError(err))
                }
                Ok(mut res) => {
                    let (res_parts, res_body) = res.into_parts();
                    let res_body_string: String = String::from_utf8(
                        hyper::body::to_bytes(res_body)
                            .await
                            .unwrap()
                            .into_iter()
                            .collect(),
                    )
                    .unwrap();
                    let reconstructed_result =
                        hyper::Response::from_parts(res_parts, res_body_string.clone().into());

                    if !reconstructed_result.status().is_success() {
                        let json_server_error = json::from_str::<client::JsonServerError>(&res_body_string).ok();
                        let server_error = json::from_str::<client::ServerError>(&res_body_string)
                            .or_else(|_| json::from_str::<client::ErrorResponse>(&res_body_string).map(|r| r.error))
                            .ok();

                        if let client::Retry::After(d) = dlg.http_failure(&reconstructed_result,
                                                              json_server_error,
                                                              server_error) {
                            sleep(d);
                            continue;
                        }
                        dlg.finished(false);
                        return match json::from_str::<client::ErrorResponse>(&res_body_string){
                            Err(_) => Err(client::Error::Failure(reconstructed_result)),
                            Ok(serr) => Err(client::Error::BadRequest(serr))
                        }
                    }
                    let result_value = {
                        match json::from_str(&res_body_string) {
                            Ok(decoded) => (reconstructed_result, decoded),
                            Err(err) => {
                                dlg.response_json_decode_error(&res_body_string, &err);
                                return Err(client::Error::JsonDecodeError(res_body_string, err));
                            }
                        }
                    };

                    dlg.finished(true);
                    return Ok(result_value)
                }
            }
        }
    }


    ///
    /// Sets the *request* property to the given value.
    ///
    /// Even though the property as already been set when instantiating this call,
    /// we provide this method for API completeness.
    pub fn request(mut self, new_value: SyncRequest) -> DeviceSyncCall<'a, C> {
        self._request = new_value;
        self
    }
    /// The delegate implementation is consulted whenever there is an intermediate result, or if something goes wrong
    /// while executing the actual API request.
    /// 
    /// It should be used to handle progress information, and to implement a certain level of resilience.
    ///
    /// Sets the *delegate* property to the given value.
    pub fn delegate(mut self, new_value: &'a mut dyn client::Delegate) -> DeviceSyncCall<'a, C> {
        self._delegate = Some(new_value);
        self
    }

    /// Set any additional parameter of the query string used in the request.
    /// It should be used to set parameters which are not yet available through their own
    /// setters.
    ///
    /// Please note that this method must not be used to set any of the known parameters
    /// which have their own setter method. If done anyway, the request will fail.
    ///
    /// # Additional Parameters
    ///
    /// * *$.xgafv* (query-string) - V1 error format.
    /// * *access_token* (query-string) - OAuth access token.
    /// * *alt* (query-string) - Data format for response.
    /// * *callback* (query-string) - JSONP
    /// * *fields* (query-string) - Selector specifying which fields to include in a partial response.
    /// * *key* (query-string) - API key. Your API key identifies your project and provides you with API access, quota, and reports. Required unless you provide an OAuth 2.0 token.
    /// * *oauth_token* (query-string) - OAuth 2.0 token for the current user.
    /// * *prettyPrint* (query-boolean) - Returns response with indentations and line breaks.
    /// * *quotaUser* (query-string) - Available to use for quota purposes for server-side applications. Can be any arbitrary string assigned to a user, but should not exceed 40 characters.
    /// * *uploadType* (query-string) - Legacy upload protocol for media (e.g. "media", "multipart").
    /// * *upload_protocol* (query-string) - Upload protocol for media (e.g. "raw", "multipart").
    pub fn param<T>(mut self, name: T, value: T) -> DeviceSyncCall<'a, C>
                                                        where T: AsRef<str> {
        self._additional_params.insert(name.as_ref().to_string(), value.as_ref().to_string());
        self
    }

}


