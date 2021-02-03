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

/// Central instance to access all SearchConsole related resource activities
///
/// # Examples
///
/// Instantiate a new hub
///
/// ```test_harness,no_run
/// extern crate hyper;
/// extern crate hyper_rustls;
/// extern crate yup_oauth2 as oauth2;
/// extern crate google_searchconsole1 as searchconsole1;
/// use searchconsole1::api::RunMobileFriendlyTestRequest;
/// use searchconsole1::{Result, Error};
/// # #[test] fn egal() {
/// use std::default::Default;
/// use oauth2::{Authenticator, DefaultAuthenticatorDelegate, ApplicationSecret, MemoryStorage};
/// use searchconsole1::SearchConsole;
/// 
/// // Get an ApplicationSecret instance by some means. It contains the `client_id` and 
/// // `client_secret`, among other things.
/// let secret: ApplicationSecret = Default::default();
/// // Instantiate the authenticator. It will choose a suitable authentication flow for you, 
/// // unless you replace  `None` with the desired Flow.
/// // Provide your own `AuthenticatorDelegate` to adjust the way it operates and get feedback about 
/// // what's going on. You probably want to bring in your own `TokenStorage` to persist tokens and
/// // retrieve them from storage.
/// let auth = Authenticator::new(&secret, DefaultAuthenticatorDelegate,
///                               hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())),
///                               <MemoryStorage as Default>::default(), None);
/// let mut hub = SearchConsole::new(hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())), auth);
/// // As the method needs a request, you would usually fill it with the desired information
/// // into the respective structure. Some of the parts shown here might not be applicable !
/// // Values shown here are possibly random and not representative !
/// let mut req = RunMobileFriendlyTestRequest::default();
/// 
/// // You can configure optional parameters by calling the respective setters at will, and
/// // execute the final call using `doit()`.
/// // Values shown here are possibly random and not representative !
/// let result = hub.url_testing_tools().mobile_friendly_test_run(req)
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
pub struct SearchConsole<C> {
    client: RefCell<C>,
    auth: RefCell<oauth2::authenticator::Authenticator<hyper_rustls::HttpsConnector<hyper::client::connect::HttpConnector>>>,
    _user_agent: String,
    _base_url: String,
    _root_url: String,
}

impl<'a, C> client::Hub for SearchConsole<C> {}

impl<'a, C> SearchConsole<C>
    where  C: BorrowMut<hyper::Client<hyper_rustls::HttpsConnector<hyper::client::connect::HttpConnector>, hyper::body::Body>> {

    pub fn new(client: C, authenticator: oauth2::authenticator::Authenticator<hyper_rustls::HttpsConnector<hyper::client::connect::HttpConnector>>) -> SearchConsole<C> {
        SearchConsole {
            client: RefCell::new(client),
            auth: RefCell::new(authenticator),
            _user_agent: "google-api-rust-client/1.0.14".to_string(),
            _base_url: "https://searchconsole.googleapis.com/".to_string(),
            _root_url: "https://searchconsole.googleapis.com/".to_string(),
        }
    }

    pub fn url_testing_tools(&'a self) -> UrlTestingToolMethods<'a, C> {
        UrlTestingToolMethods { hub: &self }
    }

    /// Set the user-agent header field to use in all requests to the server.
    /// It defaults to `google-api-rust-client/1.0.14`.
    ///
    /// Returns the previously set user-agent.
    pub fn user_agent(&mut self, agent_name: String) -> String {
        mem::replace(&mut self._user_agent, agent_name)
    }

    /// Set the base url to use in all requests to the server.
    /// It defaults to `https://searchconsole.googleapis.com/`.
    ///
    /// Returns the previously set base url.
    pub fn base_url(&mut self, new_base_url: String) -> String {
        mem::replace(&mut self._base_url, new_base_url)
    }

    /// Set the root url to use in all requests to the server.
    /// It defaults to `https://searchconsole.googleapis.com/`.
    ///
    /// Returns the previously set root url.
    pub fn root_url(&mut self, new_root_url: String) -> String {
        mem::replace(&mut self._root_url, new_root_url)
    }
}


// ############
// SCHEMAS ###
// ##########
/// Blocked resource.
/// 
/// This type is not used in any activity, and only used as *part* of another schema.
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct BlockedResource {
    /// URL of the blocked resource.
    pub url: Option<String>,
}

impl client::Part for BlockedResource {}


/// Describe image data.
/// 
/// This type is not used in any activity, and only used as *part* of another schema.
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct Image {
    /// Image data in format determined by the mime type. Currently, the format
    /// will always be "image/png", but this might change in the future.
    pub data: Option<String>,
    /// The mime-type of the image data.
    #[serde(rename="mimeType")]
    pub mime_type: Option<String>,
}

impl client::Part for Image {}


/// Mobile-friendly issue.
/// 
/// This type is not used in any activity, and only used as *part* of another schema.
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct MobileFriendlyIssue {
    /// Rule violated.
    pub rule: Option<String>,
}

impl client::Part for MobileFriendlyIssue {}


/// Information about a resource with issue.
/// 
/// This type is not used in any activity, and only used as *part* of another schema.
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct ResourceIssue {
    /// Describes a blocked resource issue.
    #[serde(rename="blockedResource")]
    pub blocked_resource: Option<BlockedResource>,
}

impl client::Part for ResourceIssue {}


/// Mobile-friendly test request.
/// 
/// # Activities
/// 
/// This type is used in activities, which are methods you may call on this type or where this type is involved in. 
/// The list links the activity name, along with information about where it is used (one of *request* and *response*).
/// 
/// * [mobile friendly test run url testing tools](UrlTestingToolMobileFriendlyTestRunCall) (request)
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct RunMobileFriendlyTestRequest {
    /// Whether or not screenshot is requested. Default is false.
    #[serde(rename="requestScreenshot")]
    pub request_screenshot: Option<bool>,
    /// URL for inspection.
    pub url: Option<String>,
}

impl client::RequestValue for RunMobileFriendlyTestRequest {}


/// Mobile-friendly test response, including mobile-friendly issues and resource
/// issues.
/// 
/// # Activities
/// 
/// This type is used in activities, which are methods you may call on this type or where this type is involved in. 
/// The list links the activity name, along with information about where it is used (one of *request* and *response*).
/// 
/// * [mobile friendly test run url testing tools](UrlTestingToolMobileFriendlyTestRunCall) (response)
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct RunMobileFriendlyTestResponse {
    /// Test verdict, whether the page is mobile friendly or not.
    #[serde(rename="mobileFriendliness")]
    pub mobile_friendliness: Option<String>,
    /// List of mobile-usability issues.
    #[serde(rename="mobileFriendlyIssues")]
    pub mobile_friendly_issues: Option<Vec<MobileFriendlyIssue>>,
    /// Information about embedded resources issues.
    #[serde(rename="resourceIssues")]
    pub resource_issues: Option<Vec<ResourceIssue>>,
    /// Screenshot of the requested URL.
    pub screenshot: Option<Image>,
    /// Final state of the test, can be either complete or an error.
    #[serde(rename="testStatus")]
    pub test_status: Option<TestStatus>,
}

impl client::ResponseResult for RunMobileFriendlyTestResponse {}


/// Final state of the test, including error details if necessary.
/// 
/// This type is not used in any activity, and only used as *part* of another schema.
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct TestStatus {
    /// Error details if applicable.
    pub details: Option<String>,
    /// Status of the test.
    pub status: Option<String>,
}

impl client::Part for TestStatus {}



// ###################
// MethodBuilders ###
// #################

/// A builder providing access to all methods supported on *urlTestingTool* resources.
/// It is not used directly, but through the `SearchConsole` hub.
///
/// # Example
///
/// Instantiate a resource builder
///
/// ```test_harness,no_run
/// extern crate hyper;
/// extern crate hyper_rustls;
/// extern crate yup_oauth2 as oauth2;
/// extern crate google_searchconsole1 as searchconsole1;
/// 
/// # #[test] fn egal() {
/// use std::default::Default;
/// use oauth2::{Authenticator, DefaultAuthenticatorDelegate, ApplicationSecret, MemoryStorage};
/// use searchconsole1::SearchConsole;
/// 
/// let secret: ApplicationSecret = Default::default();
/// let auth = Authenticator::new(&secret, DefaultAuthenticatorDelegate,
///                               hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())),
///                               <MemoryStorage as Default>::default(), None);
/// let mut hub = SearchConsole::new(hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())), auth);
/// // Usually you wouldn't bind this to a variable, but keep calling *CallBuilders*
/// // like `mobile_friendly_test_run(...)`
/// // to build up your call.
/// let rb = hub.url_testing_tools();
/// # }
/// ```
pub struct UrlTestingToolMethods<'a, C>
    where C: 'a {

    hub: &'a SearchConsole<C>,
}

impl<'a, C> client::MethodsBuilder for UrlTestingToolMethods<'a, C> {}

impl<'a, C> UrlTestingToolMethods<'a, C> {
    
    /// Create a builder to help you perform the following task:
    ///
    /// Runs Mobile-Friendly Test for a given URL.
    /// 
    /// # Arguments
    ///
    /// * `request` - No description provided.
    pub fn mobile_friendly_test_run(&self, request: RunMobileFriendlyTestRequest) -> UrlTestingToolMobileFriendlyTestRunCall<'a, C> {
        UrlTestingToolMobileFriendlyTestRunCall {
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

/// Runs Mobile-Friendly Test for a given URL.
///
/// A builder for the *mobileFriendlyTest.run* method supported by a *urlTestingTool* resource.
/// It is not used directly, but through a `UrlTestingToolMethods` instance.
///
/// # Example
///
/// Instantiate a resource method builder
///
/// ```test_harness,no_run
/// # extern crate hyper;
/// # extern crate hyper_rustls;
/// # extern crate yup_oauth2 as oauth2;
/// # extern crate google_searchconsole1 as searchconsole1;
/// use searchconsole1::api::RunMobileFriendlyTestRequest;
/// # #[test] fn egal() {
/// # use std::default::Default;
/// # use oauth2::{Authenticator, DefaultAuthenticatorDelegate, ApplicationSecret, MemoryStorage};
/// # use searchconsole1::SearchConsole;
/// 
/// # let secret: ApplicationSecret = Default::default();
/// # let auth = Authenticator::new(&secret, DefaultAuthenticatorDelegate,
/// #                               hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())),
/// #                               <MemoryStorage as Default>::default(), None);
/// # let mut hub = SearchConsole::new(hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())), auth);
/// // As the method needs a request, you would usually fill it with the desired information
/// // into the respective structure. Some of the parts shown here might not be applicable !
/// // Values shown here are possibly random and not representative !
/// let mut req = RunMobileFriendlyTestRequest::default();
/// 
/// // You can configure optional parameters by calling the respective setters at will, and
/// // execute the final call using `doit()`.
/// // Values shown here are possibly random and not representative !
/// let result = hub.url_testing_tools().mobile_friendly_test_run(req)
///              .doit();
/// # }
/// ```
pub struct UrlTestingToolMobileFriendlyTestRunCall<'a, C>
    where C: 'a {

    hub: &'a SearchConsole<C>,
    _request: RunMobileFriendlyTestRequest,
    _delegate: Option<&'a mut dyn client::Delegate>,
    _additional_params: HashMap<String, String>,
}

impl<'a, C> client::CallBuilder for UrlTestingToolMobileFriendlyTestRunCall<'a, C> {}

impl<'a, C> UrlTestingToolMobileFriendlyTestRunCall<'a, C> where C: BorrowMut<hyper::Client<hyper_rustls::HttpsConnector<hyper::client::connect::HttpConnector>, hyper::body::Body>> {


    /// Perform the operation you have build so far.
    pub async fn doit(mut self) -> client::Result<(hyper::Response<hyper::body::Body>, RunMobileFriendlyTestResponse)> {
        use std::io::{Read, Seek};
        use hyper::header::{CONTENT_TYPE, CONTENT_LENGTH, AUTHORIZATION, USER_AGENT, LOCATION};
        use client::ToParts;
        let mut dd = client::DefaultDelegate;
        let mut dlg: &mut dyn client::Delegate = match self._delegate {
            Some(d) => d,
            None => &mut dd
        };
        dlg.begin(client::MethodInfo { id: "searchconsole.urlTestingTools.mobileFriendlyTest.run",
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

        let mut url = self.hub._base_url.clone() + "v1/urlTestingTools/mobileFriendlyTest:run";
        
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
    pub fn request(mut self, new_value: RunMobileFriendlyTestRequest) -> UrlTestingToolMobileFriendlyTestRunCall<'a, C> {
        self._request = new_value;
        self
    }
    /// The delegate implementation is consulted whenever there is an intermediate result, or if something goes wrong
    /// while executing the actual API request.
    /// 
    /// It should be used to handle progress information, and to implement a certain level of resilience.
    ///
    /// Sets the *delegate* property to the given value.
    pub fn delegate(mut self, new_value: &'a mut dyn client::Delegate) -> UrlTestingToolMobileFriendlyTestRunCall<'a, C> {
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
    pub fn param<T>(mut self, name: T, value: T) -> UrlTestingToolMobileFriendlyTestRunCall<'a, C>
                                                        where T: AsRef<str> {
        self._additional_params.insert(name.as_ref().to_string(), value.as_ref().to_string());
        self
    }

}


