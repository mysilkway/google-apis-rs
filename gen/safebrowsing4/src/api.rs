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

/// Central instance to access all Safebrowsing related resource activities
///
/// # Examples
///
/// Instantiate a new hub
///
/// ```test_harness,no_run
/// extern crate hyper;
/// extern crate hyper_rustls;
/// extern crate yup_oauth2 as oauth2;
/// extern crate google_safebrowsing4 as safebrowsing4;
/// use safebrowsing4::{Result, Error};
/// # #[test] fn egal() {
/// use std::default::Default;
/// use oauth2;
/// use safebrowsing4::Safebrowsing;
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
/// let mut hub = Safebrowsing::new(hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())), auth);
/// // You can configure optional parameters by calling the respective setters at will, and
/// // execute the final call using `doit()`.
/// // Values shown here are possibly random and not representative !
/// let result = hub.encoded_full_hashes().get("encodedRequest")
///              .client_version("sed")
///              .client_id("amet.")
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
pub struct Safebrowsing<C> {
    client: RefCell<C>,
    auth: RefCell<oauth2::authenticator::Authenticator<hyper_rustls::HttpsConnector<hyper::client::connect::HttpConnector>>>,
    _user_agent: String,
    _base_url: String,
    _root_url: String,
}

impl<'a, C> client::Hub for Safebrowsing<C> {}

impl<'a, C> Safebrowsing<C>
    where  C: BorrowMut<hyper::Client<hyper_rustls::HttpsConnector<hyper::client::connect::HttpConnector>, hyper::body::Body>> {

    pub fn new(client: C, authenticator: oauth2::authenticator::Authenticator<hyper_rustls::HttpsConnector<hyper::client::connect::HttpConnector>>) -> Safebrowsing<C> {
        Safebrowsing {
            client: RefCell::new(client),
            auth: RefCell::new(authenticator),
            _user_agent: "google-api-rust-client/1.0.14".to_string(),
            _base_url: "https://safebrowsing.googleapis.com/".to_string(),
            _root_url: "https://safebrowsing.googleapis.com/".to_string(),
        }
    }

    pub fn encoded_full_hashes(&'a self) -> EncodedFullHasheMethods<'a, C> {
        EncodedFullHasheMethods { hub: &self }
    }
    pub fn encoded_updates(&'a self) -> EncodedUpdateMethods<'a, C> {
        EncodedUpdateMethods { hub: &self }
    }
    pub fn full_hashes(&'a self) -> FullHasheMethods<'a, C> {
        FullHasheMethods { hub: &self }
    }
    pub fn threat_hits(&'a self) -> ThreatHitMethods<'a, C> {
        ThreatHitMethods { hub: &self }
    }
    pub fn threat_list_updates(&'a self) -> ThreatListUpdateMethods<'a, C> {
        ThreatListUpdateMethods { hub: &self }
    }
    pub fn threat_lists(&'a self) -> ThreatListMethods<'a, C> {
        ThreatListMethods { hub: &self }
    }
    pub fn threat_matches(&'a self) -> ThreatMatcheMethods<'a, C> {
        ThreatMatcheMethods { hub: &self }
    }

    /// Set the user-agent header field to use in all requests to the server.
    /// It defaults to `google-api-rust-client/1.0.14`.
    ///
    /// Returns the previously set user-agent.
    pub fn user_agent(&mut self, agent_name: String) -> String {
        mem::replace(&mut self._user_agent, agent_name)
    }

    /// Set the base url to use in all requests to the server.
    /// It defaults to `https://safebrowsing.googleapis.com/`.
    ///
    /// Returns the previously set base url.
    pub fn base_url(&mut self, new_base_url: String) -> String {
        mem::replace(&mut self._base_url, new_base_url)
    }

    /// Set the root url to use in all requests to the server.
    /// It defaults to `https://safebrowsing.googleapis.com/`.
    ///
    /// Returns the previously set root url.
    pub fn root_url(&mut self, new_root_url: String) -> String {
        mem::replace(&mut self._root_url, new_root_url)
    }
}


// ############
// SCHEMAS ###
// ##########
/// The expected state of a client's local database.
/// 
/// This type is not used in any activity, and only used as *part* of another schema.
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct Checksum {
    /// The SHA256 hash of the client state; that is, of the sorted list of all
    /// hashes present in the database.
    pub sha256: Option<String>,
}

impl client::Part for Checksum {}


/// The client metadata associated with Safe Browsing API requests.
/// 
/// This type is not used in any activity, and only used as *part* of another schema.
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct ClientInfo {
    /// A client ID that (hopefully) uniquely identifies the client implementation
    /// of the Safe Browsing API.
    #[serde(rename="clientId")]
    pub client_id: Option<String>,
    /// The version of the client implementation.
    #[serde(rename="clientVersion")]
    pub client_version: Option<String>,
}

impl client::Part for ClientInfo {}


/// The constraints for this update.
/// 
/// This type is not used in any activity, and only used as *part* of another schema.
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct Constraints {
    /// A client's physical location, expressed as a ISO 31166-1 alpha-2
    /// region code.
    #[serde(rename="deviceLocation")]
    pub device_location: Option<String>,
    /// Requests the lists for a specific language. Expects ISO 639 alpha-2
    /// format.
    pub language: Option<String>,
    /// Sets the maximum number of entries that the client is willing to have
    /// in the local database for the specified list. This should be a power of
    /// 2 between 2**10 and 2**20. If zero, no database size limit is set.
    #[serde(rename="maxDatabaseEntries")]
    pub max_database_entries: Option<i32>,
    /// The maximum size in number of entries. The update will not contain more
    /// entries than this value.  This should be a power of 2 between 2**10 and
    /// 2**20.  If zero, no update size limit is set.
    #[serde(rename="maxUpdateEntries")]
    pub max_update_entries: Option<i32>,
    /// Requests the list for a specific geographic location. If not set the
    /// server may pick that value based on the user's IP address. Expects ISO
    /// 3166-1 alpha-2 format.
    pub region: Option<String>,
    /// The compression types supported by the client.
    #[serde(rename="supportedCompressions")]
    pub supported_compressions: Option<Vec<String>>,
}

impl client::Part for Constraints {}


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
/// * [create threat hits](ThreatHitCreateCall) (response)
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct Empty { _never_set: Option<bool> }

impl client::ResponseResult for Empty {}


/// Describes a Safe Browsing API update request. Clients can request updates for
/// multiple lists in a single request.
/// NOTE: Field index 2 is unused.
/// NEXT: 5
/// 
/// # Activities
/// 
/// This type is used in activities, which are methods you may call on this type or where this type is involved in. 
/// The list links the activity name, along with information about where it is used (one of *request* and *response*).
/// 
/// * [fetch threat list updates](ThreatListUpdateFetchCall) (request)
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct FetchThreatListUpdatesRequest {
    /// The client metadata.
    pub client: Option<ClientInfo>,
    /// The requested threat list updates.
    #[serde(rename="listUpdateRequests")]
    pub list_update_requests: Option<Vec<ListUpdateRequest>>,
}

impl client::RequestValue for FetchThreatListUpdatesRequest {}


/// There is no detailed description.
/// 
/// # Activities
/// 
/// This type is used in activities, which are methods you may call on this type or where this type is involved in. 
/// The list links the activity name, along with information about where it is used (one of *request* and *response*).
/// 
/// * [get encoded updates](EncodedUpdateGetCall) (response)
/// * [fetch threat list updates](ThreatListUpdateFetchCall) (response)
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct FetchThreatListUpdatesResponse {
    /// The list updates requested by the clients.
    #[serde(rename="listUpdateResponses")]
    pub list_update_responses: Option<Vec<ListUpdateResponse>>,
    /// The minimum duration the client must wait before issuing any update
    /// request. If this field is not set clients may update as soon as they want.
    #[serde(rename="minimumWaitDuration")]
    pub minimum_wait_duration: Option<String>,
}

impl client::ResponseResult for FetchThreatListUpdatesResponse {}


/// Request to return full hashes matched by the provided hash prefixes.
/// 
/// # Activities
/// 
/// This type is used in activities, which are methods you may call on this type or where this type is involved in. 
/// The list links the activity name, along with information about where it is used (one of *request* and *response*).
/// 
/// * [find full hashes](FullHasheFindCall) (request)
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct FindFullHashesRequest {
    /// Client metadata associated with callers of higher-level APIs built on top
    /// of the client's implementation.
    #[serde(rename="apiClient")]
    pub api_client: Option<ClientInfo>,
    /// The client metadata.
    pub client: Option<ClientInfo>,
    /// The current client states for each of the client's local threat lists.
    #[serde(rename="clientStates")]
    pub client_states: Option<Vec<String>>,
    /// The lists and hashes to be checked.
    #[serde(rename="threatInfo")]
    pub threat_info: Option<ThreatInfo>,
}

impl client::RequestValue for FindFullHashesRequest {}


/// There is no detailed description.
/// 
/// # Activities
/// 
/// This type is used in activities, which are methods you may call on this type or where this type is involved in. 
/// The list links the activity name, along with information about where it is used (one of *request* and *response*).
/// 
/// * [get encoded full hashes](EncodedFullHasheGetCall) (response)
/// * [find full hashes](FullHasheFindCall) (response)
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct FindFullHashesResponse {
    /// The full hashes that matched the requested prefixes.
    pub matches: Option<Vec<ThreatMatch>>,
    /// The minimum duration the client must wait before issuing any find hashes
    /// request. If this field is not set, clients can issue a request as soon as
    /// they want.
    #[serde(rename="minimumWaitDuration")]
    pub minimum_wait_duration: Option<String>,
    /// For requested entities that did not match the threat list, how long to
    /// cache the response.
    #[serde(rename="negativeCacheDuration")]
    pub negative_cache_duration: Option<String>,
}

impl client::ResponseResult for FindFullHashesResponse {}


/// Request to check entries against lists.
/// 
/// # Activities
/// 
/// This type is used in activities, which are methods you may call on this type or where this type is involved in. 
/// The list links the activity name, along with information about where it is used (one of *request* and *response*).
/// 
/// * [find threat matches](ThreatMatcheFindCall) (request)
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct FindThreatMatchesRequest {
    /// The client metadata.
    pub client: Option<ClientInfo>,
    /// The lists and entries to be checked for matches.
    #[serde(rename="threatInfo")]
    pub threat_info: Option<ThreatInfo>,
}

impl client::RequestValue for FindThreatMatchesRequest {}


/// There is no detailed description.
/// 
/// # Activities
/// 
/// This type is used in activities, which are methods you may call on this type or where this type is involved in. 
/// The list links the activity name, along with information about where it is used (one of *request* and *response*).
/// 
/// * [find threat matches](ThreatMatcheFindCall) (response)
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct FindThreatMatchesResponse {
    /// The threat list matches.
    pub matches: Option<Vec<ThreatMatch>>,
}

impl client::ResponseResult for FindThreatMatchesResponse {}


/// There is no detailed description.
/// 
/// # Activities
/// 
/// This type is used in activities, which are methods you may call on this type or where this type is involved in. 
/// The list links the activity name, along with information about where it is used (one of *request* and *response*).
/// 
/// * [list threat lists](ThreatListListCall) (response)
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct ListThreatListsResponse {
    /// The lists available for download by the client.
    #[serde(rename="threatLists")]
    pub threat_lists: Option<Vec<ThreatListDescriptor>>,
}

impl client::ResponseResult for ListThreatListsResponse {}


/// A single list update request.
/// 
/// This type is not used in any activity, and only used as *part* of another schema.
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct ListUpdateRequest {
    /// The constraints associated with this request.
    pub constraints: Option<Constraints>,
    /// The type of platform at risk by entries present in the list.
    #[serde(rename="platformType")]
    pub platform_type: Option<String>,
    /// The current state of the client for the requested list (the encrypted
    /// client state that was received from the last successful list update).
    pub state: Option<String>,
    /// The types of entries present in the list.
    #[serde(rename="threatEntryType")]
    pub threat_entry_type: Option<String>,
    /// The type of threat posed by entries present in the list.
    #[serde(rename="threatType")]
    pub threat_type: Option<String>,
}

impl client::Part for ListUpdateRequest {}


/// An update to an individual list.
/// 
/// This type is not used in any activity, and only used as *part* of another schema.
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct ListUpdateResponse {
    /// A set of entries to add to a local threat type's list. Repeated to allow
    /// for a combination of compressed and raw data to be sent in a single
    /// response.
    pub additions: Option<Vec<ThreatEntrySet>>,
    /// The expected SHA256 hash of the client state; that is, of the sorted list
    /// of all hashes present in the database after applying the provided update.
    /// If the client state doesn't match the expected state, the client must
    /// disregard this update and retry later.
    pub checksum: Option<Checksum>,
    /// The new client state, in encrypted format. Opaque to clients.
    #[serde(rename="newClientState")]
    pub new_client_state: Option<String>,
    /// The platform type for which data is returned.
    #[serde(rename="platformType")]
    pub platform_type: Option<String>,
    /// A set of entries to remove from a local threat type's list. In practice,
    /// this field is empty or contains exactly one ThreatEntrySet.
    pub removals: Option<Vec<ThreatEntrySet>>,
    /// The type of response. This may indicate that an action is required by the
    /// client when the response is received.
    #[serde(rename="responseType")]
    pub response_type: Option<String>,
    /// The format of the threats.
    #[serde(rename="threatEntryType")]
    pub threat_entry_type: Option<String>,
    /// The threat type for which data is returned.
    #[serde(rename="threatType")]
    pub threat_type: Option<String>,
}

impl client::Part for ListUpdateResponse {}


/// A single metadata entry.
/// 
/// This type is not used in any activity, and only used as *part* of another schema.
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct MetadataEntry {
    /// The metadata entry key. For JSON requests, the key is base64-encoded.
    pub key: Option<String>,
    /// The metadata entry value. For JSON requests, the value is base64-encoded.
    pub value: Option<String>,
}

impl client::Part for MetadataEntry {}


/// The uncompressed threat entries in hash format of a particular prefix length.
/// Hashes can be anywhere from 4 to 32 bytes in size. A large majority are 4
/// bytes, but some hashes are lengthened if they collide with the hash of a
/// popular URL.
/// 
/// Used for sending ThreatEntrySet to clients that do not support compression,
/// or when sending non-4-byte hashes to clients that do support compression.
/// 
/// This type is not used in any activity, and only used as *part* of another schema.
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct RawHashes {
    /// The number of bytes for each prefix encoded below.  This field can be
    /// anywhere from 4 (shortest prefix) to 32 (full SHA256 hash).
    #[serde(rename="prefixSize")]
    pub prefix_size: Option<i32>,
    /// The hashes, in binary format, concatenated into one long string. Hashes are
    /// sorted in lexicographic order. For JSON API users, hashes are
    /// base64-encoded.
    #[serde(rename="rawHashes")]
    pub raw_hashes: Option<String>,
}

impl client::Part for RawHashes {}


/// A set of raw indices to remove from a local list.
/// 
/// This type is not used in any activity, and only used as *part* of another schema.
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct RawIndices {
    /// The indices to remove from a lexicographically-sorted local list.
    pub indices: Option<Vec<i32>>,
}

impl client::Part for RawIndices {}


/// The Rice-Golomb encoded data. Used for sending compressed 4-byte hashes or
/// compressed removal indices.
/// 
/// This type is not used in any activity, and only used as *part* of another schema.
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct RiceDeltaEncoding {
    /// The encoded deltas that are encoded using the Golomb-Rice coder.
    #[serde(rename="encodedData")]
    pub encoded_data: Option<String>,
    /// The offset of the first entry in the encoded data, or, if only a single
    /// integer was encoded, that single integer's value. If the field is empty or
    /// missing, assume zero.
    #[serde(rename="firstValue")]
    pub first_value: Option<String>,
    /// The number of entries that are delta encoded in the encoded data. If only a
    /// single integer was encoded, this will be zero and the single value will be
    /// stored in `first_value`.
    #[serde(rename="numEntries")]
    pub num_entries: Option<i32>,
    /// The Golomb-Rice parameter, which is a number between 2 and 28. This field
    /// is missing (that is, zero) if `num_entries` is zero.
    #[serde(rename="riceParameter")]
    pub rice_parameter: Option<i32>,
}

impl client::Part for RiceDeltaEncoding {}


/// An individual threat; for example, a malicious URL or its hash
/// representation. Only one of these fields should be set.
/// 
/// This type is not used in any activity, and only used as *part* of another schema.
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct ThreatEntry {
    /// The digest of an executable in SHA256 format. The API supports both
    /// binary and hex digests. For JSON requests, digests are base64-encoded.
    pub digest: Option<String>,
    /// A hash prefix, consisting of the most significant 4-32 bytes of a SHA256
    /// hash. This field is in binary format. For JSON requests, hashes are
    /// base64-encoded.
    pub hash: Option<String>,
    /// A URL.
    pub url: Option<String>,
}

impl client::Part for ThreatEntry {}


/// The metadata associated with a specific threat entry. The client is expected
/// to know the metadata key/value pairs associated with each threat type.
/// 
/// This type is not used in any activity, and only used as *part* of another schema.
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct ThreatEntryMetadata {
    /// The metadata entries.
    pub entries: Option<Vec<MetadataEntry>>,
}

impl client::Part for ThreatEntryMetadata {}


/// A set of threats that should be added or removed from a client's local
/// database.
/// 
/// This type is not used in any activity, and only used as *part* of another schema.
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct ThreatEntrySet {
    /// The compression type for the entries in this set.
    #[serde(rename="compressionType")]
    pub compression_type: Option<String>,
    /// The raw SHA256-formatted entries.
    #[serde(rename="rawHashes")]
    pub raw_hashes: Option<RawHashes>,
    /// The raw removal indices for a local list.
    #[serde(rename="rawIndices")]
    pub raw_indices: Option<RawIndices>,
    /// The encoded 4-byte prefixes of SHA256-formatted entries, using a
    /// Golomb-Rice encoding. The hashes are converted to uint32, sorted in
    /// ascending order, then delta encoded and stored as encoded_data.
    #[serde(rename="riceHashes")]
    pub rice_hashes: Option<RiceDeltaEncoding>,
    /// The encoded local, lexicographically-sorted list indices, using a
    /// Golomb-Rice encoding. Used for sending compressed removal indices. The
    /// removal indices (uint32) are sorted in ascending order, then delta encoded
    /// and stored as encoded_data.
    #[serde(rename="riceIndices")]
    pub rice_indices: Option<RiceDeltaEncoding>,
}

impl client::Part for ThreatEntrySet {}


/// There is no detailed description.
/// 
/// # Activities
/// 
/// This type is used in activities, which are methods you may call on this type or where this type is involved in. 
/// The list links the activity name, along with information about where it is used (one of *request* and *response*).
/// 
/// * [create threat hits](ThreatHitCreateCall) (request)
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct ThreatHit {
    /// Client-reported identification.
    #[serde(rename="clientInfo")]
    pub client_info: Option<ClientInfo>,
    /// The threat entry responsible for the hit. Full hash should be reported for
    /// hash-based hits.
    pub entry: Option<ThreatEntry>,
    /// The platform type reported.
    #[serde(rename="platformType")]
    pub platform_type: Option<String>,
    /// The resources related to the threat hit.
    pub resources: Option<Vec<ThreatSource>>,
    /// The threat type reported.
    #[serde(rename="threatType")]
    pub threat_type: Option<String>,
    /// Details about the user that encountered the threat.
    #[serde(rename="userInfo")]
    pub user_info: Option<UserInfo>,
}

impl client::RequestValue for ThreatHit {}
impl client::Resource for ThreatHit {}


/// The information regarding one or more threats that a client submits when
/// checking for matches in threat lists.
/// 
/// This type is not used in any activity, and only used as *part* of another schema.
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct ThreatInfo {
    /// The platform types to be checked.
    #[serde(rename="platformTypes")]
    pub platform_types: Option<Vec<String>>,
    /// The threat entries to be checked.
    #[serde(rename="threatEntries")]
    pub threat_entries: Option<Vec<ThreatEntry>>,
    /// The entry types to be checked.
    #[serde(rename="threatEntryTypes")]
    pub threat_entry_types: Option<Vec<String>>,
    /// The threat types to be checked.
    #[serde(rename="threatTypes")]
    pub threat_types: Option<Vec<String>>,
}

impl client::Part for ThreatInfo {}


/// Describes an individual threat list. A list is defined by three parameters:
/// the type of threat posed, the type of platform targeted by the threat, and
/// the type of entries in the list.
/// 
/// This type is not used in any activity, and only used as *part* of another schema.
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct ThreatListDescriptor {
    /// The platform type targeted by the list's entries.
    #[serde(rename="platformType")]
    pub platform_type: Option<String>,
    /// The entry types contained in the list.
    #[serde(rename="threatEntryType")]
    pub threat_entry_type: Option<String>,
    /// The threat type posed by the list's entries.
    #[serde(rename="threatType")]
    pub threat_type: Option<String>,
}

impl client::Part for ThreatListDescriptor {}


/// A match when checking a threat entry in the Safe Browsing threat lists.
/// 
/// This type is not used in any activity, and only used as *part* of another schema.
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct ThreatMatch {
    /// The cache lifetime for the returned match. Clients must not cache this
    /// response for more than this duration to avoid false positives.
    #[serde(rename="cacheDuration")]
    pub cache_duration: Option<String>,
    /// The platform type matching this threat.
    #[serde(rename="platformType")]
    pub platform_type: Option<String>,
    /// The threat matching this threat.
    pub threat: Option<ThreatEntry>,
    /// Optional metadata associated with this threat.
    #[serde(rename="threatEntryMetadata")]
    pub threat_entry_metadata: Option<ThreatEntryMetadata>,
    /// The threat entry type matching this threat.
    #[serde(rename="threatEntryType")]
    pub threat_entry_type: Option<String>,
    /// The threat type matching this threat.
    #[serde(rename="threatType")]
    pub threat_type: Option<String>,
}

impl client::Part for ThreatMatch {}


/// A single resource related to a threat hit.
/// 
/// This type is not used in any activity, and only used as *part* of another schema.
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct ThreatSource {
    /// Referrer of the resource. Only set if the referrer is available.
    pub referrer: Option<String>,
    /// The remote IP of the resource in ASCII format. Either IPv4 or IPv6.
    #[serde(rename="remoteIp")]
    pub remote_ip: Option<String>,
    /// The type of source reported.
    #[serde(rename="type")]
    pub type_: Option<String>,
    /// The URL of the resource.
    pub url: Option<String>,
}

impl client::Part for ThreatSource {}


/// Details about the user that encountered the threat.
/// 
/// This type is not used in any activity, and only used as *part* of another schema.
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct UserInfo {
    /// The UN M.49 region code associated with the user's location.
    #[serde(rename="regionCode")]
    pub region_code: Option<String>,
    /// Unique user identifier defined by the client.
    #[serde(rename="userId")]
    pub user_id: Option<String>,
}

impl client::Part for UserInfo {}



// ###################
// MethodBuilders ###
// #################

/// A builder providing access to all methods supported on *encodedFullHashe* resources.
/// It is not used directly, but through the `Safebrowsing` hub.
///
/// # Example
///
/// Instantiate a resource builder
///
/// ```test_harness,no_run
/// extern crate hyper;
/// extern crate hyper_rustls;
/// extern crate yup_oauth2 as oauth2;
/// extern crate google_safebrowsing4 as safebrowsing4;
/// 
/// # #[test] fn egal() {
/// use std::default::Default;
/// use oauth2;
/// use safebrowsing4::Safebrowsing;
/// 
/// let secret: ApplicationSecret = Default::default();
/// let auth = yup_oauth2::InstalledFlowAuthenticator::builder(
///         secret,
///         yup_oauth2::InstalledFlowReturnMethod::HTTPRedirect,
///     ).build().await.unwrap();
/// let mut hub = Safebrowsing::new(hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())), auth);
/// // Usually you wouldn't bind this to a variable, but keep calling *CallBuilders*
/// // like `get(...)`
/// // to build up your call.
/// let rb = hub.encoded_full_hashes();
/// # }
/// ```
pub struct EncodedFullHasheMethods<'a, C>
    where C: 'a {

    hub: &'a Safebrowsing<C>,
}

impl<'a, C> client::MethodsBuilder for EncodedFullHasheMethods<'a, C> {}

impl<'a, C> EncodedFullHasheMethods<'a, C> {
    
    /// Create a builder to help you perform the following task:
    ///
    /// 
    /// 
    /// # Arguments
    ///
    /// * `encodedRequest` - A serialized FindFullHashesRequest proto.
    pub fn get(&self, encoded_request: &str) -> EncodedFullHasheGetCall<'a, C> {
        EncodedFullHasheGetCall {
            hub: self.hub,
            _encoded_request: encoded_request.to_string(),
            _client_version: Default::default(),
            _client_id: Default::default(),
            _delegate: Default::default(),
            _additional_params: Default::default(),
        }
    }
}



/// A builder providing access to all methods supported on *encodedUpdate* resources.
/// It is not used directly, but through the `Safebrowsing` hub.
///
/// # Example
///
/// Instantiate a resource builder
///
/// ```test_harness,no_run
/// extern crate hyper;
/// extern crate hyper_rustls;
/// extern crate yup_oauth2 as oauth2;
/// extern crate google_safebrowsing4 as safebrowsing4;
/// 
/// # #[test] fn egal() {
/// use std::default::Default;
/// use oauth2;
/// use safebrowsing4::Safebrowsing;
/// 
/// let secret: ApplicationSecret = Default::default();
/// let auth = yup_oauth2::InstalledFlowAuthenticator::builder(
///         secret,
///         yup_oauth2::InstalledFlowReturnMethod::HTTPRedirect,
///     ).build().await.unwrap();
/// let mut hub = Safebrowsing::new(hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())), auth);
/// // Usually you wouldn't bind this to a variable, but keep calling *CallBuilders*
/// // like `get(...)`
/// // to build up your call.
/// let rb = hub.encoded_updates();
/// # }
/// ```
pub struct EncodedUpdateMethods<'a, C>
    where C: 'a {

    hub: &'a Safebrowsing<C>,
}

impl<'a, C> client::MethodsBuilder for EncodedUpdateMethods<'a, C> {}

impl<'a, C> EncodedUpdateMethods<'a, C> {
    
    /// Create a builder to help you perform the following task:
    ///
    /// 
    /// 
    /// # Arguments
    ///
    /// * `encodedRequest` - A serialized FetchThreatListUpdatesRequest proto.
    pub fn get(&self, encoded_request: &str) -> EncodedUpdateGetCall<'a, C> {
        EncodedUpdateGetCall {
            hub: self.hub,
            _encoded_request: encoded_request.to_string(),
            _client_version: Default::default(),
            _client_id: Default::default(),
            _delegate: Default::default(),
            _additional_params: Default::default(),
        }
    }
}



/// A builder providing access to all methods supported on *fullHashe* resources.
/// It is not used directly, but through the `Safebrowsing` hub.
///
/// # Example
///
/// Instantiate a resource builder
///
/// ```test_harness,no_run
/// extern crate hyper;
/// extern crate hyper_rustls;
/// extern crate yup_oauth2 as oauth2;
/// extern crate google_safebrowsing4 as safebrowsing4;
/// 
/// # #[test] fn egal() {
/// use std::default::Default;
/// use oauth2;
/// use safebrowsing4::Safebrowsing;
/// 
/// let secret: ApplicationSecret = Default::default();
/// let auth = yup_oauth2::InstalledFlowAuthenticator::builder(
///         secret,
///         yup_oauth2::InstalledFlowReturnMethod::HTTPRedirect,
///     ).build().await.unwrap();
/// let mut hub = Safebrowsing::new(hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())), auth);
/// // Usually you wouldn't bind this to a variable, but keep calling *CallBuilders*
/// // like `find(...)`
/// // to build up your call.
/// let rb = hub.full_hashes();
/// # }
/// ```
pub struct FullHasheMethods<'a, C>
    where C: 'a {

    hub: &'a Safebrowsing<C>,
}

impl<'a, C> client::MethodsBuilder for FullHasheMethods<'a, C> {}

impl<'a, C> FullHasheMethods<'a, C> {
    
    /// Create a builder to help you perform the following task:
    ///
    /// Finds the full hashes that match the requested hash prefixes.
    /// 
    /// # Arguments
    ///
    /// * `request` - No description provided.
    pub fn find(&self, request: FindFullHashesRequest) -> FullHasheFindCall<'a, C> {
        FullHasheFindCall {
            hub: self.hub,
            _request: request,
            _delegate: Default::default(),
            _additional_params: Default::default(),
        }
    }
}



/// A builder providing access to all methods supported on *threatHit* resources.
/// It is not used directly, but through the `Safebrowsing` hub.
///
/// # Example
///
/// Instantiate a resource builder
///
/// ```test_harness,no_run
/// extern crate hyper;
/// extern crate hyper_rustls;
/// extern crate yup_oauth2 as oauth2;
/// extern crate google_safebrowsing4 as safebrowsing4;
/// 
/// # #[test] fn egal() {
/// use std::default::Default;
/// use oauth2;
/// use safebrowsing4::Safebrowsing;
/// 
/// let secret: ApplicationSecret = Default::default();
/// let auth = yup_oauth2::InstalledFlowAuthenticator::builder(
///         secret,
///         yup_oauth2::InstalledFlowReturnMethod::HTTPRedirect,
///     ).build().await.unwrap();
/// let mut hub = Safebrowsing::new(hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())), auth);
/// // Usually you wouldn't bind this to a variable, but keep calling *CallBuilders*
/// // like `create(...)`
/// // to build up your call.
/// let rb = hub.threat_hits();
/// # }
/// ```
pub struct ThreatHitMethods<'a, C>
    where C: 'a {

    hub: &'a Safebrowsing<C>,
}

impl<'a, C> client::MethodsBuilder for ThreatHitMethods<'a, C> {}

impl<'a, C> ThreatHitMethods<'a, C> {
    
    /// Create a builder to help you perform the following task:
    ///
    /// Reports a Safe Browsing threat list hit to Google. Only projects with
    /// TRUSTED_REPORTER visibility can use this method.
    /// 
    /// # Arguments
    ///
    /// * `request` - No description provided.
    pub fn create(&self, request: ThreatHit) -> ThreatHitCreateCall<'a, C> {
        ThreatHitCreateCall {
            hub: self.hub,
            _request: request,
            _delegate: Default::default(),
            _additional_params: Default::default(),
        }
    }
}



/// A builder providing access to all methods supported on *threatListUpdate* resources.
/// It is not used directly, but through the `Safebrowsing` hub.
///
/// # Example
///
/// Instantiate a resource builder
///
/// ```test_harness,no_run
/// extern crate hyper;
/// extern crate hyper_rustls;
/// extern crate yup_oauth2 as oauth2;
/// extern crate google_safebrowsing4 as safebrowsing4;
/// 
/// # #[test] fn egal() {
/// use std::default::Default;
/// use oauth2;
/// use safebrowsing4::Safebrowsing;
/// 
/// let secret: ApplicationSecret = Default::default();
/// let auth = yup_oauth2::InstalledFlowAuthenticator::builder(
///         secret,
///         yup_oauth2::InstalledFlowReturnMethod::HTTPRedirect,
///     ).build().await.unwrap();
/// let mut hub = Safebrowsing::new(hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())), auth);
/// // Usually you wouldn't bind this to a variable, but keep calling *CallBuilders*
/// // like `fetch(...)`
/// // to build up your call.
/// let rb = hub.threat_list_updates();
/// # }
/// ```
pub struct ThreatListUpdateMethods<'a, C>
    where C: 'a {

    hub: &'a Safebrowsing<C>,
}

impl<'a, C> client::MethodsBuilder for ThreatListUpdateMethods<'a, C> {}

impl<'a, C> ThreatListUpdateMethods<'a, C> {
    
    /// Create a builder to help you perform the following task:
    ///
    /// Fetches the most recent threat list updates. A client can request updates
    /// for multiple lists at once.
    /// 
    /// # Arguments
    ///
    /// * `request` - No description provided.
    pub fn fetch(&self, request: FetchThreatListUpdatesRequest) -> ThreatListUpdateFetchCall<'a, C> {
        ThreatListUpdateFetchCall {
            hub: self.hub,
            _request: request,
            _delegate: Default::default(),
            _additional_params: Default::default(),
        }
    }
}



/// A builder providing access to all methods supported on *threatList* resources.
/// It is not used directly, but through the `Safebrowsing` hub.
///
/// # Example
///
/// Instantiate a resource builder
///
/// ```test_harness,no_run
/// extern crate hyper;
/// extern crate hyper_rustls;
/// extern crate yup_oauth2 as oauth2;
/// extern crate google_safebrowsing4 as safebrowsing4;
/// 
/// # #[test] fn egal() {
/// use std::default::Default;
/// use oauth2;
/// use safebrowsing4::Safebrowsing;
/// 
/// let secret: ApplicationSecret = Default::default();
/// let auth = yup_oauth2::InstalledFlowAuthenticator::builder(
///         secret,
///         yup_oauth2::InstalledFlowReturnMethod::HTTPRedirect,
///     ).build().await.unwrap();
/// let mut hub = Safebrowsing::new(hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())), auth);
/// // Usually you wouldn't bind this to a variable, but keep calling *CallBuilders*
/// // like `list(...)`
/// // to build up your call.
/// let rb = hub.threat_lists();
/// # }
/// ```
pub struct ThreatListMethods<'a, C>
    where C: 'a {

    hub: &'a Safebrowsing<C>,
}

impl<'a, C> client::MethodsBuilder for ThreatListMethods<'a, C> {}

impl<'a, C> ThreatListMethods<'a, C> {
    
    /// Create a builder to help you perform the following task:
    ///
    /// Lists the Safe Browsing threat lists available for download.
    pub fn list(&self) -> ThreatListListCall<'a, C> {
        ThreatListListCall {
            hub: self.hub,
            _delegate: Default::default(),
            _additional_params: Default::default(),
        }
    }
}



/// A builder providing access to all methods supported on *threatMatche* resources.
/// It is not used directly, but through the `Safebrowsing` hub.
///
/// # Example
///
/// Instantiate a resource builder
///
/// ```test_harness,no_run
/// extern crate hyper;
/// extern crate hyper_rustls;
/// extern crate yup_oauth2 as oauth2;
/// extern crate google_safebrowsing4 as safebrowsing4;
/// 
/// # #[test] fn egal() {
/// use std::default::Default;
/// use oauth2;
/// use safebrowsing4::Safebrowsing;
/// 
/// let secret: ApplicationSecret = Default::default();
/// let auth = yup_oauth2::InstalledFlowAuthenticator::builder(
///         secret,
///         yup_oauth2::InstalledFlowReturnMethod::HTTPRedirect,
///     ).build().await.unwrap();
/// let mut hub = Safebrowsing::new(hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())), auth);
/// // Usually you wouldn't bind this to a variable, but keep calling *CallBuilders*
/// // like `find(...)`
/// // to build up your call.
/// let rb = hub.threat_matches();
/// # }
/// ```
pub struct ThreatMatcheMethods<'a, C>
    where C: 'a {

    hub: &'a Safebrowsing<C>,
}

impl<'a, C> client::MethodsBuilder for ThreatMatcheMethods<'a, C> {}

impl<'a, C> ThreatMatcheMethods<'a, C> {
    
    /// Create a builder to help you perform the following task:
    ///
    /// Finds the threat entries that match the Safe Browsing lists.
    /// 
    /// # Arguments
    ///
    /// * `request` - No description provided.
    pub fn find(&self, request: FindThreatMatchesRequest) -> ThreatMatcheFindCall<'a, C> {
        ThreatMatcheFindCall {
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

/// 
///
/// A builder for the *get* method supported by a *encodedFullHashe* resource.
/// It is not used directly, but through a `EncodedFullHasheMethods` instance.
///
/// # Example
///
/// Instantiate a resource method builder
///
/// ```test_harness,no_run
/// # extern crate hyper;
/// # extern crate hyper_rustls;
/// # extern crate yup_oauth2 as oauth2;
/// # extern crate google_safebrowsing4 as safebrowsing4;
/// # #[test] fn egal() {
/// # use std::default::Default;
/// # use oauth2;
/// # use safebrowsing4::Safebrowsing;
/// 
/// # let secret: ApplicationSecret = Default::default();
/// # let auth = yup_oauth2::InstalledFlowAuthenticator::builder(
/// #         secret,
/// #         yup_oauth2::InstalledFlowReturnMethod::HTTPRedirect,
/// #     ).build().await.unwrap();
/// # let mut hub = Safebrowsing::new(hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())), auth);
/// // You can configure optional parameters by calling the respective setters at will, and
/// // execute the final call using `doit()`.
/// // Values shown here are possibly random and not representative !
/// let result = hub.encoded_full_hashes().get("encodedRequest")
///              .client_version("amet.")
///              .client_id("duo")
///              .doit();
/// # }
/// ```
pub struct EncodedFullHasheGetCall<'a, C>
    where C: 'a {

    hub: &'a Safebrowsing<C>,
    _encoded_request: String,
    _client_version: Option<String>,
    _client_id: Option<String>,
    _delegate: Option<&'a mut dyn client::Delegate>,
    _additional_params: HashMap<String, String>,
}

impl<'a, C> client::CallBuilder for EncodedFullHasheGetCall<'a, C> {}

impl<'a, C> EncodedFullHasheGetCall<'a, C> where C: BorrowMut<hyper::Client<hyper_rustls::HttpsConnector<hyper::client::connect::HttpConnector>, hyper::body::Body>> {


    /// Perform the operation you have build so far.
    pub async fn doit(mut self) -> client::Result<(hyper::Response<hyper::body::Body>, FindFullHashesResponse)> {
        use std::io::{Read, Seek};
        use hyper::header::{CONTENT_TYPE, CONTENT_LENGTH, AUTHORIZATION, USER_AGENT, LOCATION};
        use client::ToParts;
        let mut dd = client::DefaultDelegate;
        let mut dlg: &mut dyn client::Delegate = match self._delegate {
            Some(d) => d,
            None => &mut dd
        };
        dlg.begin(client::MethodInfo { id: "safebrowsing.encodedFullHashes.get",
                               http_method: hyper::Method::GET });
        let mut params: Vec<(&str, String)> = Vec::with_capacity(5 + self._additional_params.len());
        params.push(("encodedRequest", self._encoded_request.to_string()));
        if let Some(value) = self._client_version {
            params.push(("clientVersion", value.to_string()));
        }
        if let Some(value) = self._client_id {
            params.push(("clientId", value.to_string()));
        }
        for &field in ["alt", "encodedRequest", "clientVersion", "clientId"].iter() {
            if self._additional_params.contains_key(field) {
                dlg.finished(false);
                return Err(client::Error::FieldClash(field));
            }
        }
        for (name, value) in self._additional_params.iter() {
            params.push((&name, value.clone()));
        }

        params.push(("alt", "json".to_string()));

        let mut url = self.hub._base_url.clone() + "v4/encodedFullHashes/{encodedRequest}";
        
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

        for &(find_this, param_name) in [("{encodedRequest}", "encodedRequest")].iter() {
            let mut replace_with: Option<&str> = None;
            for &(name, ref value) in params.iter() {
                if name == param_name {
                    replace_with = Some(value);
                    break;
                }
            }
            url = url.replace(find_this, replace_with.expect("to find substitution value in params"));
        }
        {
            let mut indices_for_removal: Vec<usize> = Vec::with_capacity(1);
            for param_name in ["encodedRequest"].iter() {
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
                let mut req_builder = hyper::Request::builder().method(hyper::Method::GET).uri(url.clone().into_string())
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


    /// A serialized FindFullHashesRequest proto.
    ///
    /// Sets the *encoded request* path property to the given value.
    ///
    /// Even though the property as already been set when instantiating this call,
    /// we provide this method for API completeness.
    pub fn encoded_request(mut self, new_value: &str) -> EncodedFullHasheGetCall<'a, C> {
        self._encoded_request = new_value.to_string();
        self
    }
    /// The version of the client implementation.
    ///
    /// Sets the *client version* query property to the given value.
    pub fn client_version(mut self, new_value: &str) -> EncodedFullHasheGetCall<'a, C> {
        self._client_version = Some(new_value.to_string());
        self
    }
    /// A client ID that (hopefully) uniquely identifies the client implementation
    /// of the Safe Browsing API.
    ///
    /// Sets the *client id* query property to the given value.
    pub fn client_id(mut self, new_value: &str) -> EncodedFullHasheGetCall<'a, C> {
        self._client_id = Some(new_value.to_string());
        self
    }
    /// The delegate implementation is consulted whenever there is an intermediate result, or if something goes wrong
    /// while executing the actual API request.
    /// 
    /// It should be used to handle progress information, and to implement a certain level of resilience.
    ///
    /// Sets the *delegate* property to the given value.
    pub fn delegate(mut self, new_value: &'a mut dyn client::Delegate) -> EncodedFullHasheGetCall<'a, C> {
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
    pub fn param<T>(mut self, name: T, value: T) -> EncodedFullHasheGetCall<'a, C>
                                                        where T: AsRef<str> {
        self._additional_params.insert(name.as_ref().to_string(), value.as_ref().to_string());
        self
    }

}


/// 
///
/// A builder for the *get* method supported by a *encodedUpdate* resource.
/// It is not used directly, but through a `EncodedUpdateMethods` instance.
///
/// # Example
///
/// Instantiate a resource method builder
///
/// ```test_harness,no_run
/// # extern crate hyper;
/// # extern crate hyper_rustls;
/// # extern crate yup_oauth2 as oauth2;
/// # extern crate google_safebrowsing4 as safebrowsing4;
/// # #[test] fn egal() {
/// # use std::default::Default;
/// # use oauth2;
/// # use safebrowsing4::Safebrowsing;
/// 
/// # let secret: ApplicationSecret = Default::default();
/// # let auth = yup_oauth2::InstalledFlowAuthenticator::builder(
/// #         secret,
/// #         yup_oauth2::InstalledFlowReturnMethod::HTTPRedirect,
/// #     ).build().await.unwrap();
/// # let mut hub = Safebrowsing::new(hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())), auth);
/// // You can configure optional parameters by calling the respective setters at will, and
/// // execute the final call using `doit()`.
/// // Values shown here are possibly random and not representative !
/// let result = hub.encoded_updates().get("encodedRequest")
///              .client_version("gubergren")
///              .client_id("Lorem")
///              .doit();
/// # }
/// ```
pub struct EncodedUpdateGetCall<'a, C>
    where C: 'a {

    hub: &'a Safebrowsing<C>,
    _encoded_request: String,
    _client_version: Option<String>,
    _client_id: Option<String>,
    _delegate: Option<&'a mut dyn client::Delegate>,
    _additional_params: HashMap<String, String>,
}

impl<'a, C> client::CallBuilder for EncodedUpdateGetCall<'a, C> {}

impl<'a, C> EncodedUpdateGetCall<'a, C> where C: BorrowMut<hyper::Client<hyper_rustls::HttpsConnector<hyper::client::connect::HttpConnector>, hyper::body::Body>> {


    /// Perform the operation you have build so far.
    pub async fn doit(mut self) -> client::Result<(hyper::Response<hyper::body::Body>, FetchThreatListUpdatesResponse)> {
        use std::io::{Read, Seek};
        use hyper::header::{CONTENT_TYPE, CONTENT_LENGTH, AUTHORIZATION, USER_AGENT, LOCATION};
        use client::ToParts;
        let mut dd = client::DefaultDelegate;
        let mut dlg: &mut dyn client::Delegate = match self._delegate {
            Some(d) => d,
            None => &mut dd
        };
        dlg.begin(client::MethodInfo { id: "safebrowsing.encodedUpdates.get",
                               http_method: hyper::Method::GET });
        let mut params: Vec<(&str, String)> = Vec::with_capacity(5 + self._additional_params.len());
        params.push(("encodedRequest", self._encoded_request.to_string()));
        if let Some(value) = self._client_version {
            params.push(("clientVersion", value.to_string()));
        }
        if let Some(value) = self._client_id {
            params.push(("clientId", value.to_string()));
        }
        for &field in ["alt", "encodedRequest", "clientVersion", "clientId"].iter() {
            if self._additional_params.contains_key(field) {
                dlg.finished(false);
                return Err(client::Error::FieldClash(field));
            }
        }
        for (name, value) in self._additional_params.iter() {
            params.push((&name, value.clone()));
        }

        params.push(("alt", "json".to_string()));

        let mut url = self.hub._base_url.clone() + "v4/encodedUpdates/{encodedRequest}";
        
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

        for &(find_this, param_name) in [("{encodedRequest}", "encodedRequest")].iter() {
            let mut replace_with: Option<&str> = None;
            for &(name, ref value) in params.iter() {
                if name == param_name {
                    replace_with = Some(value);
                    break;
                }
            }
            url = url.replace(find_this, replace_with.expect("to find substitution value in params"));
        }
        {
            let mut indices_for_removal: Vec<usize> = Vec::with_capacity(1);
            for param_name in ["encodedRequest"].iter() {
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
                let mut req_builder = hyper::Request::builder().method(hyper::Method::GET).uri(url.clone().into_string())
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


    /// A serialized FetchThreatListUpdatesRequest proto.
    ///
    /// Sets the *encoded request* path property to the given value.
    ///
    /// Even though the property as already been set when instantiating this call,
    /// we provide this method for API completeness.
    pub fn encoded_request(mut self, new_value: &str) -> EncodedUpdateGetCall<'a, C> {
        self._encoded_request = new_value.to_string();
        self
    }
    /// The version of the client implementation.
    ///
    /// Sets the *client version* query property to the given value.
    pub fn client_version(mut self, new_value: &str) -> EncodedUpdateGetCall<'a, C> {
        self._client_version = Some(new_value.to_string());
        self
    }
    /// A client ID that uniquely identifies the client implementation of the Safe
    /// Browsing API.
    ///
    /// Sets the *client id* query property to the given value.
    pub fn client_id(mut self, new_value: &str) -> EncodedUpdateGetCall<'a, C> {
        self._client_id = Some(new_value.to_string());
        self
    }
    /// The delegate implementation is consulted whenever there is an intermediate result, or if something goes wrong
    /// while executing the actual API request.
    /// 
    /// It should be used to handle progress information, and to implement a certain level of resilience.
    ///
    /// Sets the *delegate* property to the given value.
    pub fn delegate(mut self, new_value: &'a mut dyn client::Delegate) -> EncodedUpdateGetCall<'a, C> {
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
    pub fn param<T>(mut self, name: T, value: T) -> EncodedUpdateGetCall<'a, C>
                                                        where T: AsRef<str> {
        self._additional_params.insert(name.as_ref().to_string(), value.as_ref().to_string());
        self
    }

}


/// Finds the full hashes that match the requested hash prefixes.
///
/// A builder for the *find* method supported by a *fullHashe* resource.
/// It is not used directly, but through a `FullHasheMethods` instance.
///
/// # Example
///
/// Instantiate a resource method builder
///
/// ```test_harness,no_run
/// # extern crate hyper;
/// # extern crate hyper_rustls;
/// # extern crate yup_oauth2 as oauth2;
/// # extern crate google_safebrowsing4 as safebrowsing4;
/// use safebrowsing4::api::FindFullHashesRequest;
/// # #[test] fn egal() {
/// # use std::default::Default;
/// # use oauth2;
/// # use safebrowsing4::Safebrowsing;
/// 
/// # let secret: ApplicationSecret = Default::default();
/// # let auth = yup_oauth2::InstalledFlowAuthenticator::builder(
/// #         secret,
/// #         yup_oauth2::InstalledFlowReturnMethod::HTTPRedirect,
/// #     ).build().await.unwrap();
/// # let mut hub = Safebrowsing::new(hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())), auth);
/// // As the method needs a request, you would usually fill it with the desired information
/// // into the respective structure. Some of the parts shown here might not be applicable !
/// // Values shown here are possibly random and not representative !
/// let mut req = FindFullHashesRequest::default();
/// 
/// // You can configure optional parameters by calling the respective setters at will, and
/// // execute the final call using `doit()`.
/// // Values shown here are possibly random and not representative !
/// let result = hub.full_hashes().find(req)
///              .doit();
/// # }
/// ```
pub struct FullHasheFindCall<'a, C>
    where C: 'a {

    hub: &'a Safebrowsing<C>,
    _request: FindFullHashesRequest,
    _delegate: Option<&'a mut dyn client::Delegate>,
    _additional_params: HashMap<String, String>,
}

impl<'a, C> client::CallBuilder for FullHasheFindCall<'a, C> {}

impl<'a, C> FullHasheFindCall<'a, C> where C: BorrowMut<hyper::Client<hyper_rustls::HttpsConnector<hyper::client::connect::HttpConnector>, hyper::body::Body>> {


    /// Perform the operation you have build so far.
    pub async fn doit(mut self) -> client::Result<(hyper::Response<hyper::body::Body>, FindFullHashesResponse)> {
        use std::io::{Read, Seek};
        use hyper::header::{CONTENT_TYPE, CONTENT_LENGTH, AUTHORIZATION, USER_AGENT, LOCATION};
        use client::ToParts;
        let mut dd = client::DefaultDelegate;
        let mut dlg: &mut dyn client::Delegate = match self._delegate {
            Some(d) => d,
            None => &mut dd
        };
        dlg.begin(client::MethodInfo { id: "safebrowsing.fullHashes.find",
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

        let mut url = self.hub._base_url.clone() + "v4/fullHashes:find";
        
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
    pub fn request(mut self, new_value: FindFullHashesRequest) -> FullHasheFindCall<'a, C> {
        self._request = new_value;
        self
    }
    /// The delegate implementation is consulted whenever there is an intermediate result, or if something goes wrong
    /// while executing the actual API request.
    /// 
    /// It should be used to handle progress information, and to implement a certain level of resilience.
    ///
    /// Sets the *delegate* property to the given value.
    pub fn delegate(mut self, new_value: &'a mut dyn client::Delegate) -> FullHasheFindCall<'a, C> {
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
    pub fn param<T>(mut self, name: T, value: T) -> FullHasheFindCall<'a, C>
                                                        where T: AsRef<str> {
        self._additional_params.insert(name.as_ref().to_string(), value.as_ref().to_string());
        self
    }

}


/// Reports a Safe Browsing threat list hit to Google. Only projects with
/// TRUSTED_REPORTER visibility can use this method.
///
/// A builder for the *create* method supported by a *threatHit* resource.
/// It is not used directly, but through a `ThreatHitMethods` instance.
///
/// # Example
///
/// Instantiate a resource method builder
///
/// ```test_harness,no_run
/// # extern crate hyper;
/// # extern crate hyper_rustls;
/// # extern crate yup_oauth2 as oauth2;
/// # extern crate google_safebrowsing4 as safebrowsing4;
/// use safebrowsing4::api::ThreatHit;
/// # #[test] fn egal() {
/// # use std::default::Default;
/// # use oauth2;
/// # use safebrowsing4::Safebrowsing;
/// 
/// # let secret: ApplicationSecret = Default::default();
/// # let auth = yup_oauth2::InstalledFlowAuthenticator::builder(
/// #         secret,
/// #         yup_oauth2::InstalledFlowReturnMethod::HTTPRedirect,
/// #     ).build().await.unwrap();
/// # let mut hub = Safebrowsing::new(hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())), auth);
/// // As the method needs a request, you would usually fill it with the desired information
/// // into the respective structure. Some of the parts shown here might not be applicable !
/// // Values shown here are possibly random and not representative !
/// let mut req = ThreatHit::default();
/// 
/// // You can configure optional parameters by calling the respective setters at will, and
/// // execute the final call using `doit()`.
/// // Values shown here are possibly random and not representative !
/// let result = hub.threat_hits().create(req)
///              .doit();
/// # }
/// ```
pub struct ThreatHitCreateCall<'a, C>
    where C: 'a {

    hub: &'a Safebrowsing<C>,
    _request: ThreatHit,
    _delegate: Option<&'a mut dyn client::Delegate>,
    _additional_params: HashMap<String, String>,
}

impl<'a, C> client::CallBuilder for ThreatHitCreateCall<'a, C> {}

impl<'a, C> ThreatHitCreateCall<'a, C> where C: BorrowMut<hyper::Client<hyper_rustls::HttpsConnector<hyper::client::connect::HttpConnector>, hyper::body::Body>> {


    /// Perform the operation you have build so far.
    pub async fn doit(mut self) -> client::Result<(hyper::Response<hyper::body::Body>, Empty)> {
        use std::io::{Read, Seek};
        use hyper::header::{CONTENT_TYPE, CONTENT_LENGTH, AUTHORIZATION, USER_AGENT, LOCATION};
        use client::ToParts;
        let mut dd = client::DefaultDelegate;
        let mut dlg: &mut dyn client::Delegate = match self._delegate {
            Some(d) => d,
            None => &mut dd
        };
        dlg.begin(client::MethodInfo { id: "safebrowsing.threatHits.create",
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

        let mut url = self.hub._base_url.clone() + "v4/threatHits";
        
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
    pub fn request(mut self, new_value: ThreatHit) -> ThreatHitCreateCall<'a, C> {
        self._request = new_value;
        self
    }
    /// The delegate implementation is consulted whenever there is an intermediate result, or if something goes wrong
    /// while executing the actual API request.
    /// 
    /// It should be used to handle progress information, and to implement a certain level of resilience.
    ///
    /// Sets the *delegate* property to the given value.
    pub fn delegate(mut self, new_value: &'a mut dyn client::Delegate) -> ThreatHitCreateCall<'a, C> {
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
    pub fn param<T>(mut self, name: T, value: T) -> ThreatHitCreateCall<'a, C>
                                                        where T: AsRef<str> {
        self._additional_params.insert(name.as_ref().to_string(), value.as_ref().to_string());
        self
    }

}


/// Fetches the most recent threat list updates. A client can request updates
/// for multiple lists at once.
///
/// A builder for the *fetch* method supported by a *threatListUpdate* resource.
/// It is not used directly, but through a `ThreatListUpdateMethods` instance.
///
/// # Example
///
/// Instantiate a resource method builder
///
/// ```test_harness,no_run
/// # extern crate hyper;
/// # extern crate hyper_rustls;
/// # extern crate yup_oauth2 as oauth2;
/// # extern crate google_safebrowsing4 as safebrowsing4;
/// use safebrowsing4::api::FetchThreatListUpdatesRequest;
/// # #[test] fn egal() {
/// # use std::default::Default;
/// # use oauth2;
/// # use safebrowsing4::Safebrowsing;
/// 
/// # let secret: ApplicationSecret = Default::default();
/// # let auth = yup_oauth2::InstalledFlowAuthenticator::builder(
/// #         secret,
/// #         yup_oauth2::InstalledFlowReturnMethod::HTTPRedirect,
/// #     ).build().await.unwrap();
/// # let mut hub = Safebrowsing::new(hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())), auth);
/// // As the method needs a request, you would usually fill it with the desired information
/// // into the respective structure. Some of the parts shown here might not be applicable !
/// // Values shown here are possibly random and not representative !
/// let mut req = FetchThreatListUpdatesRequest::default();
/// 
/// // You can configure optional parameters by calling the respective setters at will, and
/// // execute the final call using `doit()`.
/// // Values shown here are possibly random and not representative !
/// let result = hub.threat_list_updates().fetch(req)
///              .doit();
/// # }
/// ```
pub struct ThreatListUpdateFetchCall<'a, C>
    where C: 'a {

    hub: &'a Safebrowsing<C>,
    _request: FetchThreatListUpdatesRequest,
    _delegate: Option<&'a mut dyn client::Delegate>,
    _additional_params: HashMap<String, String>,
}

impl<'a, C> client::CallBuilder for ThreatListUpdateFetchCall<'a, C> {}

impl<'a, C> ThreatListUpdateFetchCall<'a, C> where C: BorrowMut<hyper::Client<hyper_rustls::HttpsConnector<hyper::client::connect::HttpConnector>, hyper::body::Body>> {


    /// Perform the operation you have build so far.
    pub async fn doit(mut self) -> client::Result<(hyper::Response<hyper::body::Body>, FetchThreatListUpdatesResponse)> {
        use std::io::{Read, Seek};
        use hyper::header::{CONTENT_TYPE, CONTENT_LENGTH, AUTHORIZATION, USER_AGENT, LOCATION};
        use client::ToParts;
        let mut dd = client::DefaultDelegate;
        let mut dlg: &mut dyn client::Delegate = match self._delegate {
            Some(d) => d,
            None => &mut dd
        };
        dlg.begin(client::MethodInfo { id: "safebrowsing.threatListUpdates.fetch",
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

        let mut url = self.hub._base_url.clone() + "v4/threatListUpdates:fetch";
        
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
    pub fn request(mut self, new_value: FetchThreatListUpdatesRequest) -> ThreatListUpdateFetchCall<'a, C> {
        self._request = new_value;
        self
    }
    /// The delegate implementation is consulted whenever there is an intermediate result, or if something goes wrong
    /// while executing the actual API request.
    /// 
    /// It should be used to handle progress information, and to implement a certain level of resilience.
    ///
    /// Sets the *delegate* property to the given value.
    pub fn delegate(mut self, new_value: &'a mut dyn client::Delegate) -> ThreatListUpdateFetchCall<'a, C> {
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
    pub fn param<T>(mut self, name: T, value: T) -> ThreatListUpdateFetchCall<'a, C>
                                                        where T: AsRef<str> {
        self._additional_params.insert(name.as_ref().to_string(), value.as_ref().to_string());
        self
    }

}


/// Lists the Safe Browsing threat lists available for download.
///
/// A builder for the *list* method supported by a *threatList* resource.
/// It is not used directly, but through a `ThreatListMethods` instance.
///
/// # Example
///
/// Instantiate a resource method builder
///
/// ```test_harness,no_run
/// # extern crate hyper;
/// # extern crate hyper_rustls;
/// # extern crate yup_oauth2 as oauth2;
/// # extern crate google_safebrowsing4 as safebrowsing4;
/// # #[test] fn egal() {
/// # use std::default::Default;
/// # use oauth2;
/// # use safebrowsing4::Safebrowsing;
/// 
/// # let secret: ApplicationSecret = Default::default();
/// # let auth = yup_oauth2::InstalledFlowAuthenticator::builder(
/// #         secret,
/// #         yup_oauth2::InstalledFlowReturnMethod::HTTPRedirect,
/// #     ).build().await.unwrap();
/// # let mut hub = Safebrowsing::new(hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())), auth);
/// // You can configure optional parameters by calling the respective setters at will, and
/// // execute the final call using `doit()`.
/// // Values shown here are possibly random and not representative !
/// let result = hub.threat_lists().list()
///              .doit();
/// # }
/// ```
pub struct ThreatListListCall<'a, C>
    where C: 'a {

    hub: &'a Safebrowsing<C>,
    _delegate: Option<&'a mut dyn client::Delegate>,
    _additional_params: HashMap<String, String>,
}

impl<'a, C> client::CallBuilder for ThreatListListCall<'a, C> {}

impl<'a, C> ThreatListListCall<'a, C> where C: BorrowMut<hyper::Client<hyper_rustls::HttpsConnector<hyper::client::connect::HttpConnector>, hyper::body::Body>> {


    /// Perform the operation you have build so far.
    pub async fn doit(mut self) -> client::Result<(hyper::Response<hyper::body::Body>, ListThreatListsResponse)> {
        use std::io::{Read, Seek};
        use hyper::header::{CONTENT_TYPE, CONTENT_LENGTH, AUTHORIZATION, USER_AGENT, LOCATION};
        use client::ToParts;
        let mut dd = client::DefaultDelegate;
        let mut dlg: &mut dyn client::Delegate = match self._delegate {
            Some(d) => d,
            None => &mut dd
        };
        dlg.begin(client::MethodInfo { id: "safebrowsing.threatLists.list",
                               http_method: hyper::Method::GET });
        let mut params: Vec<(&str, String)> = Vec::with_capacity(2 + self._additional_params.len());
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

        let mut url = self.hub._base_url.clone() + "v4/threatLists";
        
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



        loop {
            let mut req_result = {
                let mut client = &mut *self.hub.client.borrow_mut();
                dlg.pre_request();
                let mut req_builder = hyper::Request::builder().method(hyper::Method::GET).uri(url.clone().into_string())
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


    /// The delegate implementation is consulted whenever there is an intermediate result, or if something goes wrong
    /// while executing the actual API request.
    /// 
    /// It should be used to handle progress information, and to implement a certain level of resilience.
    ///
    /// Sets the *delegate* property to the given value.
    pub fn delegate(mut self, new_value: &'a mut dyn client::Delegate) -> ThreatListListCall<'a, C> {
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
    pub fn param<T>(mut self, name: T, value: T) -> ThreatListListCall<'a, C>
                                                        where T: AsRef<str> {
        self._additional_params.insert(name.as_ref().to_string(), value.as_ref().to_string());
        self
    }

}


/// Finds the threat entries that match the Safe Browsing lists.
///
/// A builder for the *find* method supported by a *threatMatche* resource.
/// It is not used directly, but through a `ThreatMatcheMethods` instance.
///
/// # Example
///
/// Instantiate a resource method builder
///
/// ```test_harness,no_run
/// # extern crate hyper;
/// # extern crate hyper_rustls;
/// # extern crate yup_oauth2 as oauth2;
/// # extern crate google_safebrowsing4 as safebrowsing4;
/// use safebrowsing4::api::FindThreatMatchesRequest;
/// # #[test] fn egal() {
/// # use std::default::Default;
/// # use oauth2;
/// # use safebrowsing4::Safebrowsing;
/// 
/// # let secret: ApplicationSecret = Default::default();
/// # let auth = yup_oauth2::InstalledFlowAuthenticator::builder(
/// #         secret,
/// #         yup_oauth2::InstalledFlowReturnMethod::HTTPRedirect,
/// #     ).build().await.unwrap();
/// # let mut hub = Safebrowsing::new(hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())), auth);
/// // As the method needs a request, you would usually fill it with the desired information
/// // into the respective structure. Some of the parts shown here might not be applicable !
/// // Values shown here are possibly random and not representative !
/// let mut req = FindThreatMatchesRequest::default();
/// 
/// // You can configure optional parameters by calling the respective setters at will, and
/// // execute the final call using `doit()`.
/// // Values shown here are possibly random and not representative !
/// let result = hub.threat_matches().find(req)
///              .doit();
/// # }
/// ```
pub struct ThreatMatcheFindCall<'a, C>
    where C: 'a {

    hub: &'a Safebrowsing<C>,
    _request: FindThreatMatchesRequest,
    _delegate: Option<&'a mut dyn client::Delegate>,
    _additional_params: HashMap<String, String>,
}

impl<'a, C> client::CallBuilder for ThreatMatcheFindCall<'a, C> {}

impl<'a, C> ThreatMatcheFindCall<'a, C> where C: BorrowMut<hyper::Client<hyper_rustls::HttpsConnector<hyper::client::connect::HttpConnector>, hyper::body::Body>> {


    /// Perform the operation you have build so far.
    pub async fn doit(mut self) -> client::Result<(hyper::Response<hyper::body::Body>, FindThreatMatchesResponse)> {
        use std::io::{Read, Seek};
        use hyper::header::{CONTENT_TYPE, CONTENT_LENGTH, AUTHORIZATION, USER_AGENT, LOCATION};
        use client::ToParts;
        let mut dd = client::DefaultDelegate;
        let mut dlg: &mut dyn client::Delegate = match self._delegate {
            Some(d) => d,
            None => &mut dd
        };
        dlg.begin(client::MethodInfo { id: "safebrowsing.threatMatches.find",
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

        let mut url = self.hub._base_url.clone() + "v4/threatMatches:find";
        
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
    pub fn request(mut self, new_value: FindThreatMatchesRequest) -> ThreatMatcheFindCall<'a, C> {
        self._request = new_value;
        self
    }
    /// The delegate implementation is consulted whenever there is an intermediate result, or if something goes wrong
    /// while executing the actual API request.
    /// 
    /// It should be used to handle progress information, and to implement a certain level of resilience.
    ///
    /// Sets the *delegate* property to the given value.
    pub fn delegate(mut self, new_value: &'a mut dyn client::Delegate) -> ThreatMatcheFindCall<'a, C> {
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
    pub fn param<T>(mut self, name: T, value: T) -> ThreatMatcheFindCall<'a, C>
                                                        where T: AsRef<str> {
        self._additional_params.insert(name.as_ref().to_string(), value.as_ref().to_string());
        self
    }

}

