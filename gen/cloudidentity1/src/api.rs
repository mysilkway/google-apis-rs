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

/// Identifies the an OAuth2 authorization scope.
/// A scope is needed when requesting an
/// [authorization token](https://developers.google.com/youtube/v3/guides/authentication).
#[derive(PartialEq, Eq, Hash)]
pub enum Scope {
    /// See, change, create, and delete any of the Cloud Identity Groups that you can access, including the members of each group
    CloudIdentityGroup,

    /// See any Cloud Identity Groups that you can access, including group members and their emails
    CloudIdentityGroupReadonly,

    /// View and manage your data across Google Cloud Platform services
    CloudPlatform,
}

impl AsRef<str> for Scope {
    fn as_ref(&self) -> &str {
        match *self {
            Scope::CloudIdentityGroup => "https://www.googleapis.com/auth/cloud-identity.groups",
            Scope::CloudIdentityGroupReadonly => "https://www.googleapis.com/auth/cloud-identity.groups.readonly",
            Scope::CloudPlatform => "https://www.googleapis.com/auth/cloud-platform",
        }
    }
}

impl Default for Scope {
    fn default() -> Scope {
        Scope::CloudIdentityGroupReadonly
    }
}



// ########
// HUB ###
// ######

/// Central instance to access all CloudIdentity related resource activities
///
/// # Examples
///
/// Instantiate a new hub
///
/// ```test_harness,no_run
/// extern crate hyper;
/// extern crate hyper_rustls;
/// extern crate yup_oauth2 as oauth2;
/// extern crate google_cloudidentity1 as cloudidentity1;
/// use cloudidentity1::{Result, Error};
/// # #[test] fn egal() {
/// use std::default::Default;
/// use oauth2::{Authenticator, DefaultAuthenticatorDelegate, ApplicationSecret, MemoryStorage};
/// use cloudidentity1::CloudIdentity;
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
/// let mut hub = CloudIdentity::new(hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())), auth);
/// // You can configure optional parameters by calling the respective setters at will, and
/// // execute the final call using `doit()`.
/// // Values shown here are possibly random and not representative !
/// let result = hub.groups().memberships_list("parent")
///              .view("takimata")
///              .page_token("amet.")
///              .page_size(-20)
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
pub struct CloudIdentity<C> {
    client: RefCell<C>,
    auth: RefCell<oauth2::authenticator::Authenticator<hyper_rustls::HttpsConnector<hyper::client::connect::HttpConnector>>>,
    _user_agent: String,
    _base_url: String,
    _root_url: String,
}

impl<'a, C> client::Hub for CloudIdentity<C> {}

impl<'a, C> CloudIdentity<C>
    where  C: BorrowMut<hyper::Client<hyper_rustls::HttpsConnector<hyper::client::connect::HttpConnector>, hyper::body::Body>> {

    pub fn new(client: C, authenticator: oauth2::authenticator::Authenticator<hyper_rustls::HttpsConnector<hyper::client::connect::HttpConnector>>) -> CloudIdentity<C> {
        CloudIdentity {
            client: RefCell::new(client),
            auth: RefCell::new(authenticator),
            _user_agent: "google-api-rust-client/1.0.14".to_string(),
            _base_url: "https://cloudidentity.googleapis.com/".to_string(),
            _root_url: "https://cloudidentity.googleapis.com/".to_string(),
        }
    }

    pub fn groups(&'a self) -> GroupMethods<'a, C> {
        GroupMethods { hub: &self }
    }

    /// Set the user-agent header field to use in all requests to the server.
    /// It defaults to `google-api-rust-client/1.0.14`.
    ///
    /// Returns the previously set user-agent.
    pub fn user_agent(&mut self, agent_name: String) -> String {
        mem::replace(&mut self._user_agent, agent_name)
    }

    /// Set the base url to use in all requests to the server.
    /// It defaults to `https://cloudidentity.googleapis.com/`.
    ///
    /// Returns the previously set base url.
    pub fn base_url(&mut self, new_base_url: String) -> String {
        mem::replace(&mut self._base_url, new_base_url)
    }

    /// Set the root url to use in all requests to the server.
    /// It defaults to `https://cloudidentity.googleapis.com/`.
    ///
    /// Returns the previously set root url.
    pub fn root_url(&mut self, new_root_url: String) -> String {
        mem::replace(&mut self._root_url, new_root_url)
    }
}


// ############
// SCHEMAS ###
// ##########
/// An EntityKey uniquely identifies an Entity. Namespaces are used to provide
/// isolation for IDs. A single ID can be reused across namespaces but the
/// combination of a namespace and an ID must be unique.
/// 
/// This type is not used in any activity, and only used as *part* of another schema.
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct EntityKey {
    /// The ID of the entity within the given namespace. The ID must be unique
    /// within its namespace.
    pub id: Option<String>,
    /// Namespaces provide isolation for IDs, so an ID only needs to be unique
    /// within its namespace.
    /// 
    /// Namespaces are currently only created as part of IdentitySource creation
    /// from Admin Console. A namespace `"identitysources/{identity_source_id}"` is
    /// created corresponding to every Identity Source `identity_source_id`.
    pub namespace: Option<String>,
}

impl client::Part for EntityKey {}


/// Resource representing a Group.
/// 
/// # Activities
/// 
/// This type is used in activities, which are methods you may call on this type or where this type is involved in. 
/// The list links the activity name, along with information about where it is used (one of *request* and *response*).
/// 
/// * [memberships create groups](GroupMembershipCreateCall) (none)
/// * [memberships delete groups](GroupMembershipDeleteCall) (none)
/// * [memberships get groups](GroupMembershipGetCall) (none)
/// * [memberships list groups](GroupMembershipListCall) (none)
/// * [memberships lookup groups](GroupMembershipLookupCall) (none)
/// * [create groups](GroupCreateCall) (request)
/// * [delete groups](GroupDeleteCall) (none)
/// * [get groups](GroupGetCall) (response)
/// * [list groups](GroupListCall) (none)
/// * [lookup groups](GroupLookupCall) (none)
/// * [patch groups](GroupPatchCall) (request)
/// * [search groups](GroupSearchCall) (none)
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct Group {
    /// Output only. The time when the Group was created.
    /// Output only.
    #[serde(rename="createTime")]
    pub create_time: Option<String>,
    /// An extended description to help users determine the purpose of a Group. For
    /// example, you can include information about who should join the Group, the
    /// types of messages to send to the Group, links to FAQs about the Group, or
    /// related Groups. Maximum length is 4,096 characters.
    pub description: Option<String>,
    /// The Group's display name.
    #[serde(rename="displayName")]
    pub display_name: Option<String>,
    /// Required. Immutable. EntityKey of the Group.
    /// 
    /// Must be set when creating a Group, read-only afterwards.
    #[serde(rename="groupKey")]
    pub group_key: Option<EntityKey>,
    /// Required. `Required`. Labels for Group resource.
    /// For creating Groups under a namespace, set label key to
    /// 'labels/system/groups/external' and label value as empty.
    pub labels: Option<HashMap<String, String>>,
    /// Output only. [Resource name](https://cloud.google.com/apis/design/resource_names) of the
    /// Group in the format: `groups/{group_id}`, where group_id is the unique ID
    /// assigned to the Group.
    /// 
    /// Must be left blank while creating a Group.
    pub name: Option<String>,
    /// Required. Immutable. The entity under which this Group resides in Cloud Identity resource
    /// hierarchy. Must be set when creating a Group, read-only afterwards.
    /// 
    /// Currently allowed types: `identitysources`.
    pub parent: Option<String>,
    /// Output only. The time when the Group was last updated.
    /// Output only.
    #[serde(rename="updateTime")]
    pub update_time: Option<String>,
}

impl client::RequestValue for Group {}
impl client::Resource for Group {}
impl client::ResponseResult for Group {}


/// Response message for ListGroups operation.
/// 
/// # Activities
/// 
/// This type is used in activities, which are methods you may call on this type or where this type is involved in. 
/// The list links the activity name, along with information about where it is used (one of *request* and *response*).
/// 
/// * [list groups](GroupListCall) (response)
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct ListGroupsResponse {
    /// Groups returned in response to list request.
    /// The results are not sorted.
    pub groups: Option<Vec<Group>>,
    /// Token to retrieve the next page of results, or empty if there are no
    /// more results available for listing.
    #[serde(rename="nextPageToken")]
    pub next_page_token: Option<String>,
}

impl client::ResponseResult for ListGroupsResponse {}


/// There is no detailed description.
/// 
/// # Activities
/// 
/// This type is used in activities, which are methods you may call on this type or where this type is involved in. 
/// The list links the activity name, along with information about where it is used (one of *request* and *response*).
/// 
/// * [memberships list groups](GroupMembershipListCall) (response)
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct ListMembershipsResponse {
    /// List of Memberships.
    pub memberships: Option<Vec<Membership>>,
    /// Token to retrieve the next page of results, or empty if there are no
    /// more results available for listing.
    #[serde(rename="nextPageToken")]
    pub next_page_token: Option<String>,
}

impl client::ResponseResult for ListMembershipsResponse {}


/// There is no detailed description.
/// 
/// # Activities
/// 
/// This type is used in activities, which are methods you may call on this type or where this type is involved in. 
/// The list links the activity name, along with information about where it is used (one of *request* and *response*).
/// 
/// * [lookup groups](GroupLookupCall) (response)
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct LookupGroupNameResponse {
    /// [Resource name](https://cloud.google.com/apis/design/resource_names) of the
    /// Group in the format: `groups/{group_id}`, where `group_id` is the unique ID
    /// assigned to the Group.
    pub name: Option<String>,
}

impl client::ResponseResult for LookupGroupNameResponse {}


/// There is no detailed description.
/// 
/// # Activities
/// 
/// This type is used in activities, which are methods you may call on this type or where this type is involved in. 
/// The list links the activity name, along with information about where it is used (one of *request* and *response*).
/// 
/// * [memberships lookup groups](GroupMembershipLookupCall) (response)
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct LookupMembershipNameResponse {
    /// [Resource name](https://cloud.google.com/apis/design/resource_names) of the
    /// Membership being looked up.
    /// 
    /// Format: `groups/{group_id}/memberships/{member_id}`, where `group_id` is
    /// the unique ID assigned to the Group to which Membership belongs to, and
    /// `member_id` is the unique ID assigned to the member.
    pub name: Option<String>,
}

impl client::ResponseResult for LookupMembershipNameResponse {}


/// Resource representing a Membership within a Group
/// 
/// # Activities
/// 
/// This type is used in activities, which are methods you may call on this type or where this type is involved in. 
/// The list links the activity name, along with information about where it is used (one of *request* and *response*).
/// 
/// * [memberships create groups](GroupMembershipCreateCall) (request)
/// * [memberships get groups](GroupMembershipGetCall) (response)
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct Membership {
    /// Output only. Creation timestamp of the Membership. Output only.
    #[serde(rename="createTime")]
    pub create_time: Option<String>,
    /// Output only. [Resource name](https://cloud.google.com/apis/design/resource_names) of the
    /// Membership in the format: `groups/{group_id}/memberships/{member_id}`,
    /// where group_id is the unique ID assigned to the Group to which Membership
    /// belongs to, and member_id is the unique ID assigned to the member
    /// 
    /// Must be left blank while creating a Membership.
    pub name: Option<String>,
    /// Required. Immutable. EntityKey of the entity to be added as the member. Must be set while
    /// creating a Membership, read-only afterwards.
    /// 
    /// Currently allowed entity types: `Users`, `Groups`.
    #[serde(rename="preferredMemberKey")]
    pub preferred_member_key: Option<EntityKey>,
    /// Roles for a member within the Group.
    /// 
    /// Currently supported MembershipRoles: `"MEMBER"`.
    pub roles: Option<Vec<MembershipRole>>,
    /// Output only. Last updated timestamp of the Membership. Output only.
    #[serde(rename="updateTime")]
    pub update_time: Option<String>,
}

impl client::RequestValue for Membership {}
impl client::ResponseResult for Membership {}


/// Resource representing a role within a Membership.
/// 
/// This type is not used in any activity, and only used as *part* of another schema.
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct MembershipRole {
    /// MembershipRole in string format.
    /// 
    /// Currently supported MembershipRoles: `"MEMBER"`.
    pub name: Option<String>,
}

impl client::Part for MembershipRole {}


/// This resource represents a long-running operation that is the result of a
/// network API call.
/// 
/// # Activities
/// 
/// This type is used in activities, which are methods you may call on this type or where this type is involved in. 
/// The list links the activity name, along with information about where it is used (one of *request* and *response*).
/// 
/// * [memberships create groups](GroupMembershipCreateCall) (response)
/// * [memberships delete groups](GroupMembershipDeleteCall) (response)
/// * [create groups](GroupCreateCall) (response)
/// * [delete groups](GroupDeleteCall) (response)
/// * [patch groups](GroupPatchCall) (response)
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct Operation {
    /// If the value is `false`, it means the operation is still in progress.
    /// If `true`, the operation is completed, and either `error` or `response` is
    /// available.
    pub done: Option<bool>,
    /// The error result of the operation in case of failure or cancellation.
    pub error: Option<Status>,
    /// Service-specific metadata associated with the operation.  It typically
    /// contains progress information and common metadata such as create time.
    /// Some services might not provide such metadata.  Any method that returns a
    /// long-running operation should document the metadata type, if any.
    pub metadata: Option<HashMap<String, String>>,
    /// The server-assigned name, which is only unique within the same service that
    /// originally returns it. If you use the default HTTP mapping, the
    /// `name` should be a resource name ending with `operations/{unique_id}`.
    pub name: Option<String>,
    /// The normal response of the operation in case of success.  If the original
    /// method returns no data on success, such as `Delete`, the response is
    /// `google.protobuf.Empty`.  If the original method is standard
    /// `Get`/`Create`/`Update`, the response should be the resource.  For other
    /// methods, the response should have the type `XxxResponse`, where `Xxx`
    /// is the original method name.  For example, if the original method name
    /// is `TakeSnapshot()`, the inferred response type is
    /// `TakeSnapshotResponse`.
    pub response: Option<HashMap<String, String>>,
}

impl client::ResponseResult for Operation {}


/// There is no detailed description.
/// 
/// # Activities
/// 
/// This type is used in activities, which are methods you may call on this type or where this type is involved in. 
/// The list links the activity name, along with information about where it is used (one of *request* and *response*).
/// 
/// * [search groups](GroupSearchCall) (response)
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct SearchGroupsResponse {
    /// List of Groups satisfying the search query.
    pub groups: Option<Vec<Group>>,
    /// Token to retrieve the next page of results, or empty if there are no
    /// more results available for specified query.
    #[serde(rename="nextPageToken")]
    pub next_page_token: Option<String>,
}

impl client::ResponseResult for SearchGroupsResponse {}


/// The `Status` type defines a logical error model that is suitable for
/// different programming environments, including REST APIs and RPC APIs. It is
/// used by [gRPC](https://github.com/grpc). Each `Status` message contains
/// three pieces of data: error code, error message, and error details.
/// 
/// You can find out more about this error model and how to work with it in the
/// [API Design Guide](https://cloud.google.com/apis/design/errors).
/// 
/// This type is not used in any activity, and only used as *part* of another schema.
/// 
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct Status {
    /// The status code, which should be an enum value of google.rpc.Code.
    pub code: Option<i32>,
    /// A list of messages that carry the error details.  There is a common set of
    /// message types for APIs to use.
    pub details: Option<Vec<HashMap<String, String>>>,
    /// A developer-facing error message, which should be in English. Any
    /// user-facing error message should be localized and sent in the
    /// google.rpc.Status.details field, or localized by the client.
    pub message: Option<String>,
}

impl client::Part for Status {}



// ###################
// MethodBuilders ###
// #################

/// A builder providing access to all methods supported on *group* resources.
/// It is not used directly, but through the `CloudIdentity` hub.
///
/// # Example
///
/// Instantiate a resource builder
///
/// ```test_harness,no_run
/// extern crate hyper;
/// extern crate hyper_rustls;
/// extern crate yup_oauth2 as oauth2;
/// extern crate google_cloudidentity1 as cloudidentity1;
/// 
/// # #[test] fn egal() {
/// use std::default::Default;
/// use oauth2::{Authenticator, DefaultAuthenticatorDelegate, ApplicationSecret, MemoryStorage};
/// use cloudidentity1::CloudIdentity;
/// 
/// let secret: ApplicationSecret = Default::default();
/// let auth = Authenticator::new(&secret, DefaultAuthenticatorDelegate,
///                               hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())),
///                               <MemoryStorage as Default>::default(), None);
/// let mut hub = CloudIdentity::new(hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())), auth);
/// // Usually you wouldn't bind this to a variable, but keep calling *CallBuilders*
/// // like `create(...)`, `delete(...)`, `get(...)`, `list(...)`, `lookup(...)`, `memberships_create(...)`, `memberships_delete(...)`, `memberships_get(...)`, `memberships_list(...)`, `memberships_lookup(...)`, `patch(...)` and `search(...)`
/// // to build up your call.
/// let rb = hub.groups();
/// # }
/// ```
pub struct GroupMethods<'a, C>
    where C: 'a {

    hub: &'a CloudIdentity<C>,
}

impl<'a, C> client::MethodsBuilder for GroupMethods<'a, C> {}

impl<'a, C> GroupMethods<'a, C> {
    
    /// Create a builder to help you perform the following task:
    ///
    /// Creates a Membership.
    /// 
    /// # Arguments
    ///
    /// * `request` - No description provided.
    /// * `parent` - Required. [Resource name](https://cloud.google.com/apis/design/resource_names) of the
    ///              Group to create Membership within. Format: `groups/{group_id}`, where
    ///              `group_id` is the unique ID assigned to the Group.
    pub fn memberships_create(&self, request: Membership, parent: &str) -> GroupMembershipCreateCall<'a, C> {
        GroupMembershipCreateCall {
            hub: self.hub,
            _request: request,
            _parent: parent.to_string(),
            _delegate: Default::default(),
            _additional_params: Default::default(),
            _scopes: Default::default(),
        }
    }
    
    /// Create a builder to help you perform the following task:
    ///
    /// Deletes a Membership.
    /// 
    /// # Arguments
    ///
    /// * `name` - Required. [Resource name](https://cloud.google.com/apis/design/resource_names) of the
    ///            Membership to be deleted.
    ///            Format: `groups/{group_id}/memberships/{member_id}`, where `group_id` is
    ///            the unique ID assigned to the Group to which Membership belongs to, and
    ///            member_id is the unique ID assigned to the member.
    pub fn memberships_delete(&self, name: &str) -> GroupMembershipDeleteCall<'a, C> {
        GroupMembershipDeleteCall {
            hub: self.hub,
            _name: name.to_string(),
            _delegate: Default::default(),
            _additional_params: Default::default(),
            _scopes: Default::default(),
        }
    }
    
    /// Create a builder to help you perform the following task:
    ///
    /// Retrieves a Membership.
    /// 
    /// # Arguments
    ///
    /// * `name` - Required. [Resource name](https://cloud.google.com/apis/design/resource_names) of the
    ///            Membership to be retrieved.
    ///            Format: `groups/{group_id}/memberships/{member_id}`, where `group_id` is
    ///            the unique id assigned to the Group to which Membership belongs to, and
    ///            `member_id` is the unique ID assigned to the member.
    pub fn memberships_get(&self, name: &str) -> GroupMembershipGetCall<'a, C> {
        GroupMembershipGetCall {
            hub: self.hub,
            _name: name.to_string(),
            _delegate: Default::default(),
            _additional_params: Default::default(),
            _scopes: Default::default(),
        }
    }
    
    /// Create a builder to help you perform the following task:
    ///
    /// Lists Memberships within a Group.
    /// 
    /// # Arguments
    ///
    /// * `parent` - Required. [Resource name](https://cloud.google.com/apis/design/resource_names) of the
    ///              Group to list Memberships within.
    ///              Format: `groups/{group_id}`, where `group_id` is the unique ID assigned to
    ///              the Group.
    pub fn memberships_list(&self, parent: &str) -> GroupMembershipListCall<'a, C> {
        GroupMembershipListCall {
            hub: self.hub,
            _parent: parent.to_string(),
            _view: Default::default(),
            _page_token: Default::default(),
            _page_size: Default::default(),
            _delegate: Default::default(),
            _additional_params: Default::default(),
            _scopes: Default::default(),
        }
    }
    
    /// Create a builder to help you perform the following task:
    ///
    /// Looks up [resource
    /// name](https://cloud.google.com/apis/design/resource_names) of a Membership
    /// within a Group by member's EntityKey.
    /// 
    /// # Arguments
    ///
    /// * `parent` - Required. [Resource name](https://cloud.google.com/apis/design/resource_names) of the
    ///              Group to lookup Membership within.
    ///              Format: `groups/{group_id}`, where `group_id` is the unique ID assigned to
    ///              the Group.
    pub fn memberships_lookup(&self, parent: &str) -> GroupMembershipLookupCall<'a, C> {
        GroupMembershipLookupCall {
            hub: self.hub,
            _parent: parent.to_string(),
            _member_key_namespace: Default::default(),
            _member_key_id: Default::default(),
            _delegate: Default::default(),
            _additional_params: Default::default(),
            _scopes: Default::default(),
        }
    }
    
    /// Create a builder to help you perform the following task:
    ///
    /// Creates a Group.
    /// 
    /// # Arguments
    ///
    /// * `request` - No description provided.
    pub fn create(&self, request: Group) -> GroupCreateCall<'a, C> {
        GroupCreateCall {
            hub: self.hub,
            _request: request,
            _delegate: Default::default(),
            _additional_params: Default::default(),
            _scopes: Default::default(),
        }
    }
    
    /// Create a builder to help you perform the following task:
    ///
    /// Deletes a Group.
    /// 
    /// # Arguments
    ///
    /// * `name` - Required. [Resource name](https://cloud.google.com/apis/design/resource_names) of the
    ///            Group in the format: `groups/{group_id}`, where `group_id` is the unique ID
    ///            assigned to the Group.
    pub fn delete(&self, name: &str) -> GroupDeleteCall<'a, C> {
        GroupDeleteCall {
            hub: self.hub,
            _name: name.to_string(),
            _delegate: Default::default(),
            _additional_params: Default::default(),
            _scopes: Default::default(),
        }
    }
    
    /// Create a builder to help you perform the following task:
    ///
    /// Retrieves a Group.
    /// 
    /// # Arguments
    ///
    /// * `name` - Required. [Resource name](https://cloud.google.com/apis/design/resource_names) of the
    ///            Group in the format: `groups/{group_id}`, where `group_id` is the unique ID
    ///            assigned to the Group.
    pub fn get(&self, name: &str) -> GroupGetCall<'a, C> {
        GroupGetCall {
            hub: self.hub,
            _name: name.to_string(),
            _delegate: Default::default(),
            _additional_params: Default::default(),
            _scopes: Default::default(),
        }
    }
    
    /// Create a builder to help you perform the following task:
    ///
    /// Lists groups within a customer or a domain.
    pub fn list(&self) -> GroupListCall<'a, C> {
        GroupListCall {
            hub: self.hub,
            _view: Default::default(),
            _parent: Default::default(),
            _page_token: Default::default(),
            _page_size: Default::default(),
            _delegate: Default::default(),
            _additional_params: Default::default(),
            _scopes: Default::default(),
        }
    }
    
    /// Create a builder to help you perform the following task:
    ///
    /// Looks up [resource
    /// name](https://cloud.google.com/apis/design/resource_names) of a Group by
    /// its EntityKey.
    pub fn lookup(&self) -> GroupLookupCall<'a, C> {
        GroupLookupCall {
            hub: self.hub,
            _group_key_namespace: Default::default(),
            _group_key_id: Default::default(),
            _delegate: Default::default(),
            _additional_params: Default::default(),
            _scopes: Default::default(),
        }
    }
    
    /// Create a builder to help you perform the following task:
    ///
    /// Updates a Group.
    /// 
    /// # Arguments
    ///
    /// * `request` - No description provided.
    /// * `name` - Output only. [Resource name](https://cloud.google.com/apis/design/resource_names) of the
    ///            Group in the format: `groups/{group_id}`, where group_id is the unique ID
    ///            assigned to the Group.
    ///            Must be left blank while creating a Group.
    pub fn patch(&self, request: Group, name: &str) -> GroupPatchCall<'a, C> {
        GroupPatchCall {
            hub: self.hub,
            _request: request,
            _name: name.to_string(),
            _update_mask: Default::default(),
            _delegate: Default::default(),
            _additional_params: Default::default(),
            _scopes: Default::default(),
        }
    }
    
    /// Create a builder to help you perform the following task:
    ///
    /// Searches for Groups.
    pub fn search(&self) -> GroupSearchCall<'a, C> {
        GroupSearchCall {
            hub: self.hub,
            _view: Default::default(),
            _query: Default::default(),
            _page_token: Default::default(),
            _page_size: Default::default(),
            _delegate: Default::default(),
            _additional_params: Default::default(),
            _scopes: Default::default(),
        }
    }
}





// ###################
// CallBuilders   ###
// #################

/// Creates a Membership.
///
/// A builder for the *memberships.create* method supported by a *group* resource.
/// It is not used directly, but through a `GroupMethods` instance.
///
/// # Example
///
/// Instantiate a resource method builder
///
/// ```test_harness,no_run
/// # extern crate hyper;
/// # extern crate hyper_rustls;
/// # extern crate yup_oauth2 as oauth2;
/// # extern crate google_cloudidentity1 as cloudidentity1;
/// use cloudidentity1::api::Membership;
/// # #[test] fn egal() {
/// # use std::default::Default;
/// # use oauth2::{Authenticator, DefaultAuthenticatorDelegate, ApplicationSecret, MemoryStorage};
/// # use cloudidentity1::CloudIdentity;
/// 
/// # let secret: ApplicationSecret = Default::default();
/// # let auth = Authenticator::new(&secret, DefaultAuthenticatorDelegate,
/// #                               hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())),
/// #                               <MemoryStorage as Default>::default(), None);
/// # let mut hub = CloudIdentity::new(hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())), auth);
/// // As the method needs a request, you would usually fill it with the desired information
/// // into the respective structure. Some of the parts shown here might not be applicable !
/// // Values shown here are possibly random and not representative !
/// let mut req = Membership::default();
/// 
/// // You can configure optional parameters by calling the respective setters at will, and
/// // execute the final call using `doit()`.
/// // Values shown here are possibly random and not representative !
/// let result = hub.groups().memberships_create(req, "parent")
///              .doit();
/// # }
/// ```
pub struct GroupMembershipCreateCall<'a, C>
    where C: 'a {

    hub: &'a CloudIdentity<C>,
    _request: Membership,
    _parent: String,
    _delegate: Option<&'a mut dyn client::Delegate>,
    _additional_params: HashMap<String, String>,
    _scopes: BTreeMap<String, ()>
}

impl<'a, C> client::CallBuilder for GroupMembershipCreateCall<'a, C> {}

impl<'a, C> GroupMembershipCreateCall<'a, C> where C: BorrowMut<hyper::Client<hyper_rustls::HttpsConnector<hyper::client::connect::HttpConnector>, hyper::body::Body>> {


    /// Perform the operation you have build so far.
    pub async fn doit(mut self) -> client::Result<(hyper::Response<hyper::body::Body>, Operation)> {
        use url::percent_encoding::{percent_encode, DEFAULT_ENCODE_SET};
        use std::io::{Read, Seek};
        use hyper::header::{CONTENT_TYPE, CONTENT_LENGTH, AUTHORIZATION, USER_AGENT, LOCATION};
        use client::ToParts;
        let mut dd = client::DefaultDelegate;
        let mut dlg: &mut dyn client::Delegate = match self._delegate {
            Some(d) => d,
            None => &mut dd
        };
        dlg.begin(client::MethodInfo { id: "cloudidentity.groups.memberships.create",
                               http_method: hyper::Method::POST });
        let mut params: Vec<(&str, String)> = Vec::with_capacity(4 + self._additional_params.len());
        params.push(("parent", self._parent.to_string()));
        for &field in ["alt", "parent"].iter() {
            if self._additional_params.contains_key(field) {
                dlg.finished(false);
                return Err(client::Error::FieldClash(field));
            }
        }
        for (name, value) in self._additional_params.iter() {
            params.push((&name, value.clone()));
        }

        params.push(("alt", "json".to_string()));

        let mut url = self.hub._base_url.clone() + "v1/{+parent}/memberships";
        if self._scopes.len() == 0 {
            self._scopes.insert(Scope::CloudIdentityGroup.as_ref().to_string(), ());
        }

        for &(find_this, param_name) in [("{+parent}", "parent")].iter() {
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
            for param_name in ["parent"].iter() {
                if let Some(index) = params.iter().position(|t| &t.0 == param_name) {
                    indices_for_removal.push(index);
                }
            }
            for &index in indices_for_removal.iter() {
                params.remove(index);
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
            let authenticator = self.hub.auth.borrow_mut();
            let token = match authenticator.token(&self._scopes.keys().collect::<Vec<_>>()[..]).await {
                Ok(token) => token.clone(),
                Err(err) => {
                    match  dlg.token(&err) {
                        Some(token) => token,
                        None => {
                            dlg.finished(false);
                            return Err(client::Error::MissingToken(err))
                        }
                    }
                }
            };
            request_value_reader.seek(io::SeekFrom::Start(0)).unwrap();
            let mut req_result = {
                let mut client = &mut *self.hub.client.borrow_mut();
                dlg.pre_request();
                let mut req_builder = hyper::Request::builder().method(hyper::Method::POST).uri(url.clone().into_string())
                        .header(USER_AGENT, self.hub._user_agent.clone())
                        .header(AUTHORIZATION, format!("Bearer {}", token.as_str()))
                        .header(CONTENT_TYPE, format!("{}", json_mime_type))
                        .header(CONTENT_LENGTH, request_size as u64)
                        .body(hyper::body::Body::from(request_value_reader.get_ref().clone()))                        .unwrap()
;

                client.borrow_mut().request(req_builder).await
                
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
    pub fn request(mut self, new_value: Membership) -> GroupMembershipCreateCall<'a, C> {
        self._request = new_value;
        self
    }
    /// Required. [Resource name](https://cloud.google.com/apis/design/resource_names) of the
    /// Group to create Membership within. Format: `groups/{group_id}`, where
    /// `group_id` is the unique ID assigned to the Group.
    ///
    /// Sets the *parent* path property to the given value.
    ///
    /// Even though the property as already been set when instantiating this call,
    /// we provide this method for API completeness.
    pub fn parent(mut self, new_value: &str) -> GroupMembershipCreateCall<'a, C> {
        self._parent = new_value.to_string();
        self
    }
    /// The delegate implementation is consulted whenever there is an intermediate result, or if something goes wrong
    /// while executing the actual API request.
    /// 
    /// It should be used to handle progress information, and to implement a certain level of resilience.
    ///
    /// Sets the *delegate* property to the given value.
    pub fn delegate(mut self, new_value: &'a mut dyn client::Delegate) -> GroupMembershipCreateCall<'a, C> {
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
    pub fn param<T>(mut self, name: T, value: T) -> GroupMembershipCreateCall<'a, C>
                                                        where T: AsRef<str> {
        self._additional_params.insert(name.as_ref().to_string(), value.as_ref().to_string());
        self
    }

    /// Identifies the authorization scope for the method you are building.
    ///
    /// Use this method to actively specify which scope should be used, instead the default `Scope` variant
    /// `Scope::CloudIdentityGroup`.
    ///
    /// The `scope` will be added to a set of scopes. This is important as one can maintain access
    /// tokens for more than one scope.
    /// If `None` is specified, then all scopes will be removed and no default scope will be used either.
    /// In that case, you have to specify your API-key using the `key` parameter (see the `param()`
    /// function for details).
    ///
    /// Usually there is more than one suitable scope to authorize an operation, some of which may
    /// encompass more rights than others. For example, for listing resources, a *read-only* scope will be
    /// sufficient, a read-write scope will do as well.
    pub fn add_scope<T, S>(mut self, scope: T) -> GroupMembershipCreateCall<'a, C>
                                                        where T: Into<Option<S>>,
                                                              S: AsRef<str> {
        match scope.into() {
          Some(scope) => self._scopes.insert(scope.as_ref().to_string(), ()),
          None => None,
        };
        self
    }
}


/// Deletes a Membership.
///
/// A builder for the *memberships.delete* method supported by a *group* resource.
/// It is not used directly, but through a `GroupMethods` instance.
///
/// # Example
///
/// Instantiate a resource method builder
///
/// ```test_harness,no_run
/// # extern crate hyper;
/// # extern crate hyper_rustls;
/// # extern crate yup_oauth2 as oauth2;
/// # extern crate google_cloudidentity1 as cloudidentity1;
/// # #[test] fn egal() {
/// # use std::default::Default;
/// # use oauth2::{Authenticator, DefaultAuthenticatorDelegate, ApplicationSecret, MemoryStorage};
/// # use cloudidentity1::CloudIdentity;
/// 
/// # let secret: ApplicationSecret = Default::default();
/// # let auth = Authenticator::new(&secret, DefaultAuthenticatorDelegate,
/// #                               hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())),
/// #                               <MemoryStorage as Default>::default(), None);
/// # let mut hub = CloudIdentity::new(hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())), auth);
/// // You can configure optional parameters by calling the respective setters at will, and
/// // execute the final call using `doit()`.
/// // Values shown here are possibly random and not representative !
/// let result = hub.groups().memberships_delete("name")
///              .doit();
/// # }
/// ```
pub struct GroupMembershipDeleteCall<'a, C>
    where C: 'a {

    hub: &'a CloudIdentity<C>,
    _name: String,
    _delegate: Option<&'a mut dyn client::Delegate>,
    _additional_params: HashMap<String, String>,
    _scopes: BTreeMap<String, ()>
}

impl<'a, C> client::CallBuilder for GroupMembershipDeleteCall<'a, C> {}

impl<'a, C> GroupMembershipDeleteCall<'a, C> where C: BorrowMut<hyper::Client<hyper_rustls::HttpsConnector<hyper::client::connect::HttpConnector>, hyper::body::Body>> {


    /// Perform the operation you have build so far.
    pub async fn doit(mut self) -> client::Result<(hyper::Response<hyper::body::Body>, Operation)> {
        use url::percent_encoding::{percent_encode, DEFAULT_ENCODE_SET};
        use std::io::{Read, Seek};
        use hyper::header::{CONTENT_TYPE, CONTENT_LENGTH, AUTHORIZATION, USER_AGENT, LOCATION};
        use client::ToParts;
        let mut dd = client::DefaultDelegate;
        let mut dlg: &mut dyn client::Delegate = match self._delegate {
            Some(d) => d,
            None => &mut dd
        };
        dlg.begin(client::MethodInfo { id: "cloudidentity.groups.memberships.delete",
                               http_method: hyper::Method::DELETE });
        let mut params: Vec<(&str, String)> = Vec::with_capacity(3 + self._additional_params.len());
        params.push(("name", self._name.to_string()));
        for &field in ["alt", "name"].iter() {
            if self._additional_params.contains_key(field) {
                dlg.finished(false);
                return Err(client::Error::FieldClash(field));
            }
        }
        for (name, value) in self._additional_params.iter() {
            params.push((&name, value.clone()));
        }

        params.push(("alt", "json".to_string()));

        let mut url = self.hub._base_url.clone() + "v1/{+name}";
        if self._scopes.len() == 0 {
            self._scopes.insert(Scope::CloudIdentityGroup.as_ref().to_string(), ());
        }

        for &(find_this, param_name) in [("{+name}", "name")].iter() {
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
            for param_name in ["name"].iter() {
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
            let authenticator = self.hub.auth.borrow_mut();
            let token = match authenticator.token(&self._scopes.keys().collect::<Vec<_>>()[..]).await {
                Ok(token) => token.clone(),
                Err(err) => {
                    match  dlg.token(&err) {
                        Some(token) => token,
                        None => {
                            dlg.finished(false);
                            return Err(client::Error::MissingToken(err))
                        }
                    }
                }
            };
            let mut req_result = {
                let mut client = &mut *self.hub.client.borrow_mut();
                dlg.pre_request();
                let mut req_builder = hyper::Request::builder().method(hyper::Method::DELETE).uri(url.clone().into_string())
                        .header(USER_AGENT, self.hub._user_agent.clone())
                        .header(AUTHORIZATION, format!("Bearer {}", token.as_str()))                        .body(hyper::body::Body::empty())                        .unwrap()
;

                client.borrow_mut().request(req_builder).await
                
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


    /// Required. [Resource name](https://cloud.google.com/apis/design/resource_names) of the
    /// Membership to be deleted.
    /// 
    /// Format: `groups/{group_id}/memberships/{member_id}`, where `group_id` is
    /// the unique ID assigned to the Group to which Membership belongs to, and
    /// member_id is the unique ID assigned to the member.
    ///
    /// Sets the *name* path property to the given value.
    ///
    /// Even though the property as already been set when instantiating this call,
    /// we provide this method for API completeness.
    pub fn name(mut self, new_value: &str) -> GroupMembershipDeleteCall<'a, C> {
        self._name = new_value.to_string();
        self
    }
    /// The delegate implementation is consulted whenever there is an intermediate result, or if something goes wrong
    /// while executing the actual API request.
    /// 
    /// It should be used to handle progress information, and to implement a certain level of resilience.
    ///
    /// Sets the *delegate* property to the given value.
    pub fn delegate(mut self, new_value: &'a mut dyn client::Delegate) -> GroupMembershipDeleteCall<'a, C> {
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
    pub fn param<T>(mut self, name: T, value: T) -> GroupMembershipDeleteCall<'a, C>
                                                        where T: AsRef<str> {
        self._additional_params.insert(name.as_ref().to_string(), value.as_ref().to_string());
        self
    }

    /// Identifies the authorization scope for the method you are building.
    ///
    /// Use this method to actively specify which scope should be used, instead the default `Scope` variant
    /// `Scope::CloudIdentityGroup`.
    ///
    /// The `scope` will be added to a set of scopes. This is important as one can maintain access
    /// tokens for more than one scope.
    /// If `None` is specified, then all scopes will be removed and no default scope will be used either.
    /// In that case, you have to specify your API-key using the `key` parameter (see the `param()`
    /// function for details).
    ///
    /// Usually there is more than one suitable scope to authorize an operation, some of which may
    /// encompass more rights than others. For example, for listing resources, a *read-only* scope will be
    /// sufficient, a read-write scope will do as well.
    pub fn add_scope<T, S>(mut self, scope: T) -> GroupMembershipDeleteCall<'a, C>
                                                        where T: Into<Option<S>>,
                                                              S: AsRef<str> {
        match scope.into() {
          Some(scope) => self._scopes.insert(scope.as_ref().to_string(), ()),
          None => None,
        };
        self
    }
}


/// Retrieves a Membership.
///
/// A builder for the *memberships.get* method supported by a *group* resource.
/// It is not used directly, but through a `GroupMethods` instance.
///
/// # Example
///
/// Instantiate a resource method builder
///
/// ```test_harness,no_run
/// # extern crate hyper;
/// # extern crate hyper_rustls;
/// # extern crate yup_oauth2 as oauth2;
/// # extern crate google_cloudidentity1 as cloudidentity1;
/// # #[test] fn egal() {
/// # use std::default::Default;
/// # use oauth2::{Authenticator, DefaultAuthenticatorDelegate, ApplicationSecret, MemoryStorage};
/// # use cloudidentity1::CloudIdentity;
/// 
/// # let secret: ApplicationSecret = Default::default();
/// # let auth = Authenticator::new(&secret, DefaultAuthenticatorDelegate,
/// #                               hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())),
/// #                               <MemoryStorage as Default>::default(), None);
/// # let mut hub = CloudIdentity::new(hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())), auth);
/// // You can configure optional parameters by calling the respective setters at will, and
/// // execute the final call using `doit()`.
/// // Values shown here are possibly random and not representative !
/// let result = hub.groups().memberships_get("name")
///              .doit();
/// # }
/// ```
pub struct GroupMembershipGetCall<'a, C>
    where C: 'a {

    hub: &'a CloudIdentity<C>,
    _name: String,
    _delegate: Option<&'a mut dyn client::Delegate>,
    _additional_params: HashMap<String, String>,
    _scopes: BTreeMap<String, ()>
}

impl<'a, C> client::CallBuilder for GroupMembershipGetCall<'a, C> {}

impl<'a, C> GroupMembershipGetCall<'a, C> where C: BorrowMut<hyper::Client<hyper_rustls::HttpsConnector<hyper::client::connect::HttpConnector>, hyper::body::Body>> {


    /// Perform the operation you have build so far.
    pub async fn doit(mut self) -> client::Result<(hyper::Response<hyper::body::Body>, Membership)> {
        use url::percent_encoding::{percent_encode, DEFAULT_ENCODE_SET};
        use std::io::{Read, Seek};
        use hyper::header::{CONTENT_TYPE, CONTENT_LENGTH, AUTHORIZATION, USER_AGENT, LOCATION};
        use client::ToParts;
        let mut dd = client::DefaultDelegate;
        let mut dlg: &mut dyn client::Delegate = match self._delegate {
            Some(d) => d,
            None => &mut dd
        };
        dlg.begin(client::MethodInfo { id: "cloudidentity.groups.memberships.get",
                               http_method: hyper::Method::GET });
        let mut params: Vec<(&str, String)> = Vec::with_capacity(3 + self._additional_params.len());
        params.push(("name", self._name.to_string()));
        for &field in ["alt", "name"].iter() {
            if self._additional_params.contains_key(field) {
                dlg.finished(false);
                return Err(client::Error::FieldClash(field));
            }
        }
        for (name, value) in self._additional_params.iter() {
            params.push((&name, value.clone()));
        }

        params.push(("alt", "json".to_string()));

        let mut url = self.hub._base_url.clone() + "v1/{+name}";
        if self._scopes.len() == 0 {
            self._scopes.insert(Scope::CloudIdentityGroupReadonly.as_ref().to_string(), ());
        }

        for &(find_this, param_name) in [("{+name}", "name")].iter() {
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
            for param_name in ["name"].iter() {
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
            let authenticator = self.hub.auth.borrow_mut();
            let token = match authenticator.token(&self._scopes.keys().collect::<Vec<_>>()[..]).await {
                Ok(token) => token.clone(),
                Err(err) => {
                    match  dlg.token(&err) {
                        Some(token) => token,
                        None => {
                            dlg.finished(false);
                            return Err(client::Error::MissingToken(err))
                        }
                    }
                }
            };
            let mut req_result = {
                let mut client = &mut *self.hub.client.borrow_mut();
                dlg.pre_request();
                let mut req_builder = hyper::Request::builder().method(hyper::Method::GET).uri(url.clone().into_string())
                        .header(USER_AGENT, self.hub._user_agent.clone())
                        .header(AUTHORIZATION, format!("Bearer {}", token.as_str()))                        .body(hyper::body::Body::empty())                        .unwrap()
;

                client.borrow_mut().request(req_builder).await
                
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


    /// Required. [Resource name](https://cloud.google.com/apis/design/resource_names) of the
    /// Membership to be retrieved.
    /// 
    /// Format: `groups/{group_id}/memberships/{member_id}`, where `group_id` is
    /// the unique id assigned to the Group to which Membership belongs to, and
    /// `member_id` is the unique ID assigned to the member.
    ///
    /// Sets the *name* path property to the given value.
    ///
    /// Even though the property as already been set when instantiating this call,
    /// we provide this method for API completeness.
    pub fn name(mut self, new_value: &str) -> GroupMembershipGetCall<'a, C> {
        self._name = new_value.to_string();
        self
    }
    /// The delegate implementation is consulted whenever there is an intermediate result, or if something goes wrong
    /// while executing the actual API request.
    /// 
    /// It should be used to handle progress information, and to implement a certain level of resilience.
    ///
    /// Sets the *delegate* property to the given value.
    pub fn delegate(mut self, new_value: &'a mut dyn client::Delegate) -> GroupMembershipGetCall<'a, C> {
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
    pub fn param<T>(mut self, name: T, value: T) -> GroupMembershipGetCall<'a, C>
                                                        where T: AsRef<str> {
        self._additional_params.insert(name.as_ref().to_string(), value.as_ref().to_string());
        self
    }

    /// Identifies the authorization scope for the method you are building.
    ///
    /// Use this method to actively specify which scope should be used, instead the default `Scope` variant
    /// `Scope::CloudIdentityGroupReadonly`.
    ///
    /// The `scope` will be added to a set of scopes. This is important as one can maintain access
    /// tokens for more than one scope.
    /// If `None` is specified, then all scopes will be removed and no default scope will be used either.
    /// In that case, you have to specify your API-key using the `key` parameter (see the `param()`
    /// function for details).
    ///
    /// Usually there is more than one suitable scope to authorize an operation, some of which may
    /// encompass more rights than others. For example, for listing resources, a *read-only* scope will be
    /// sufficient, a read-write scope will do as well.
    pub fn add_scope<T, S>(mut self, scope: T) -> GroupMembershipGetCall<'a, C>
                                                        where T: Into<Option<S>>,
                                                              S: AsRef<str> {
        match scope.into() {
          Some(scope) => self._scopes.insert(scope.as_ref().to_string(), ()),
          None => None,
        };
        self
    }
}


/// Lists Memberships within a Group.
///
/// A builder for the *memberships.list* method supported by a *group* resource.
/// It is not used directly, but through a `GroupMethods` instance.
///
/// # Example
///
/// Instantiate a resource method builder
///
/// ```test_harness,no_run
/// # extern crate hyper;
/// # extern crate hyper_rustls;
/// # extern crate yup_oauth2 as oauth2;
/// # extern crate google_cloudidentity1 as cloudidentity1;
/// # #[test] fn egal() {
/// # use std::default::Default;
/// # use oauth2::{Authenticator, DefaultAuthenticatorDelegate, ApplicationSecret, MemoryStorage};
/// # use cloudidentity1::CloudIdentity;
/// 
/// # let secret: ApplicationSecret = Default::default();
/// # let auth = Authenticator::new(&secret, DefaultAuthenticatorDelegate,
/// #                               hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())),
/// #                               <MemoryStorage as Default>::default(), None);
/// # let mut hub = CloudIdentity::new(hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())), auth);
/// // You can configure optional parameters by calling the respective setters at will, and
/// // execute the final call using `doit()`.
/// // Values shown here are possibly random and not representative !
/// let result = hub.groups().memberships_list("parent")
///              .view("eos")
///              .page_token("dolor")
///              .page_size(-17)
///              .doit();
/// # }
/// ```
pub struct GroupMembershipListCall<'a, C>
    where C: 'a {

    hub: &'a CloudIdentity<C>,
    _parent: String,
    _view: Option<String>,
    _page_token: Option<String>,
    _page_size: Option<i32>,
    _delegate: Option<&'a mut dyn client::Delegate>,
    _additional_params: HashMap<String, String>,
    _scopes: BTreeMap<String, ()>
}

impl<'a, C> client::CallBuilder for GroupMembershipListCall<'a, C> {}

impl<'a, C> GroupMembershipListCall<'a, C> where C: BorrowMut<hyper::Client<hyper_rustls::HttpsConnector<hyper::client::connect::HttpConnector>, hyper::body::Body>> {


    /// Perform the operation you have build so far.
    pub async fn doit(mut self) -> client::Result<(hyper::Response<hyper::body::Body>, ListMembershipsResponse)> {
        use url::percent_encoding::{percent_encode, DEFAULT_ENCODE_SET};
        use std::io::{Read, Seek};
        use hyper::header::{CONTENT_TYPE, CONTENT_LENGTH, AUTHORIZATION, USER_AGENT, LOCATION};
        use client::ToParts;
        let mut dd = client::DefaultDelegate;
        let mut dlg: &mut dyn client::Delegate = match self._delegate {
            Some(d) => d,
            None => &mut dd
        };
        dlg.begin(client::MethodInfo { id: "cloudidentity.groups.memberships.list",
                               http_method: hyper::Method::GET });
        let mut params: Vec<(&str, String)> = Vec::with_capacity(6 + self._additional_params.len());
        params.push(("parent", self._parent.to_string()));
        if let Some(value) = self._view {
            params.push(("view", value.to_string()));
        }
        if let Some(value) = self._page_token {
            params.push(("pageToken", value.to_string()));
        }
        if let Some(value) = self._page_size {
            params.push(("pageSize", value.to_string()));
        }
        for &field in ["alt", "parent", "view", "pageToken", "pageSize"].iter() {
            if self._additional_params.contains_key(field) {
                dlg.finished(false);
                return Err(client::Error::FieldClash(field));
            }
        }
        for (name, value) in self._additional_params.iter() {
            params.push((&name, value.clone()));
        }

        params.push(("alt", "json".to_string()));

        let mut url = self.hub._base_url.clone() + "v1/{+parent}/memberships";
        if self._scopes.len() == 0 {
            self._scopes.insert(Scope::CloudIdentityGroupReadonly.as_ref().to_string(), ());
        }

        for &(find_this, param_name) in [("{+parent}", "parent")].iter() {
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
            for param_name in ["parent"].iter() {
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
            let authenticator = self.hub.auth.borrow_mut();
            let token = match authenticator.token(&self._scopes.keys().collect::<Vec<_>>()[..]).await {
                Ok(token) => token.clone(),
                Err(err) => {
                    match  dlg.token(&err) {
                        Some(token) => token,
                        None => {
                            dlg.finished(false);
                            return Err(client::Error::MissingToken(err))
                        }
                    }
                }
            };
            let mut req_result = {
                let mut client = &mut *self.hub.client.borrow_mut();
                dlg.pre_request();
                let mut req_builder = hyper::Request::builder().method(hyper::Method::GET).uri(url.clone().into_string())
                        .header(USER_AGENT, self.hub._user_agent.clone())
                        .header(AUTHORIZATION, format!("Bearer {}", token.as_str()))                        .body(hyper::body::Body::empty())                        .unwrap()
;

                client.borrow_mut().request(req_builder).await
                
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


    /// Required. [Resource name](https://cloud.google.com/apis/design/resource_names) of the
    /// Group to list Memberships within.
    /// 
    /// Format: `groups/{group_id}`, where `group_id` is the unique ID assigned to
    /// the Group.
    ///
    /// Sets the *parent* path property to the given value.
    ///
    /// Even though the property as already been set when instantiating this call,
    /// we provide this method for API completeness.
    pub fn parent(mut self, new_value: &str) -> GroupMembershipListCall<'a, C> {
        self._parent = new_value.to_string();
        self
    }
    /// Membership resource view to be returned. Defaults to View.BASIC.
    ///
    /// Sets the *view* query property to the given value.
    pub fn view(mut self, new_value: &str) -> GroupMembershipListCall<'a, C> {
        self._view = Some(new_value.to_string());
        self
    }
    /// The next_page_token value returned from a previous list request, if any.
    ///
    /// Sets the *page token* query property to the given value.
    pub fn page_token(mut self, new_value: &str) -> GroupMembershipListCall<'a, C> {
        self._page_token = Some(new_value.to_string());
        self
    }
    /// The default page size is 200 (max 1000) for the BASIC view, and 50
    /// (max 500) for the FULL view.
    ///
    /// Sets the *page size* query property to the given value.
    pub fn page_size(mut self, new_value: i32) -> GroupMembershipListCall<'a, C> {
        self._page_size = Some(new_value);
        self
    }
    /// The delegate implementation is consulted whenever there is an intermediate result, or if something goes wrong
    /// while executing the actual API request.
    /// 
    /// It should be used to handle progress information, and to implement a certain level of resilience.
    ///
    /// Sets the *delegate* property to the given value.
    pub fn delegate(mut self, new_value: &'a mut dyn client::Delegate) -> GroupMembershipListCall<'a, C> {
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
    pub fn param<T>(mut self, name: T, value: T) -> GroupMembershipListCall<'a, C>
                                                        where T: AsRef<str> {
        self._additional_params.insert(name.as_ref().to_string(), value.as_ref().to_string());
        self
    }

    /// Identifies the authorization scope for the method you are building.
    ///
    /// Use this method to actively specify which scope should be used, instead the default `Scope` variant
    /// `Scope::CloudIdentityGroupReadonly`.
    ///
    /// The `scope` will be added to a set of scopes. This is important as one can maintain access
    /// tokens for more than one scope.
    /// If `None` is specified, then all scopes will be removed and no default scope will be used either.
    /// In that case, you have to specify your API-key using the `key` parameter (see the `param()`
    /// function for details).
    ///
    /// Usually there is more than one suitable scope to authorize an operation, some of which may
    /// encompass more rights than others. For example, for listing resources, a *read-only* scope will be
    /// sufficient, a read-write scope will do as well.
    pub fn add_scope<T, S>(mut self, scope: T) -> GroupMembershipListCall<'a, C>
                                                        where T: Into<Option<S>>,
                                                              S: AsRef<str> {
        match scope.into() {
          Some(scope) => self._scopes.insert(scope.as_ref().to_string(), ()),
          None => None,
        };
        self
    }
}


/// Looks up [resource
/// name](https://cloud.google.com/apis/design/resource_names) of a Membership
/// within a Group by member's EntityKey.
///
/// A builder for the *memberships.lookup* method supported by a *group* resource.
/// It is not used directly, but through a `GroupMethods` instance.
///
/// # Example
///
/// Instantiate a resource method builder
///
/// ```test_harness,no_run
/// # extern crate hyper;
/// # extern crate hyper_rustls;
/// # extern crate yup_oauth2 as oauth2;
/// # extern crate google_cloudidentity1 as cloudidentity1;
/// # #[test] fn egal() {
/// # use std::default::Default;
/// # use oauth2::{Authenticator, DefaultAuthenticatorDelegate, ApplicationSecret, MemoryStorage};
/// # use cloudidentity1::CloudIdentity;
/// 
/// # let secret: ApplicationSecret = Default::default();
/// # let auth = Authenticator::new(&secret, DefaultAuthenticatorDelegate,
/// #                               hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())),
/// #                               <MemoryStorage as Default>::default(), None);
/// # let mut hub = CloudIdentity::new(hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())), auth);
/// // You can configure optional parameters by calling the respective setters at will, and
/// // execute the final call using `doit()`.
/// // Values shown here are possibly random and not representative !
/// let result = hub.groups().memberships_lookup("parent")
///              .member_key_namespace("invidunt")
///              .member_key_id("amet")
///              .doit();
/// # }
/// ```
pub struct GroupMembershipLookupCall<'a, C>
    where C: 'a {

    hub: &'a CloudIdentity<C>,
    _parent: String,
    _member_key_namespace: Option<String>,
    _member_key_id: Option<String>,
    _delegate: Option<&'a mut dyn client::Delegate>,
    _additional_params: HashMap<String, String>,
    _scopes: BTreeMap<String, ()>
}

impl<'a, C> client::CallBuilder for GroupMembershipLookupCall<'a, C> {}

impl<'a, C> GroupMembershipLookupCall<'a, C> where C: BorrowMut<hyper::Client<hyper_rustls::HttpsConnector<hyper::client::connect::HttpConnector>, hyper::body::Body>> {


    /// Perform the operation you have build so far.
    pub async fn doit(mut self) -> client::Result<(hyper::Response<hyper::body::Body>, LookupMembershipNameResponse)> {
        use url::percent_encoding::{percent_encode, DEFAULT_ENCODE_SET};
        use std::io::{Read, Seek};
        use hyper::header::{CONTENT_TYPE, CONTENT_LENGTH, AUTHORIZATION, USER_AGENT, LOCATION};
        use client::ToParts;
        let mut dd = client::DefaultDelegate;
        let mut dlg: &mut dyn client::Delegate = match self._delegate {
            Some(d) => d,
            None => &mut dd
        };
        dlg.begin(client::MethodInfo { id: "cloudidentity.groups.memberships.lookup",
                               http_method: hyper::Method::GET });
        let mut params: Vec<(&str, String)> = Vec::with_capacity(5 + self._additional_params.len());
        params.push(("parent", self._parent.to_string()));
        if let Some(value) = self._member_key_namespace {
            params.push(("memberKey.namespace", value.to_string()));
        }
        if let Some(value) = self._member_key_id {
            params.push(("memberKey.id", value.to_string()));
        }
        for &field in ["alt", "parent", "memberKey.namespace", "memberKey.id"].iter() {
            if self._additional_params.contains_key(field) {
                dlg.finished(false);
                return Err(client::Error::FieldClash(field));
            }
        }
        for (name, value) in self._additional_params.iter() {
            params.push((&name, value.clone()));
        }

        params.push(("alt", "json".to_string()));

        let mut url = self.hub._base_url.clone() + "v1/{+parent}/memberships:lookup";
        if self._scopes.len() == 0 {
            self._scopes.insert(Scope::CloudIdentityGroupReadonly.as_ref().to_string(), ());
        }

        for &(find_this, param_name) in [("{+parent}", "parent")].iter() {
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
            for param_name in ["parent"].iter() {
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
            let authenticator = self.hub.auth.borrow_mut();
            let token = match authenticator.token(&self._scopes.keys().collect::<Vec<_>>()[..]).await {
                Ok(token) => token.clone(),
                Err(err) => {
                    match  dlg.token(&err) {
                        Some(token) => token,
                        None => {
                            dlg.finished(false);
                            return Err(client::Error::MissingToken(err))
                        }
                    }
                }
            };
            let mut req_result = {
                let mut client = &mut *self.hub.client.borrow_mut();
                dlg.pre_request();
                let mut req_builder = hyper::Request::builder().method(hyper::Method::GET).uri(url.clone().into_string())
                        .header(USER_AGENT, self.hub._user_agent.clone())
                        .header(AUTHORIZATION, format!("Bearer {}", token.as_str()))                        .body(hyper::body::Body::empty())                        .unwrap()
;

                client.borrow_mut().request(req_builder).await
                
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


    /// Required. [Resource name](https://cloud.google.com/apis/design/resource_names) of the
    /// Group to lookup Membership within.
    /// 
    /// Format: `groups/{group_id}`, where `group_id` is the unique ID assigned to
    /// the Group.
    ///
    /// Sets the *parent* path property to the given value.
    ///
    /// Even though the property as already been set when instantiating this call,
    /// we provide this method for API completeness.
    pub fn parent(mut self, new_value: &str) -> GroupMembershipLookupCall<'a, C> {
        self._parent = new_value.to_string();
        self
    }
    /// Namespaces provide isolation for IDs, so an ID only needs to be unique
    /// within its namespace.
    /// 
    /// Namespaces are currently only created as part of IdentitySource creation
    /// from Admin Console. A namespace `"identitysources/{identity_source_id}"` is
    /// created corresponding to every Identity Source `identity_source_id`.
    ///
    /// Sets the *member key.namespace* query property to the given value.
    pub fn member_key_namespace(mut self, new_value: &str) -> GroupMembershipLookupCall<'a, C> {
        self._member_key_namespace = Some(new_value.to_string());
        self
    }
    /// The ID of the entity within the given namespace. The ID must be unique
    /// within its namespace.
    ///
    /// Sets the *member key.id* query property to the given value.
    pub fn member_key_id(mut self, new_value: &str) -> GroupMembershipLookupCall<'a, C> {
        self._member_key_id = Some(new_value.to_string());
        self
    }
    /// The delegate implementation is consulted whenever there is an intermediate result, or if something goes wrong
    /// while executing the actual API request.
    /// 
    /// It should be used to handle progress information, and to implement a certain level of resilience.
    ///
    /// Sets the *delegate* property to the given value.
    pub fn delegate(mut self, new_value: &'a mut dyn client::Delegate) -> GroupMembershipLookupCall<'a, C> {
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
    pub fn param<T>(mut self, name: T, value: T) -> GroupMembershipLookupCall<'a, C>
                                                        where T: AsRef<str> {
        self._additional_params.insert(name.as_ref().to_string(), value.as_ref().to_string());
        self
    }

    /// Identifies the authorization scope for the method you are building.
    ///
    /// Use this method to actively specify which scope should be used, instead the default `Scope` variant
    /// `Scope::CloudIdentityGroupReadonly`.
    ///
    /// The `scope` will be added to a set of scopes. This is important as one can maintain access
    /// tokens for more than one scope.
    /// If `None` is specified, then all scopes will be removed and no default scope will be used either.
    /// In that case, you have to specify your API-key using the `key` parameter (see the `param()`
    /// function for details).
    ///
    /// Usually there is more than one suitable scope to authorize an operation, some of which may
    /// encompass more rights than others. For example, for listing resources, a *read-only* scope will be
    /// sufficient, a read-write scope will do as well.
    pub fn add_scope<T, S>(mut self, scope: T) -> GroupMembershipLookupCall<'a, C>
                                                        where T: Into<Option<S>>,
                                                              S: AsRef<str> {
        match scope.into() {
          Some(scope) => self._scopes.insert(scope.as_ref().to_string(), ()),
          None => None,
        };
        self
    }
}


/// Creates a Group.
///
/// A builder for the *create* method supported by a *group* resource.
/// It is not used directly, but through a `GroupMethods` instance.
///
/// # Example
///
/// Instantiate a resource method builder
///
/// ```test_harness,no_run
/// # extern crate hyper;
/// # extern crate hyper_rustls;
/// # extern crate yup_oauth2 as oauth2;
/// # extern crate google_cloudidentity1 as cloudidentity1;
/// use cloudidentity1::api::Group;
/// # #[test] fn egal() {
/// # use std::default::Default;
/// # use oauth2::{Authenticator, DefaultAuthenticatorDelegate, ApplicationSecret, MemoryStorage};
/// # use cloudidentity1::CloudIdentity;
/// 
/// # let secret: ApplicationSecret = Default::default();
/// # let auth = Authenticator::new(&secret, DefaultAuthenticatorDelegate,
/// #                               hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())),
/// #                               <MemoryStorage as Default>::default(), None);
/// # let mut hub = CloudIdentity::new(hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())), auth);
/// // As the method needs a request, you would usually fill it with the desired information
/// // into the respective structure. Some of the parts shown here might not be applicable !
/// // Values shown here are possibly random and not representative !
/// let mut req = Group::default();
/// 
/// // You can configure optional parameters by calling the respective setters at will, and
/// // execute the final call using `doit()`.
/// // Values shown here are possibly random and not representative !
/// let result = hub.groups().create(req)
///              .doit();
/// # }
/// ```
pub struct GroupCreateCall<'a, C>
    where C: 'a {

    hub: &'a CloudIdentity<C>,
    _request: Group,
    _delegate: Option<&'a mut dyn client::Delegate>,
    _additional_params: HashMap<String, String>,
    _scopes: BTreeMap<String, ()>
}

impl<'a, C> client::CallBuilder for GroupCreateCall<'a, C> {}

impl<'a, C> GroupCreateCall<'a, C> where C: BorrowMut<hyper::Client<hyper_rustls::HttpsConnector<hyper::client::connect::HttpConnector>, hyper::body::Body>> {


    /// Perform the operation you have build so far.
    pub async fn doit(mut self) -> client::Result<(hyper::Response<hyper::body::Body>, Operation)> {
        use std::io::{Read, Seek};
        use hyper::header::{CONTENT_TYPE, CONTENT_LENGTH, AUTHORIZATION, USER_AGENT, LOCATION};
        use client::ToParts;
        let mut dd = client::DefaultDelegate;
        let mut dlg: &mut dyn client::Delegate = match self._delegate {
            Some(d) => d,
            None => &mut dd
        };
        dlg.begin(client::MethodInfo { id: "cloudidentity.groups.create",
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

        let mut url = self.hub._base_url.clone() + "v1/groups";
        if self._scopes.len() == 0 {
            self._scopes.insert(Scope::CloudIdentityGroup.as_ref().to_string(), ());
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
            let authenticator = self.hub.auth.borrow_mut();
            let token = match authenticator.token(&self._scopes.keys().collect::<Vec<_>>()[..]).await {
                Ok(token) => token.clone(),
                Err(err) => {
                    match  dlg.token(&err) {
                        Some(token) => token,
                        None => {
                            dlg.finished(false);
                            return Err(client::Error::MissingToken(err))
                        }
                    }
                }
            };
            request_value_reader.seek(io::SeekFrom::Start(0)).unwrap();
            let mut req_result = {
                let mut client = &mut *self.hub.client.borrow_mut();
                dlg.pre_request();
                let mut req_builder = hyper::Request::builder().method(hyper::Method::POST).uri(url.clone().into_string())
                        .header(USER_AGENT, self.hub._user_agent.clone())
                        .header(AUTHORIZATION, format!("Bearer {}", token.as_str()))
                        .header(CONTENT_TYPE, format!("{}", json_mime_type))
                        .header(CONTENT_LENGTH, request_size as u64)
                        .body(hyper::body::Body::from(request_value_reader.get_ref().clone()))                        .unwrap()
;

                client.borrow_mut().request(req_builder).await
                
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
    pub fn request(mut self, new_value: Group) -> GroupCreateCall<'a, C> {
        self._request = new_value;
        self
    }
    /// The delegate implementation is consulted whenever there is an intermediate result, or if something goes wrong
    /// while executing the actual API request.
    /// 
    /// It should be used to handle progress information, and to implement a certain level of resilience.
    ///
    /// Sets the *delegate* property to the given value.
    pub fn delegate(mut self, new_value: &'a mut dyn client::Delegate) -> GroupCreateCall<'a, C> {
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
    pub fn param<T>(mut self, name: T, value: T) -> GroupCreateCall<'a, C>
                                                        where T: AsRef<str> {
        self._additional_params.insert(name.as_ref().to_string(), value.as_ref().to_string());
        self
    }

    /// Identifies the authorization scope for the method you are building.
    ///
    /// Use this method to actively specify which scope should be used, instead the default `Scope` variant
    /// `Scope::CloudIdentityGroup`.
    ///
    /// The `scope` will be added to a set of scopes. This is important as one can maintain access
    /// tokens for more than one scope.
    /// If `None` is specified, then all scopes will be removed and no default scope will be used either.
    /// In that case, you have to specify your API-key using the `key` parameter (see the `param()`
    /// function for details).
    ///
    /// Usually there is more than one suitable scope to authorize an operation, some of which may
    /// encompass more rights than others. For example, for listing resources, a *read-only* scope will be
    /// sufficient, a read-write scope will do as well.
    pub fn add_scope<T, S>(mut self, scope: T) -> GroupCreateCall<'a, C>
                                                        where T: Into<Option<S>>,
                                                              S: AsRef<str> {
        match scope.into() {
          Some(scope) => self._scopes.insert(scope.as_ref().to_string(), ()),
          None => None,
        };
        self
    }
}


/// Deletes a Group.
///
/// A builder for the *delete* method supported by a *group* resource.
/// It is not used directly, but through a `GroupMethods` instance.
///
/// # Example
///
/// Instantiate a resource method builder
///
/// ```test_harness,no_run
/// # extern crate hyper;
/// # extern crate hyper_rustls;
/// # extern crate yup_oauth2 as oauth2;
/// # extern crate google_cloudidentity1 as cloudidentity1;
/// # #[test] fn egal() {
/// # use std::default::Default;
/// # use oauth2::{Authenticator, DefaultAuthenticatorDelegate, ApplicationSecret, MemoryStorage};
/// # use cloudidentity1::CloudIdentity;
/// 
/// # let secret: ApplicationSecret = Default::default();
/// # let auth = Authenticator::new(&secret, DefaultAuthenticatorDelegate,
/// #                               hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())),
/// #                               <MemoryStorage as Default>::default(), None);
/// # let mut hub = CloudIdentity::new(hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())), auth);
/// // You can configure optional parameters by calling the respective setters at will, and
/// // execute the final call using `doit()`.
/// // Values shown here are possibly random and not representative !
/// let result = hub.groups().delete("name")
///              .doit();
/// # }
/// ```
pub struct GroupDeleteCall<'a, C>
    where C: 'a {

    hub: &'a CloudIdentity<C>,
    _name: String,
    _delegate: Option<&'a mut dyn client::Delegate>,
    _additional_params: HashMap<String, String>,
    _scopes: BTreeMap<String, ()>
}

impl<'a, C> client::CallBuilder for GroupDeleteCall<'a, C> {}

impl<'a, C> GroupDeleteCall<'a, C> where C: BorrowMut<hyper::Client<hyper_rustls::HttpsConnector<hyper::client::connect::HttpConnector>, hyper::body::Body>> {


    /// Perform the operation you have build so far.
    pub async fn doit(mut self) -> client::Result<(hyper::Response<hyper::body::Body>, Operation)> {
        use url::percent_encoding::{percent_encode, DEFAULT_ENCODE_SET};
        use std::io::{Read, Seek};
        use hyper::header::{CONTENT_TYPE, CONTENT_LENGTH, AUTHORIZATION, USER_AGENT, LOCATION};
        use client::ToParts;
        let mut dd = client::DefaultDelegate;
        let mut dlg: &mut dyn client::Delegate = match self._delegate {
            Some(d) => d,
            None => &mut dd
        };
        dlg.begin(client::MethodInfo { id: "cloudidentity.groups.delete",
                               http_method: hyper::Method::DELETE });
        let mut params: Vec<(&str, String)> = Vec::with_capacity(3 + self._additional_params.len());
        params.push(("name", self._name.to_string()));
        for &field in ["alt", "name"].iter() {
            if self._additional_params.contains_key(field) {
                dlg.finished(false);
                return Err(client::Error::FieldClash(field));
            }
        }
        for (name, value) in self._additional_params.iter() {
            params.push((&name, value.clone()));
        }

        params.push(("alt", "json".to_string()));

        let mut url = self.hub._base_url.clone() + "v1/{+name}";
        if self._scopes.len() == 0 {
            self._scopes.insert(Scope::CloudIdentityGroup.as_ref().to_string(), ());
        }

        for &(find_this, param_name) in [("{+name}", "name")].iter() {
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
            for param_name in ["name"].iter() {
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
            let authenticator = self.hub.auth.borrow_mut();
            let token = match authenticator.token(&self._scopes.keys().collect::<Vec<_>>()[..]).await {
                Ok(token) => token.clone(),
                Err(err) => {
                    match  dlg.token(&err) {
                        Some(token) => token,
                        None => {
                            dlg.finished(false);
                            return Err(client::Error::MissingToken(err))
                        }
                    }
                }
            };
            let mut req_result = {
                let mut client = &mut *self.hub.client.borrow_mut();
                dlg.pre_request();
                let mut req_builder = hyper::Request::builder().method(hyper::Method::DELETE).uri(url.clone().into_string())
                        .header(USER_AGENT, self.hub._user_agent.clone())
                        .header(AUTHORIZATION, format!("Bearer {}", token.as_str()))                        .body(hyper::body::Body::empty())                        .unwrap()
;

                client.borrow_mut().request(req_builder).await
                
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


    /// Required. [Resource name](https://cloud.google.com/apis/design/resource_names) of the
    /// Group in the format: `groups/{group_id}`, where `group_id` is the unique ID
    /// assigned to the Group.
    ///
    /// Sets the *name* path property to the given value.
    ///
    /// Even though the property as already been set when instantiating this call,
    /// we provide this method for API completeness.
    pub fn name(mut self, new_value: &str) -> GroupDeleteCall<'a, C> {
        self._name = new_value.to_string();
        self
    }
    /// The delegate implementation is consulted whenever there is an intermediate result, or if something goes wrong
    /// while executing the actual API request.
    /// 
    /// It should be used to handle progress information, and to implement a certain level of resilience.
    ///
    /// Sets the *delegate* property to the given value.
    pub fn delegate(mut self, new_value: &'a mut dyn client::Delegate) -> GroupDeleteCall<'a, C> {
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
    pub fn param<T>(mut self, name: T, value: T) -> GroupDeleteCall<'a, C>
                                                        where T: AsRef<str> {
        self._additional_params.insert(name.as_ref().to_string(), value.as_ref().to_string());
        self
    }

    /// Identifies the authorization scope for the method you are building.
    ///
    /// Use this method to actively specify which scope should be used, instead the default `Scope` variant
    /// `Scope::CloudIdentityGroup`.
    ///
    /// The `scope` will be added to a set of scopes. This is important as one can maintain access
    /// tokens for more than one scope.
    /// If `None` is specified, then all scopes will be removed and no default scope will be used either.
    /// In that case, you have to specify your API-key using the `key` parameter (see the `param()`
    /// function for details).
    ///
    /// Usually there is more than one suitable scope to authorize an operation, some of which may
    /// encompass more rights than others. For example, for listing resources, a *read-only* scope will be
    /// sufficient, a read-write scope will do as well.
    pub fn add_scope<T, S>(mut self, scope: T) -> GroupDeleteCall<'a, C>
                                                        where T: Into<Option<S>>,
                                                              S: AsRef<str> {
        match scope.into() {
          Some(scope) => self._scopes.insert(scope.as_ref().to_string(), ()),
          None => None,
        };
        self
    }
}


/// Retrieves a Group.
///
/// A builder for the *get* method supported by a *group* resource.
/// It is not used directly, but through a `GroupMethods` instance.
///
/// # Example
///
/// Instantiate a resource method builder
///
/// ```test_harness,no_run
/// # extern crate hyper;
/// # extern crate hyper_rustls;
/// # extern crate yup_oauth2 as oauth2;
/// # extern crate google_cloudidentity1 as cloudidentity1;
/// # #[test] fn egal() {
/// # use std::default::Default;
/// # use oauth2::{Authenticator, DefaultAuthenticatorDelegate, ApplicationSecret, MemoryStorage};
/// # use cloudidentity1::CloudIdentity;
/// 
/// # let secret: ApplicationSecret = Default::default();
/// # let auth = Authenticator::new(&secret, DefaultAuthenticatorDelegate,
/// #                               hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())),
/// #                               <MemoryStorage as Default>::default(), None);
/// # let mut hub = CloudIdentity::new(hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())), auth);
/// // You can configure optional parameters by calling the respective setters at will, and
/// // execute the final call using `doit()`.
/// // Values shown here are possibly random and not representative !
/// let result = hub.groups().get("name")
///              .doit();
/// # }
/// ```
pub struct GroupGetCall<'a, C>
    where C: 'a {

    hub: &'a CloudIdentity<C>,
    _name: String,
    _delegate: Option<&'a mut dyn client::Delegate>,
    _additional_params: HashMap<String, String>,
    _scopes: BTreeMap<String, ()>
}

impl<'a, C> client::CallBuilder for GroupGetCall<'a, C> {}

impl<'a, C> GroupGetCall<'a, C> where C: BorrowMut<hyper::Client<hyper_rustls::HttpsConnector<hyper::client::connect::HttpConnector>, hyper::body::Body>> {


    /// Perform the operation you have build so far.
    pub async fn doit(mut self) -> client::Result<(hyper::Response<hyper::body::Body>, Group)> {
        use url::percent_encoding::{percent_encode, DEFAULT_ENCODE_SET};
        use std::io::{Read, Seek};
        use hyper::header::{CONTENT_TYPE, CONTENT_LENGTH, AUTHORIZATION, USER_AGENT, LOCATION};
        use client::ToParts;
        let mut dd = client::DefaultDelegate;
        let mut dlg: &mut dyn client::Delegate = match self._delegate {
            Some(d) => d,
            None => &mut dd
        };
        dlg.begin(client::MethodInfo { id: "cloudidentity.groups.get",
                               http_method: hyper::Method::GET });
        let mut params: Vec<(&str, String)> = Vec::with_capacity(3 + self._additional_params.len());
        params.push(("name", self._name.to_string()));
        for &field in ["alt", "name"].iter() {
            if self._additional_params.contains_key(field) {
                dlg.finished(false);
                return Err(client::Error::FieldClash(field));
            }
        }
        for (name, value) in self._additional_params.iter() {
            params.push((&name, value.clone()));
        }

        params.push(("alt", "json".to_string()));

        let mut url = self.hub._base_url.clone() + "v1/{+name}";
        if self._scopes.len() == 0 {
            self._scopes.insert(Scope::CloudIdentityGroupReadonly.as_ref().to_string(), ());
        }

        for &(find_this, param_name) in [("{+name}", "name")].iter() {
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
            for param_name in ["name"].iter() {
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
            let authenticator = self.hub.auth.borrow_mut();
            let token = match authenticator.token(&self._scopes.keys().collect::<Vec<_>>()[..]).await {
                Ok(token) => token.clone(),
                Err(err) => {
                    match  dlg.token(&err) {
                        Some(token) => token,
                        None => {
                            dlg.finished(false);
                            return Err(client::Error::MissingToken(err))
                        }
                    }
                }
            };
            let mut req_result = {
                let mut client = &mut *self.hub.client.borrow_mut();
                dlg.pre_request();
                let mut req_builder = hyper::Request::builder().method(hyper::Method::GET).uri(url.clone().into_string())
                        .header(USER_AGENT, self.hub._user_agent.clone())
                        .header(AUTHORIZATION, format!("Bearer {}", token.as_str()))                        .body(hyper::body::Body::empty())                        .unwrap()
;

                client.borrow_mut().request(req_builder).await
                
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


    /// Required. [Resource name](https://cloud.google.com/apis/design/resource_names) of the
    /// Group in the format: `groups/{group_id}`, where `group_id` is the unique ID
    /// assigned to the Group.
    ///
    /// Sets the *name* path property to the given value.
    ///
    /// Even though the property as already been set when instantiating this call,
    /// we provide this method for API completeness.
    pub fn name(mut self, new_value: &str) -> GroupGetCall<'a, C> {
        self._name = new_value.to_string();
        self
    }
    /// The delegate implementation is consulted whenever there is an intermediate result, or if something goes wrong
    /// while executing the actual API request.
    /// 
    /// It should be used to handle progress information, and to implement a certain level of resilience.
    ///
    /// Sets the *delegate* property to the given value.
    pub fn delegate(mut self, new_value: &'a mut dyn client::Delegate) -> GroupGetCall<'a, C> {
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
    pub fn param<T>(mut self, name: T, value: T) -> GroupGetCall<'a, C>
                                                        where T: AsRef<str> {
        self._additional_params.insert(name.as_ref().to_string(), value.as_ref().to_string());
        self
    }

    /// Identifies the authorization scope for the method you are building.
    ///
    /// Use this method to actively specify which scope should be used, instead the default `Scope` variant
    /// `Scope::CloudIdentityGroupReadonly`.
    ///
    /// The `scope` will be added to a set of scopes. This is important as one can maintain access
    /// tokens for more than one scope.
    /// If `None` is specified, then all scopes will be removed and no default scope will be used either.
    /// In that case, you have to specify your API-key using the `key` parameter (see the `param()`
    /// function for details).
    ///
    /// Usually there is more than one suitable scope to authorize an operation, some of which may
    /// encompass more rights than others. For example, for listing resources, a *read-only* scope will be
    /// sufficient, a read-write scope will do as well.
    pub fn add_scope<T, S>(mut self, scope: T) -> GroupGetCall<'a, C>
                                                        where T: Into<Option<S>>,
                                                              S: AsRef<str> {
        match scope.into() {
          Some(scope) => self._scopes.insert(scope.as_ref().to_string(), ()),
          None => None,
        };
        self
    }
}


/// Lists groups within a customer or a domain.
///
/// A builder for the *list* method supported by a *group* resource.
/// It is not used directly, but through a `GroupMethods` instance.
///
/// # Example
///
/// Instantiate a resource method builder
///
/// ```test_harness,no_run
/// # extern crate hyper;
/// # extern crate hyper_rustls;
/// # extern crate yup_oauth2 as oauth2;
/// # extern crate google_cloudidentity1 as cloudidentity1;
/// # #[test] fn egal() {
/// # use std::default::Default;
/// # use oauth2::{Authenticator, DefaultAuthenticatorDelegate, ApplicationSecret, MemoryStorage};
/// # use cloudidentity1::CloudIdentity;
/// 
/// # let secret: ApplicationSecret = Default::default();
/// # let auth = Authenticator::new(&secret, DefaultAuthenticatorDelegate,
/// #                               hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())),
/// #                               <MemoryStorage as Default>::default(), None);
/// # let mut hub = CloudIdentity::new(hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())), auth);
/// // You can configure optional parameters by calling the respective setters at will, and
/// // execute the final call using `doit()`.
/// // Values shown here are possibly random and not representative !
/// let result = hub.groups().list()
///              .view("sed")
///              .parent("ut")
///              .page_token("gubergren")
///              .page_size(-16)
///              .doit();
/// # }
/// ```
pub struct GroupListCall<'a, C>
    where C: 'a {

    hub: &'a CloudIdentity<C>,
    _view: Option<String>,
    _parent: Option<String>,
    _page_token: Option<String>,
    _page_size: Option<i32>,
    _delegate: Option<&'a mut dyn client::Delegate>,
    _additional_params: HashMap<String, String>,
    _scopes: BTreeMap<String, ()>
}

impl<'a, C> client::CallBuilder for GroupListCall<'a, C> {}

impl<'a, C> GroupListCall<'a, C> where C: BorrowMut<hyper::Client<hyper_rustls::HttpsConnector<hyper::client::connect::HttpConnector>, hyper::body::Body>> {


    /// Perform the operation you have build so far.
    pub async fn doit(mut self) -> client::Result<(hyper::Response<hyper::body::Body>, ListGroupsResponse)> {
        use std::io::{Read, Seek};
        use hyper::header::{CONTENT_TYPE, CONTENT_LENGTH, AUTHORIZATION, USER_AGENT, LOCATION};
        use client::ToParts;
        let mut dd = client::DefaultDelegate;
        let mut dlg: &mut dyn client::Delegate = match self._delegate {
            Some(d) => d,
            None => &mut dd
        };
        dlg.begin(client::MethodInfo { id: "cloudidentity.groups.list",
                               http_method: hyper::Method::GET });
        let mut params: Vec<(&str, String)> = Vec::with_capacity(6 + self._additional_params.len());
        if let Some(value) = self._view {
            params.push(("view", value.to_string()));
        }
        if let Some(value) = self._parent {
            params.push(("parent", value.to_string()));
        }
        if let Some(value) = self._page_token {
            params.push(("pageToken", value.to_string()));
        }
        if let Some(value) = self._page_size {
            params.push(("pageSize", value.to_string()));
        }
        for &field in ["alt", "view", "parent", "pageToken", "pageSize"].iter() {
            if self._additional_params.contains_key(field) {
                dlg.finished(false);
                return Err(client::Error::FieldClash(field));
            }
        }
        for (name, value) in self._additional_params.iter() {
            params.push((&name, value.clone()));
        }

        params.push(("alt", "json".to_string()));

        let mut url = self.hub._base_url.clone() + "v1/groups";
        if self._scopes.len() == 0 {
            self._scopes.insert(Scope::CloudIdentityGroupReadonly.as_ref().to_string(), ());
        }


        let url = url::Url::parse_with_params(&url, params).unwrap();



        loop {
            let authenticator = self.hub.auth.borrow_mut();
            let token = match authenticator.token(&self._scopes.keys().collect::<Vec<_>>()[..]).await {
                Ok(token) => token.clone(),
                Err(err) => {
                    match  dlg.token(&err) {
                        Some(token) => token,
                        None => {
                            dlg.finished(false);
                            return Err(client::Error::MissingToken(err))
                        }
                    }
                }
            };
            let mut req_result = {
                let mut client = &mut *self.hub.client.borrow_mut();
                dlg.pre_request();
                let mut req_builder = hyper::Request::builder().method(hyper::Method::GET).uri(url.clone().into_string())
                        .header(USER_AGENT, self.hub._user_agent.clone())
                        .header(AUTHORIZATION, format!("Bearer {}", token.as_str()))                        .body(hyper::body::Body::empty())                        .unwrap()
;

                client.borrow_mut().request(req_builder).await
                
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


    /// Group resource view to be returned. Defaults to [View.BASIC]().
    ///
    /// Sets the *view* query property to the given value.
    pub fn view(mut self, new_value: &str) -> GroupListCall<'a, C> {
        self._view = Some(new_value.to_string());
        self
    }
    /// Required. Customer ID to list all groups from.
    ///
    /// Sets the *parent* query property to the given value.
    pub fn parent(mut self, new_value: &str) -> GroupListCall<'a, C> {
        self._parent = Some(new_value.to_string());
        self
    }
    /// The next_page_token value returned from a previous list request, if any.
    ///
    /// Sets the *page token* query property to the given value.
    pub fn page_token(mut self, new_value: &str) -> GroupListCall<'a, C> {
        self._page_token = Some(new_value.to_string());
        self
    }
    /// The default page size is 200 (max 1000) for the BASIC view, and 50
    /// (max 500) for the FULL view.
    ///
    /// Sets the *page size* query property to the given value.
    pub fn page_size(mut self, new_value: i32) -> GroupListCall<'a, C> {
        self._page_size = Some(new_value);
        self
    }
    /// The delegate implementation is consulted whenever there is an intermediate result, or if something goes wrong
    /// while executing the actual API request.
    /// 
    /// It should be used to handle progress information, and to implement a certain level of resilience.
    ///
    /// Sets the *delegate* property to the given value.
    pub fn delegate(mut self, new_value: &'a mut dyn client::Delegate) -> GroupListCall<'a, C> {
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
    pub fn param<T>(mut self, name: T, value: T) -> GroupListCall<'a, C>
                                                        where T: AsRef<str> {
        self._additional_params.insert(name.as_ref().to_string(), value.as_ref().to_string());
        self
    }

    /// Identifies the authorization scope for the method you are building.
    ///
    /// Use this method to actively specify which scope should be used, instead the default `Scope` variant
    /// `Scope::CloudIdentityGroupReadonly`.
    ///
    /// The `scope` will be added to a set of scopes. This is important as one can maintain access
    /// tokens for more than one scope.
    /// If `None` is specified, then all scopes will be removed and no default scope will be used either.
    /// In that case, you have to specify your API-key using the `key` parameter (see the `param()`
    /// function for details).
    ///
    /// Usually there is more than one suitable scope to authorize an operation, some of which may
    /// encompass more rights than others. For example, for listing resources, a *read-only* scope will be
    /// sufficient, a read-write scope will do as well.
    pub fn add_scope<T, S>(mut self, scope: T) -> GroupListCall<'a, C>
                                                        where T: Into<Option<S>>,
                                                              S: AsRef<str> {
        match scope.into() {
          Some(scope) => self._scopes.insert(scope.as_ref().to_string(), ()),
          None => None,
        };
        self
    }
}


/// Looks up [resource
/// name](https://cloud.google.com/apis/design/resource_names) of a Group by
/// its EntityKey.
///
/// A builder for the *lookup* method supported by a *group* resource.
/// It is not used directly, but through a `GroupMethods` instance.
///
/// # Example
///
/// Instantiate a resource method builder
///
/// ```test_harness,no_run
/// # extern crate hyper;
/// # extern crate hyper_rustls;
/// # extern crate yup_oauth2 as oauth2;
/// # extern crate google_cloudidentity1 as cloudidentity1;
/// # #[test] fn egal() {
/// # use std::default::Default;
/// # use oauth2::{Authenticator, DefaultAuthenticatorDelegate, ApplicationSecret, MemoryStorage};
/// # use cloudidentity1::CloudIdentity;
/// 
/// # let secret: ApplicationSecret = Default::default();
/// # let auth = Authenticator::new(&secret, DefaultAuthenticatorDelegate,
/// #                               hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())),
/// #                               <MemoryStorage as Default>::default(), None);
/// # let mut hub = CloudIdentity::new(hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())), auth);
/// // You can configure optional parameters by calling the respective setters at will, and
/// // execute the final call using `doit()`.
/// // Values shown here are possibly random and not representative !
/// let result = hub.groups().lookup()
///              .group_key_namespace("est")
///              .group_key_id("ipsum")
///              .doit();
/// # }
/// ```
pub struct GroupLookupCall<'a, C>
    where C: 'a {

    hub: &'a CloudIdentity<C>,
    _group_key_namespace: Option<String>,
    _group_key_id: Option<String>,
    _delegate: Option<&'a mut dyn client::Delegate>,
    _additional_params: HashMap<String, String>,
    _scopes: BTreeMap<String, ()>
}

impl<'a, C> client::CallBuilder for GroupLookupCall<'a, C> {}

impl<'a, C> GroupLookupCall<'a, C> where C: BorrowMut<hyper::Client<hyper_rustls::HttpsConnector<hyper::client::connect::HttpConnector>, hyper::body::Body>> {


    /// Perform the operation you have build so far.
    pub async fn doit(mut self) -> client::Result<(hyper::Response<hyper::body::Body>, LookupGroupNameResponse)> {
        use std::io::{Read, Seek};
        use hyper::header::{CONTENT_TYPE, CONTENT_LENGTH, AUTHORIZATION, USER_AGENT, LOCATION};
        use client::ToParts;
        let mut dd = client::DefaultDelegate;
        let mut dlg: &mut dyn client::Delegate = match self._delegate {
            Some(d) => d,
            None => &mut dd
        };
        dlg.begin(client::MethodInfo { id: "cloudidentity.groups.lookup",
                               http_method: hyper::Method::GET });
        let mut params: Vec<(&str, String)> = Vec::with_capacity(4 + self._additional_params.len());
        if let Some(value) = self._group_key_namespace {
            params.push(("groupKey.namespace", value.to_string()));
        }
        if let Some(value) = self._group_key_id {
            params.push(("groupKey.id", value.to_string()));
        }
        for &field in ["alt", "groupKey.namespace", "groupKey.id"].iter() {
            if self._additional_params.contains_key(field) {
                dlg.finished(false);
                return Err(client::Error::FieldClash(field));
            }
        }
        for (name, value) in self._additional_params.iter() {
            params.push((&name, value.clone()));
        }

        params.push(("alt", "json".to_string()));

        let mut url = self.hub._base_url.clone() + "v1/groups:lookup";
        if self._scopes.len() == 0 {
            self._scopes.insert(Scope::CloudIdentityGroupReadonly.as_ref().to_string(), ());
        }


        let url = url::Url::parse_with_params(&url, params).unwrap();



        loop {
            let authenticator = self.hub.auth.borrow_mut();
            let token = match authenticator.token(&self._scopes.keys().collect::<Vec<_>>()[..]).await {
                Ok(token) => token.clone(),
                Err(err) => {
                    match  dlg.token(&err) {
                        Some(token) => token,
                        None => {
                            dlg.finished(false);
                            return Err(client::Error::MissingToken(err))
                        }
                    }
                }
            };
            let mut req_result = {
                let mut client = &mut *self.hub.client.borrow_mut();
                dlg.pre_request();
                let mut req_builder = hyper::Request::builder().method(hyper::Method::GET).uri(url.clone().into_string())
                        .header(USER_AGENT, self.hub._user_agent.clone())
                        .header(AUTHORIZATION, format!("Bearer {}", token.as_str()))                        .body(hyper::body::Body::empty())                        .unwrap()
;

                client.borrow_mut().request(req_builder).await
                
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


    /// Namespaces provide isolation for IDs, so an ID only needs to be unique
    /// within its namespace.
    /// 
    /// Namespaces are currently only created as part of IdentitySource creation
    /// from Admin Console. A namespace `"identitysources/{identity_source_id}"` is
    /// created corresponding to every Identity Source `identity_source_id`.
    ///
    /// Sets the *group key.namespace* query property to the given value.
    pub fn group_key_namespace(mut self, new_value: &str) -> GroupLookupCall<'a, C> {
        self._group_key_namespace = Some(new_value.to_string());
        self
    }
    /// The ID of the entity within the given namespace. The ID must be unique
    /// within its namespace.
    ///
    /// Sets the *group key.id* query property to the given value.
    pub fn group_key_id(mut self, new_value: &str) -> GroupLookupCall<'a, C> {
        self._group_key_id = Some(new_value.to_string());
        self
    }
    /// The delegate implementation is consulted whenever there is an intermediate result, or if something goes wrong
    /// while executing the actual API request.
    /// 
    /// It should be used to handle progress information, and to implement a certain level of resilience.
    ///
    /// Sets the *delegate* property to the given value.
    pub fn delegate(mut self, new_value: &'a mut dyn client::Delegate) -> GroupLookupCall<'a, C> {
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
    pub fn param<T>(mut self, name: T, value: T) -> GroupLookupCall<'a, C>
                                                        where T: AsRef<str> {
        self._additional_params.insert(name.as_ref().to_string(), value.as_ref().to_string());
        self
    }

    /// Identifies the authorization scope for the method you are building.
    ///
    /// Use this method to actively specify which scope should be used, instead the default `Scope` variant
    /// `Scope::CloudIdentityGroupReadonly`.
    ///
    /// The `scope` will be added to a set of scopes. This is important as one can maintain access
    /// tokens for more than one scope.
    /// If `None` is specified, then all scopes will be removed and no default scope will be used either.
    /// In that case, you have to specify your API-key using the `key` parameter (see the `param()`
    /// function for details).
    ///
    /// Usually there is more than one suitable scope to authorize an operation, some of which may
    /// encompass more rights than others. For example, for listing resources, a *read-only* scope will be
    /// sufficient, a read-write scope will do as well.
    pub fn add_scope<T, S>(mut self, scope: T) -> GroupLookupCall<'a, C>
                                                        where T: Into<Option<S>>,
                                                              S: AsRef<str> {
        match scope.into() {
          Some(scope) => self._scopes.insert(scope.as_ref().to_string(), ()),
          None => None,
        };
        self
    }
}


/// Updates a Group.
///
/// A builder for the *patch* method supported by a *group* resource.
/// It is not used directly, but through a `GroupMethods` instance.
///
/// # Example
///
/// Instantiate a resource method builder
///
/// ```test_harness,no_run
/// # extern crate hyper;
/// # extern crate hyper_rustls;
/// # extern crate yup_oauth2 as oauth2;
/// # extern crate google_cloudidentity1 as cloudidentity1;
/// use cloudidentity1::api::Group;
/// # #[test] fn egal() {
/// # use std::default::Default;
/// # use oauth2::{Authenticator, DefaultAuthenticatorDelegate, ApplicationSecret, MemoryStorage};
/// # use cloudidentity1::CloudIdentity;
/// 
/// # let secret: ApplicationSecret = Default::default();
/// # let auth = Authenticator::new(&secret, DefaultAuthenticatorDelegate,
/// #                               hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())),
/// #                               <MemoryStorage as Default>::default(), None);
/// # let mut hub = CloudIdentity::new(hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())), auth);
/// // As the method needs a request, you would usually fill it with the desired information
/// // into the respective structure. Some of the parts shown here might not be applicable !
/// // Values shown here are possibly random and not representative !
/// let mut req = Group::default();
/// 
/// // You can configure optional parameters by calling the respective setters at will, and
/// // execute the final call using `doit()`.
/// // Values shown here are possibly random and not representative !
/// let result = hub.groups().patch(req, "name")
///              .update_mask("est")
///              .doit();
/// # }
/// ```
pub struct GroupPatchCall<'a, C>
    where C: 'a {

    hub: &'a CloudIdentity<C>,
    _request: Group,
    _name: String,
    _update_mask: Option<String>,
    _delegate: Option<&'a mut dyn client::Delegate>,
    _additional_params: HashMap<String, String>,
    _scopes: BTreeMap<String, ()>
}

impl<'a, C> client::CallBuilder for GroupPatchCall<'a, C> {}

impl<'a, C> GroupPatchCall<'a, C> where C: BorrowMut<hyper::Client<hyper_rustls::HttpsConnector<hyper::client::connect::HttpConnector>, hyper::body::Body>> {


    /// Perform the operation you have build so far.
    pub async fn doit(mut self) -> client::Result<(hyper::Response<hyper::body::Body>, Operation)> {
        use url::percent_encoding::{percent_encode, DEFAULT_ENCODE_SET};
        use std::io::{Read, Seek};
        use hyper::header::{CONTENT_TYPE, CONTENT_LENGTH, AUTHORIZATION, USER_AGENT, LOCATION};
        use client::ToParts;
        let mut dd = client::DefaultDelegate;
        let mut dlg: &mut dyn client::Delegate = match self._delegate {
            Some(d) => d,
            None => &mut dd
        };
        dlg.begin(client::MethodInfo { id: "cloudidentity.groups.patch",
                               http_method: hyper::Method::PATCH });
        let mut params: Vec<(&str, String)> = Vec::with_capacity(5 + self._additional_params.len());
        params.push(("name", self._name.to_string()));
        if let Some(value) = self._update_mask {
            params.push(("updateMask", value.to_string()));
        }
        for &field in ["alt", "name", "updateMask"].iter() {
            if self._additional_params.contains_key(field) {
                dlg.finished(false);
                return Err(client::Error::FieldClash(field));
            }
        }
        for (name, value) in self._additional_params.iter() {
            params.push((&name, value.clone()));
        }

        params.push(("alt", "json".to_string()));

        let mut url = self.hub._base_url.clone() + "v1/{+name}";
        if self._scopes.len() == 0 {
            self._scopes.insert(Scope::CloudIdentityGroup.as_ref().to_string(), ());
        }

        for &(find_this, param_name) in [("{+name}", "name")].iter() {
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
            for param_name in ["name"].iter() {
                if let Some(index) = params.iter().position(|t| &t.0 == param_name) {
                    indices_for_removal.push(index);
                }
            }
            for &index in indices_for_removal.iter() {
                params.remove(index);
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
            let authenticator = self.hub.auth.borrow_mut();
            let token = match authenticator.token(&self._scopes.keys().collect::<Vec<_>>()[..]).await {
                Ok(token) => token.clone(),
                Err(err) => {
                    match  dlg.token(&err) {
                        Some(token) => token,
                        None => {
                            dlg.finished(false);
                            return Err(client::Error::MissingToken(err))
                        }
                    }
                }
            };
            request_value_reader.seek(io::SeekFrom::Start(0)).unwrap();
            let mut req_result = {
                let mut client = &mut *self.hub.client.borrow_mut();
                dlg.pre_request();
                let mut req_builder = hyper::Request::builder().method(hyper::Method::PATCH).uri(url.clone().into_string())
                        .header(USER_AGENT, self.hub._user_agent.clone())
                        .header(AUTHORIZATION, format!("Bearer {}", token.as_str()))
                        .header(CONTENT_TYPE, format!("{}", json_mime_type))
                        .header(CONTENT_LENGTH, request_size as u64)
                        .body(hyper::body::Body::from(request_value_reader.get_ref().clone()))                        .unwrap()
;

                client.borrow_mut().request(req_builder).await
                
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
    pub fn request(mut self, new_value: Group) -> GroupPatchCall<'a, C> {
        self._request = new_value;
        self
    }
    /// Output only. [Resource name](https://cloud.google.com/apis/design/resource_names) of the
    /// Group in the format: `groups/{group_id}`, where group_id is the unique ID
    /// assigned to the Group.
    /// 
    /// Must be left blank while creating a Group.
    ///
    /// Sets the *name* path property to the given value.
    ///
    /// Even though the property as already been set when instantiating this call,
    /// we provide this method for API completeness.
    pub fn name(mut self, new_value: &str) -> GroupPatchCall<'a, C> {
        self._name = new_value.to_string();
        self
    }
    /// Required. Editable fields: `display_name`, `description`
    ///
    /// Sets the *update mask* query property to the given value.
    pub fn update_mask(mut self, new_value: &str) -> GroupPatchCall<'a, C> {
        self._update_mask = Some(new_value.to_string());
        self
    }
    /// The delegate implementation is consulted whenever there is an intermediate result, or if something goes wrong
    /// while executing the actual API request.
    /// 
    /// It should be used to handle progress information, and to implement a certain level of resilience.
    ///
    /// Sets the *delegate* property to the given value.
    pub fn delegate(mut self, new_value: &'a mut dyn client::Delegate) -> GroupPatchCall<'a, C> {
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
    pub fn param<T>(mut self, name: T, value: T) -> GroupPatchCall<'a, C>
                                                        where T: AsRef<str> {
        self._additional_params.insert(name.as_ref().to_string(), value.as_ref().to_string());
        self
    }

    /// Identifies the authorization scope for the method you are building.
    ///
    /// Use this method to actively specify which scope should be used, instead the default `Scope` variant
    /// `Scope::CloudIdentityGroup`.
    ///
    /// The `scope` will be added to a set of scopes. This is important as one can maintain access
    /// tokens for more than one scope.
    /// If `None` is specified, then all scopes will be removed and no default scope will be used either.
    /// In that case, you have to specify your API-key using the `key` parameter (see the `param()`
    /// function for details).
    ///
    /// Usually there is more than one suitable scope to authorize an operation, some of which may
    /// encompass more rights than others. For example, for listing resources, a *read-only* scope will be
    /// sufficient, a read-write scope will do as well.
    pub fn add_scope<T, S>(mut self, scope: T) -> GroupPatchCall<'a, C>
                                                        where T: Into<Option<S>>,
                                                              S: AsRef<str> {
        match scope.into() {
          Some(scope) => self._scopes.insert(scope.as_ref().to_string(), ()),
          None => None,
        };
        self
    }
}


/// Searches for Groups.
///
/// A builder for the *search* method supported by a *group* resource.
/// It is not used directly, but through a `GroupMethods` instance.
///
/// # Example
///
/// Instantiate a resource method builder
///
/// ```test_harness,no_run
/// # extern crate hyper;
/// # extern crate hyper_rustls;
/// # extern crate yup_oauth2 as oauth2;
/// # extern crate google_cloudidentity1 as cloudidentity1;
/// # #[test] fn egal() {
/// # use std::default::Default;
/// # use oauth2::{Authenticator, DefaultAuthenticatorDelegate, ApplicationSecret, MemoryStorage};
/// # use cloudidentity1::CloudIdentity;
/// 
/// # let secret: ApplicationSecret = Default::default();
/// # let auth = Authenticator::new(&secret, DefaultAuthenticatorDelegate,
/// #                               hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())),
/// #                               <MemoryStorage as Default>::default(), None);
/// # let mut hub = CloudIdentity::new(hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())), auth);
/// // You can configure optional parameters by calling the respective setters at will, and
/// // execute the final call using `doit()`.
/// // Values shown here are possibly random and not representative !
/// let result = hub.groups().search()
///              .view("gubergren")
///              .query("ea")
///              .page_token("dolor")
///              .page_size(-56)
///              .doit();
/// # }
/// ```
pub struct GroupSearchCall<'a, C>
    where C: 'a {

    hub: &'a CloudIdentity<C>,
    _view: Option<String>,
    _query: Option<String>,
    _page_token: Option<String>,
    _page_size: Option<i32>,
    _delegate: Option<&'a mut dyn client::Delegate>,
    _additional_params: HashMap<String, String>,
    _scopes: BTreeMap<String, ()>
}

impl<'a, C> client::CallBuilder for GroupSearchCall<'a, C> {}

impl<'a, C> GroupSearchCall<'a, C> where C: BorrowMut<hyper::Client<hyper_rustls::HttpsConnector<hyper::client::connect::HttpConnector>, hyper::body::Body>> {


    /// Perform the operation you have build so far.
    pub async fn doit(mut self) -> client::Result<(hyper::Response<hyper::body::Body>, SearchGroupsResponse)> {
        use std::io::{Read, Seek};
        use hyper::header::{CONTENT_TYPE, CONTENT_LENGTH, AUTHORIZATION, USER_AGENT, LOCATION};
        use client::ToParts;
        let mut dd = client::DefaultDelegate;
        let mut dlg: &mut dyn client::Delegate = match self._delegate {
            Some(d) => d,
            None => &mut dd
        };
        dlg.begin(client::MethodInfo { id: "cloudidentity.groups.search",
                               http_method: hyper::Method::GET });
        let mut params: Vec<(&str, String)> = Vec::with_capacity(6 + self._additional_params.len());
        if let Some(value) = self._view {
            params.push(("view", value.to_string()));
        }
        if let Some(value) = self._query {
            params.push(("query", value.to_string()));
        }
        if let Some(value) = self._page_token {
            params.push(("pageToken", value.to_string()));
        }
        if let Some(value) = self._page_size {
            params.push(("pageSize", value.to_string()));
        }
        for &field in ["alt", "view", "query", "pageToken", "pageSize"].iter() {
            if self._additional_params.contains_key(field) {
                dlg.finished(false);
                return Err(client::Error::FieldClash(field));
            }
        }
        for (name, value) in self._additional_params.iter() {
            params.push((&name, value.clone()));
        }

        params.push(("alt", "json".to_string()));

        let mut url = self.hub._base_url.clone() + "v1/groups:search";
        if self._scopes.len() == 0 {
            self._scopes.insert(Scope::CloudIdentityGroupReadonly.as_ref().to_string(), ());
        }


        let url = url::Url::parse_with_params(&url, params).unwrap();



        loop {
            let authenticator = self.hub.auth.borrow_mut();
            let token = match authenticator.token(&self._scopes.keys().collect::<Vec<_>>()[..]).await {
                Ok(token) => token.clone(),
                Err(err) => {
                    match  dlg.token(&err) {
                        Some(token) => token,
                        None => {
                            dlg.finished(false);
                            return Err(client::Error::MissingToken(err))
                        }
                    }
                }
            };
            let mut req_result = {
                let mut client = &mut *self.hub.client.borrow_mut();
                dlg.pre_request();
                let mut req_builder = hyper::Request::builder().method(hyper::Method::GET).uri(url.clone().into_string())
                        .header(USER_AGENT, self.hub._user_agent.clone())
                        .header(AUTHORIZATION, format!("Bearer {}", token.as_str()))                        .body(hyper::body::Body::empty())                        .unwrap()
;

                client.borrow_mut().request(req_builder).await
                
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


    /// Group resource view to be returned. Defaults to [View.BASIC]().
    ///
    /// Sets the *view* query property to the given value.
    pub fn view(mut self, new_value: &str) -> GroupSearchCall<'a, C> {
        self._view = Some(new_value.to_string());
        self
    }
    /// Required. `Required`. Query string for performing search on groups. Users can search
    /// on parent and label attributes of groups.
    /// EXACT match ('==') is supported on parent, and CONTAINS match ('in') is
    /// supported on labels.
    ///
    /// Sets the *query* query property to the given value.
    pub fn query(mut self, new_value: &str) -> GroupSearchCall<'a, C> {
        self._query = Some(new_value.to_string());
        self
    }
    /// The next_page_token value returned from a previous search request, if any.
    ///
    /// Sets the *page token* query property to the given value.
    pub fn page_token(mut self, new_value: &str) -> GroupSearchCall<'a, C> {
        self._page_token = Some(new_value.to_string());
        self
    }
    /// The default page size is 200 (max 1000) for the BASIC view, and 50
    /// (max 500) for the FULL view.
    ///
    /// Sets the *page size* query property to the given value.
    pub fn page_size(mut self, new_value: i32) -> GroupSearchCall<'a, C> {
        self._page_size = Some(new_value);
        self
    }
    /// The delegate implementation is consulted whenever there is an intermediate result, or if something goes wrong
    /// while executing the actual API request.
    /// 
    /// It should be used to handle progress information, and to implement a certain level of resilience.
    ///
    /// Sets the *delegate* property to the given value.
    pub fn delegate(mut self, new_value: &'a mut dyn client::Delegate) -> GroupSearchCall<'a, C> {
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
    pub fn param<T>(mut self, name: T, value: T) -> GroupSearchCall<'a, C>
                                                        where T: AsRef<str> {
        self._additional_params.insert(name.as_ref().to_string(), value.as_ref().to_string());
        self
    }

    /// Identifies the authorization scope for the method you are building.
    ///
    /// Use this method to actively specify which scope should be used, instead the default `Scope` variant
    /// `Scope::CloudIdentityGroupReadonly`.
    ///
    /// The `scope` will be added to a set of scopes. This is important as one can maintain access
    /// tokens for more than one scope.
    /// If `None` is specified, then all scopes will be removed and no default scope will be used either.
    /// In that case, you have to specify your API-key using the `key` parameter (see the `param()`
    /// function for details).
    ///
    /// Usually there is more than one suitable scope to authorize an operation, some of which may
    /// encompass more rights than others. For example, for listing resources, a *read-only* scope will be
    /// sufficient, a read-write scope will do as well.
    pub fn add_scope<T, S>(mut self, scope: T) -> GroupSearchCall<'a, C>
                                                        where T: Into<Option<S>>,
                                                              S: AsRef<str> {
        match scope.into() {
          Some(scope) => self._scopes.insert(scope.as_ref().to_string(), ()),
          None => None,
        };
        self
    }
}


