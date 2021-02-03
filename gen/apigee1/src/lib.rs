// DO NOT EDIT !
// This file was generated automatically from 'src/mako/api/lib.rs.mako'
// DO NOT EDIT !

//! This documentation was generated from *Apigee* crate version *1.0.14+20200625*, where *20200625* is the exact revision of the *apigee:v1* schema built by the [mako](http://www.makotemplates.org/) code generator *v1.0.14*.
//! 
//! Everything else about the *Apigee* *v1* API can be found at the
//! [official documentation site](https://cloud.google.com/apigee-api-management/).
//! The original source code is [on github](https://github.com/Byron/google-apis-rs/tree/master/gen/apigee1).
//! # Features
//! 
//! Handle the following *Resources* with ease from the central [hub](Apigee) ... 
//! 
//! * hybrid
//!  * [*issuers list*](api::HybridIssuerListCall)
//! * organizations
//!  * [*apiproducts attributes*](api::OrganizationApiproductAttributeCall), [*apiproducts attributes delete*](api::OrganizationApiproductAttributeDeleteCall), [*apiproducts attributes get*](api::OrganizationApiproductAttributeGetCall), [*apiproducts attributes list*](api::OrganizationApiproductAttributeListCall), [*apiproducts attributes update api product attribute*](api::OrganizationApiproductAttributeUpdateApiProductAttributeCall), [*apiproducts create*](api::OrganizationApiproductCreateCall), [*apiproducts delete*](api::OrganizationApiproductDeleteCall), [*apiproducts get*](api::OrganizationApiproductGetCall), [*apiproducts list*](api::OrganizationApiproductListCall), [*apiproducts update*](api::OrganizationApiproductUpdateCall), [*apis create*](api::OrganizationApiCreateCall), [*apis delete*](api::OrganizationApiDeleteCall), [*apis deployments list*](api::OrganizationApiDeploymentListCall), [*apis get*](api::OrganizationApiGetCall), [*apis keyvaluemaps create*](api::OrganizationApiKeyvaluemapCreateCall), [*apis keyvaluemaps delete*](api::OrganizationApiKeyvaluemapDeleteCall), [*apis list*](api::OrganizationApiListCall), [*apis revisions delete*](api::OrganizationApiRevisionDeleteCall), [*apis revisions deployments list*](api::OrganizationApiRevisionDeploymentListCall), [*apis revisions get*](api::OrganizationApiRevisionGetCall), [*apis revisions update api proxy revision*](api::OrganizationApiRevisionUpdateApiProxyRevisionCall), [*apps get*](api::OrganizationAppGetCall), [*apps list*](api::OrganizationAppListCall), [*create*](api::OrganizationCreateCall), [*deployments list*](api::OrganizationDeploymentListCall), [*developers apps attributes*](api::OrganizationDeveloperAppAttributeCall), [*developers apps attributes delete*](api::OrganizationDeveloperAppAttributeDeleteCall), [*developers apps attributes get*](api::OrganizationDeveloperAppAttributeGetCall), [*developers apps attributes list*](api::OrganizationDeveloperAppAttributeListCall), [*developers apps attributes update developer app attribute*](api::OrganizationDeveloperAppAttributeUpdateDeveloperAppAttributeCall), [*developers apps create*](api::OrganizationDeveloperAppCreateCall), [*developers apps delete*](api::OrganizationDeveloperAppDeleteCall), [*developers apps generate key pair or update developer app status*](api::OrganizationDeveloperAppGenerateKeyPairOrUpdateDeveloperAppStatuCall), [*developers apps get*](api::OrganizationDeveloperAppGetCall), [*developers apps keys apiproducts delete*](api::OrganizationDeveloperAppKeyApiproductDeleteCall), [*developers apps keys apiproducts update developer app key api product*](api::OrganizationDeveloperAppKeyApiproductUpdateDeveloperAppKeyApiProductCall), [*developers apps keys create*](api::OrganizationDeveloperAppKeyCreateCall), [*developers apps keys create create*](api::OrganizationDeveloperAppKeyCreateCreateCall), [*developers apps keys delete*](api::OrganizationDeveloperAppKeyDeleteCall), [*developers apps keys get*](api::OrganizationDeveloperAppKeyGetCall), [*developers apps keys replace developer app key*](api::OrganizationDeveloperAppKeyReplaceDeveloperAppKeyCall), [*developers apps keys update developer app key*](api::OrganizationDeveloperAppKeyUpdateDeveloperAppKeyCall), [*developers apps list*](api::OrganizationDeveloperAppListCall), [*developers apps update*](api::OrganizationDeveloperAppUpdateCall), [*developers attributes*](api::OrganizationDeveloperAttributeCall), [*developers attributes delete*](api::OrganizationDeveloperAttributeDeleteCall), [*developers attributes get*](api::OrganizationDeveloperAttributeGetCall), [*developers attributes list*](api::OrganizationDeveloperAttributeListCall), [*developers attributes update developer attribute*](api::OrganizationDeveloperAttributeUpdateDeveloperAttributeCall), [*developers create*](api::OrganizationDeveloperCreateCall), [*developers delete*](api::OrganizationDeveloperDeleteCall), [*developers get*](api::OrganizationDeveloperGetCall), [*developers list*](api::OrganizationDeveloperListCall), [*developers set developer status*](api::OrganizationDeveloperSetDeveloperStatuCall), [*developers update*](api::OrganizationDeveloperUpdateCall), [*environments analytics admin get schemav2*](api::OrganizationEnvironmentAnalyticAdminGetSchemav2Call), [*environments apis deployments list*](api::OrganizationEnvironmentApiDeploymentListCall), [*environments apis revisions debugsessions create*](api::OrganizationEnvironmentApiRevisionDebugsessionCreateCall), [*environments apis revisions debugsessions data get*](api::OrganizationEnvironmentApiRevisionDebugsessionDataGetCall), [*environments apis revisions debugsessions delete data*](api::OrganizationEnvironmentApiRevisionDebugsessionDeleteDataCall), [*environments apis revisions debugsessions get*](api::OrganizationEnvironmentApiRevisionDebugsessionGetCall), [*environments apis revisions debugsessions list*](api::OrganizationEnvironmentApiRevisionDebugsessionListCall), [*environments apis revisions deployments*](api::OrganizationEnvironmentApiRevisionDeploymentCall), [*environments apis revisions get deployments*](api::OrganizationEnvironmentApiRevisionGetDeploymentCall), [*environments caches delete*](api::OrganizationEnvironmentCacheDeleteCall), [*environments create*](api::OrganizationEnvironmentCreateCall), [*environments delete*](api::OrganizationEnvironmentDeleteCall), [*environments deployments list*](api::OrganizationEnvironmentDeploymentListCall), [*environments flowhooks attach shared flow to flow hook*](api::OrganizationEnvironmentFlowhookAttachSharedFlowToFlowHookCall), [*environments flowhooks detach shared flow from flow hook*](api::OrganizationEnvironmentFlowhookDetachSharedFlowFromFlowHookCall), [*environments flowhooks get*](api::OrganizationEnvironmentFlowhookGetCall), [*environments get*](api::OrganizationEnvironmentGetCall), [*environments get debugmask*](api::OrganizationEnvironmentGetDebugmaskCall), [*environments get deployed config*](api::OrganizationEnvironmentGetDeployedConfigCall), [*environments get iam policy*](api::OrganizationEnvironmentGetIamPolicyCall), [*environments keystores aliases create*](api::OrganizationEnvironmentKeystoreAliaseCreateCall), [*environments keystores aliases csr*](api::OrganizationEnvironmentKeystoreAliaseCsrCall), [*environments keystores aliases delete*](api::OrganizationEnvironmentKeystoreAliaseDeleteCall), [*environments keystores aliases get*](api::OrganizationEnvironmentKeystoreAliaseGetCall), [*environments keystores aliases get certificate*](api::OrganizationEnvironmentKeystoreAliaseGetCertificateCall), [*environments keystores aliases update*](api::OrganizationEnvironmentKeystoreAliaseUpdateCall), [*environments keystores create*](api::OrganizationEnvironmentKeystoreCreateCall), [*environments keystores delete*](api::OrganizationEnvironmentKeystoreDeleteCall), [*environments keystores get*](api::OrganizationEnvironmentKeystoreGetCall), [*environments keyvaluemaps create*](api::OrganizationEnvironmentKeyvaluemapCreateCall), [*environments keyvaluemaps delete*](api::OrganizationEnvironmentKeyvaluemapDeleteCall), [*environments optimized stats get*](api::OrganizationEnvironmentOptimizedStatGetCall), [*environments queries create*](api::OrganizationEnvironmentQueryCreateCall), [*environments queries get*](api::OrganizationEnvironmentQueryGetCall), [*environments queries get result*](api::OrganizationEnvironmentQueryGetResultCall), [*environments queries list*](api::OrganizationEnvironmentQueryListCall), [*environments references create*](api::OrganizationEnvironmentReferenceCreateCall), [*environments references delete*](api::OrganizationEnvironmentReferenceDeleteCall), [*environments references get*](api::OrganizationEnvironmentReferenceGetCall), [*environments references update*](api::OrganizationEnvironmentReferenceUpdateCall), [*environments resourcefiles create*](api::OrganizationEnvironmentResourcefileCreateCall), [*environments resourcefiles delete*](api::OrganizationEnvironmentResourcefileDeleteCall), [*environments resourcefiles get*](api::OrganizationEnvironmentResourcefileGetCall), [*environments resourcefiles list*](api::OrganizationEnvironmentResourcefileListCall), [*environments resourcefiles list environment resources*](api::OrganizationEnvironmentResourcefileListEnvironmentResourceCall), [*environments resourcefiles update*](api::OrganizationEnvironmentResourcefileUpdateCall), [*environments set iam policy*](api::OrganizationEnvironmentSetIamPolicyCall), [*environments sharedflows deployments list*](api::OrganizationEnvironmentSharedflowDeploymentListCall), [*environments sharedflows revisions deployments*](api::OrganizationEnvironmentSharedflowRevisionDeploymentCall), [*environments sharedflows revisions get deployments*](api::OrganizationEnvironmentSharedflowRevisionGetDeploymentCall), [*environments stats get*](api::OrganizationEnvironmentStatGetCall), [*environments subscribe*](api::OrganizationEnvironmentSubscribeCall), [*environments targetservers create*](api::OrganizationEnvironmentTargetserverCreateCall), [*environments targetservers delete*](api::OrganizationEnvironmentTargetserverDeleteCall), [*environments targetservers get*](api::OrganizationEnvironmentTargetserverGetCall), [*environments targetservers update*](api::OrganizationEnvironmentTargetserverUpdateCall), [*environments test iam permissions*](api::OrganizationEnvironmentTestIamPermissionCall), [*environments unsubscribe*](api::OrganizationEnvironmentUnsubscribeCall), [*environments update*](api::OrganizationEnvironmentUpdateCall), [*environments update debugmask*](api::OrganizationEnvironmentUpdateDebugmaskCall), [*environments update environment*](api::OrganizationEnvironmentUpdateEnvironmentCall), [*get*](api::OrganizationGetCall), [*get sync authorization*](api::OrganizationGetSyncAuthorizationCall), [*keyvaluemaps create*](api::OrganizationKeyvaluemapCreateCall), [*keyvaluemaps delete*](api::OrganizationKeyvaluemapDeleteCall), [*list*](api::OrganizationListCall), [*operations get*](api::OrganizationOperationGetCall), [*operations list*](api::OrganizationOperationListCall), [*reports create*](api::OrganizationReportCreateCall), [*reports delete*](api::OrganizationReportDeleteCall), [*reports get*](api::OrganizationReportGetCall), [*reports list*](api::OrganizationReportListCall), [*reports update*](api::OrganizationReportUpdateCall), [*set sync authorization*](api::OrganizationSetSyncAuthorizationCall), [*sharedflows create*](api::OrganizationSharedflowCreateCall), [*sharedflows delete*](api::OrganizationSharedflowDeleteCall), [*sharedflows deployments list*](api::OrganizationSharedflowDeploymentListCall), [*sharedflows get*](api::OrganizationSharedflowGetCall), [*sharedflows list*](api::OrganizationSharedflowListCall), [*sharedflows revisions delete*](api::OrganizationSharedflowRevisionDeleteCall), [*sharedflows revisions deployments list*](api::OrganizationSharedflowRevisionDeploymentListCall), [*sharedflows revisions get*](api::OrganizationSharedflowRevisionGetCall), [*sharedflows revisions update shared flow revision*](api::OrganizationSharedflowRevisionUpdateSharedFlowRevisionCall) and [*update*](api::OrganizationUpdateCall)
//! 
//! 
//! 
//! 
//! Not what you are looking for ? Find all other Google APIs in their Rust [documentation index](http://byron.github.io/google-apis-rs).
//! 
//! # Structure of this Library
//! 
//! The API is structured into the following primary items:
//! 
//! * **[Hub](Apigee)**
//!     * a central object to maintain state and allow accessing all *Activities*
//!     * creates [*Method Builders*](client::MethodsBuilder) which in turn
//!       allow access to individual [*Call Builders*](client::CallBuilder)
//! * **[Resources](client::Resource)**
//!     * primary types that you can apply *Activities* to
//!     * a collection of properties and *Parts*
//!     * **[Parts](client::Part)**
//!         * a collection of properties
//!         * never directly used in *Activities*
//! * **[Activities](client::CallBuilder)**
//!     * operations to apply to *Resources*
//! 
//! All *structures* are marked with applicable traits to further categorize them and ease browsing.
//! 
//! Generally speaking, you can invoke *Activities* like this:
//! 
//! ```Rust,ignore
//! let r = hub.resource().activity(...).doit()
//! ```
//! 
//! Or specifically ...
//! 
//! ```ignore
//! let r = hub.organizations().apis_revisions_get(...).doit()
//! let r = hub.organizations().apis_revisions_update_api_proxy_revision(...).doit()
//! let r = hub.organizations().apis_create(...).doit()
//! let r = hub.organizations().environments_keystores_aliases_create(...).doit()
//! let r = hub.organizations().environments_keystores_aliases_csr(...).doit()
//! let r = hub.organizations().environments_keystores_aliases_get_certificate(...).doit()
//! let r = hub.organizations().environments_keystores_aliases_update(...).doit()
//! let r = hub.organizations().environments_queries_get_result(...).doit()
//! let r = hub.organizations().environments_resourcefiles_create(...).doit()
//! let r = hub.organizations().environments_resourcefiles_get(...).doit()
//! let r = hub.organizations().environments_resourcefiles_update(...).doit()
//! let r = hub.organizations().sharedflows_revisions_get(...).doit()
//! let r = hub.organizations().sharedflows_revisions_update_shared_flow_revision(...).doit()
//! let r = hub.organizations().sharedflows_create(...).doit()
//! ```
//! 
//! The `resource()` and `activity(...)` calls create [builders][builder-pattern]. The second one dealing with `Activities` 
//! supports various methods to configure the impending operation (not shown here). It is made such that all required arguments have to be 
//! specified right away (i.e. `(...)`), whereas all optional ones can be [build up][builder-pattern] as desired.
//! The `doit()` method performs the actual communication with the server and returns the respective result.
//! 
//! # Usage
//! 
//! ## Setting up your Project
//! 
//! To use this library, you would put the following lines into your `Cargo.toml` file:
//! 
//! ```toml
//! [dependencies]
//! google-apigee1 = "*"
//! # This project intentionally uses an old version of Hyper. See
//! # https://github.com/Byron/google-apis-rs/issues/173 for more
//! # information.
//! hyper = "^0.10"
//! hyper-rustls = "^0.6"
//! serde = "^1.0"
//! serde_json = "^1.0"
//! yup-oauth2 = "^1.0"
//! ```
//! 
//! ## A complete example
//! 
//! ```test_harness,no_run
//! extern crate hyper;
//! extern crate hyper_rustls;
//! extern crate yup_oauth2 as oauth2;
//! extern crate google_apigee1 as apigee1;
//! use apigee1::api::GoogleApiHttpBody;
//! use apigee1::{Result, Error};
//! # #[test] fn egal() {
//! use std::default::Default;
//! use oauth2::{Authenticator, DefaultAuthenticatorDelegate, ApplicationSecret, MemoryStorage};
//! use apigee1::Apigee;
//! 
//! // Get an ApplicationSecret instance by some means. It contains the `client_id` and 
//! // `client_secret`, among other things.
//! let secret: ApplicationSecret = Default::default();
//! // Instantiate the authenticator. It will choose a suitable authentication flow for you, 
//! // unless you replace  `None` with the desired Flow.
//! // Provide your own `AuthenticatorDelegate` to adjust the way it operates and get feedback about 
//! // what's going on. You probably want to bring in your own `TokenStorage` to persist tokens and
//! // retrieve them from storage.
//! let auth = Authenticator::new(&secret, DefaultAuthenticatorDelegate,
//!                               hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())),
//!                               <MemoryStorage as Default>::default(), None);
//! let mut hub = Apigee::new(hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())), auth);
//! // As the method needs a request, you would usually fill it with the desired information
//! // into the respective structure. Some of the parts shown here might not be applicable !
//! // Values shown here are possibly random and not representative !
//! let mut req = GoogleApiHttpBody::default();
//! 
//! // You can configure optional parameters by calling the respective setters at will, and
//! // execute the final call using `doit()`.
//! // Values shown here are possibly random and not representative !
//! let result = hub.organizations().environments_keystores_aliases_create(req, "parent")
//!              .ignore_newline_validation(true)
//!              .ignore_expiry_validation(true)
//!              .format("Lorem")
//!              .alias("gubergren")
//!              ._password("eos")
//!              .doit();
//! 
//! match result {
//!     Err(e) => match e {
//!         // The Error enum provides details about what exactly happened.
//!         // You can also just use its `Debug`, `Display` or `Error` traits
//!          Error::HttpError(_)
//!         |Error::MissingAPIKey
//!         |Error::MissingToken(_)
//!         |Error::Cancelled
//!         |Error::UploadSizeLimitExceeded(_, _)
//!         |Error::Failure(_)
//!         |Error::BadRequest(_)
//!         |Error::FieldClash(_)
//!         |Error::JsonDecodeError(_, _) => println!("{}", e),
//!     },
//!     Ok(res) => println!("Success: {:?}", res),
//! }
//! # }
//! ```
//! ## Handling Errors
//! 
//! All errors produced by the system are provided either as [Result](client::Result) enumeration as return value of
//! the doit() methods, or handed as possibly intermediate results to either the 
//! [Hub Delegate](client::Delegate), or the [Authenticator Delegate](https://docs.rs/yup-oauth2/*/yup_oauth2/trait.AuthenticatorDelegate.html).
//! 
//! When delegates handle errors or intermediate values, they may have a chance to instruct the system to retry. This 
//! makes the system potentially resilient to all kinds of errors.
//! 
//! ## Uploads and Downloads
//! If a method supports downloads, the response body, which is part of the [Result](client::Result), should be
//! read by you to obtain the media.
//! If such a method also supports a [Response Result](client::ResponseResult), it will return that by default.
//! You can see it as meta-data for the actual media. To trigger a media download, you will have to set up the builder by making
//! this call: `.param("alt", "media")`.
//! 
//! Methods supporting uploads can do so using up to 2 different protocols: 
//! *simple* and *resumable*. The distinctiveness of each is represented by customized 
//! `doit(...)` methods, which are then named `upload(...)` and `upload_resumable(...)` respectively.
//! 
//! ## Customization and Callbacks
//! 
//! You may alter the way an `doit()` method is called by providing a [delegate](client::Delegate) to the 
//! [Method Builder](client::CallBuilder) before making the final `doit()` call. 
//! Respective methods will be called to provide progress information, as well as determine whether the system should 
//! retry on failure.
//! 
//! The [delegate trait](client::Delegate) is default-implemented, allowing you to customize it with minimal effort.
//! 
//! ## Optional Parts in Server-Requests
//! 
//! All structures provided by this library are made to be [encodable](client::RequestValue) and 
//! [decodable](client::ResponseResult) via *json*. Optionals are used to indicate that partial requests are responses 
//! are valid.
//! Most optionals are are considered [Parts](client::Part) which are identifiable by name, which will be sent to 
//! the server to indicate either the set parts of the request or the desired parts in the response.
//! 
//! ## Builder Arguments
//! 
//! Using [method builders](client::CallBuilder), you are able to prepare an action call by repeatedly calling it's methods.
//! These will always take a single argument, for which the following statements are true.
//! 
//! * [PODs][wiki-pod] are handed by copy
//! * strings are passed as `&str`
//! * [request values](client::RequestValue) are moved
//! 
//! Arguments will always be copied or cloned into the builder, to make them independent of their original life times.
//! 
//! [wiki-pod]: http://en.wikipedia.org/wiki/Plain_old_data_structure
//! [builder-pattern]: http://en.wikipedia.org/wiki/Builder_pattern
//! [google-go-api]: https://github.com/google/google-api-go-client
//! 
//! 

// Unused attributes happen thanks to defined, but unused structures
// We don't warn about this, as depending on the API, some data structures or facilities are never used.
// Instead of pre-determining this, we just disable the lint. It's manually tuned to not have any
// unused imports in fully featured APIs. Same with unused_mut ... .
#![allow(unused_imports, unused_mut, dead_code)]

// DO NOT EDIT !
// This file was generated automatically from 'src/mako/api/lib.rs.mako'
// DO NOT EDIT !

#[macro_use]
extern crate serde_derive;

extern crate hyper;
extern crate serde;
extern crate serde_json;
extern crate yup_oauth2 as oauth2;
extern crate mime;
extern crate url;

pub mod api;
pub mod client;

// Re-export the hub type and some basic client structs
pub use api::Apigee;
pub use client::{Result, Error, Delegate};
