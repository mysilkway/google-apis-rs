<!---
DO NOT EDIT !
This file was generated automatically from 'src/mako/api/README.md.mako'
DO NOT EDIT !
-->
The `google-apigee1` library allows access to all features of the *Google Apigee* service.

This documentation was generated from *Apigee* crate version *1.0.14+20200625*, where *20200625* is the exact revision of the *apigee:v1* schema built by the [mako](http://www.makotemplates.org/) code generator *v1.0.14*.

Everything else about the *Apigee* *v1* API can be found at the
[official documentation site](https://cloud.google.com/apigee-api-management/).
# Features

Handle the following *Resources* with ease from the central [hub](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/Apigee) ... 

* hybrid
 * [*issuers list*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::HybridIssuerListCall)
* organizations
 * [*apiproducts attributes*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationApiproductAttributeCall), [*apiproducts attributes delete*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationApiproductAttributeDeleteCall), [*apiproducts attributes get*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationApiproductAttributeGetCall), [*apiproducts attributes list*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationApiproductAttributeListCall), [*apiproducts attributes update api product attribute*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationApiproductAttributeUpdateApiProductAttributeCall), [*apiproducts create*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationApiproductCreateCall), [*apiproducts delete*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationApiproductDeleteCall), [*apiproducts get*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationApiproductGetCall), [*apiproducts list*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationApiproductListCall), [*apiproducts update*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationApiproductUpdateCall), [*apis create*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationApiCreateCall), [*apis delete*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationApiDeleteCall), [*apis deployments list*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationApiDeploymentListCall), [*apis get*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationApiGetCall), [*apis keyvaluemaps create*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationApiKeyvaluemapCreateCall), [*apis keyvaluemaps delete*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationApiKeyvaluemapDeleteCall), [*apis list*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationApiListCall), [*apis revisions delete*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationApiRevisionDeleteCall), [*apis revisions deployments list*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationApiRevisionDeploymentListCall), [*apis revisions get*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationApiRevisionGetCall), [*apis revisions update api proxy revision*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationApiRevisionUpdateApiProxyRevisionCall), [*apps get*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationAppGetCall), [*apps list*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationAppListCall), [*create*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationCreateCall), [*deployments list*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationDeploymentListCall), [*developers apps attributes*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationDeveloperAppAttributeCall), [*developers apps attributes delete*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationDeveloperAppAttributeDeleteCall), [*developers apps attributes get*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationDeveloperAppAttributeGetCall), [*developers apps attributes list*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationDeveloperAppAttributeListCall), [*developers apps attributes update developer app attribute*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationDeveloperAppAttributeUpdateDeveloperAppAttributeCall), [*developers apps create*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationDeveloperAppCreateCall), [*developers apps delete*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationDeveloperAppDeleteCall), [*developers apps generate key pair or update developer app status*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationDeveloperAppGenerateKeyPairOrUpdateDeveloperAppStatuCall), [*developers apps get*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationDeveloperAppGetCall), [*developers apps keys apiproducts delete*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationDeveloperAppKeyApiproductDeleteCall), [*developers apps keys apiproducts update developer app key api product*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationDeveloperAppKeyApiproductUpdateDeveloperAppKeyApiProductCall), [*developers apps keys create*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationDeveloperAppKeyCreateCall), [*developers apps keys create create*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationDeveloperAppKeyCreateCreateCall), [*developers apps keys delete*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationDeveloperAppKeyDeleteCall), [*developers apps keys get*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationDeveloperAppKeyGetCall), [*developers apps keys replace developer app key*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationDeveloperAppKeyReplaceDeveloperAppKeyCall), [*developers apps keys update developer app key*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationDeveloperAppKeyUpdateDeveloperAppKeyCall), [*developers apps list*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationDeveloperAppListCall), [*developers apps update*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationDeveloperAppUpdateCall), [*developers attributes*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationDeveloperAttributeCall), [*developers attributes delete*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationDeveloperAttributeDeleteCall), [*developers attributes get*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationDeveloperAttributeGetCall), [*developers attributes list*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationDeveloperAttributeListCall), [*developers attributes update developer attribute*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationDeveloperAttributeUpdateDeveloperAttributeCall), [*developers create*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationDeveloperCreateCall), [*developers delete*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationDeveloperDeleteCall), [*developers get*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationDeveloperGetCall), [*developers list*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationDeveloperListCall), [*developers set developer status*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationDeveloperSetDeveloperStatuCall), [*developers update*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationDeveloperUpdateCall), [*environments analytics admin get schemav2*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentAnalyticAdminGetSchemav2Call), [*environments apis deployments list*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentApiDeploymentListCall), [*environments apis revisions debugsessions create*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentApiRevisionDebugsessionCreateCall), [*environments apis revisions debugsessions data get*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentApiRevisionDebugsessionDataGetCall), [*environments apis revisions debugsessions delete data*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentApiRevisionDebugsessionDeleteDataCall), [*environments apis revisions debugsessions get*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentApiRevisionDebugsessionGetCall), [*environments apis revisions debugsessions list*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentApiRevisionDebugsessionListCall), [*environments apis revisions deployments*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentApiRevisionDeploymentCall), [*environments apis revisions get deployments*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentApiRevisionGetDeploymentCall), [*environments caches delete*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentCacheDeleteCall), [*environments create*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentCreateCall), [*environments delete*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentDeleteCall), [*environments deployments list*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentDeploymentListCall), [*environments flowhooks attach shared flow to flow hook*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentFlowhookAttachSharedFlowToFlowHookCall), [*environments flowhooks detach shared flow from flow hook*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentFlowhookDetachSharedFlowFromFlowHookCall), [*environments flowhooks get*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentFlowhookGetCall), [*environments get*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentGetCall), [*environments get debugmask*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentGetDebugmaskCall), [*environments get deployed config*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentGetDeployedConfigCall), [*environments get iam policy*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentGetIamPolicyCall), [*environments keystores aliases create*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentKeystoreAliaseCreateCall), [*environments keystores aliases csr*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentKeystoreAliaseCsrCall), [*environments keystores aliases delete*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentKeystoreAliaseDeleteCall), [*environments keystores aliases get*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentKeystoreAliaseGetCall), [*environments keystores aliases get certificate*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentKeystoreAliaseGetCertificateCall), [*environments keystores aliases update*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentKeystoreAliaseUpdateCall), [*environments keystores create*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentKeystoreCreateCall), [*environments keystores delete*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentKeystoreDeleteCall), [*environments keystores get*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentKeystoreGetCall), [*environments keyvaluemaps create*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentKeyvaluemapCreateCall), [*environments keyvaluemaps delete*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentKeyvaluemapDeleteCall), [*environments optimized stats get*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentOptimizedStatGetCall), [*environments queries create*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentQueryCreateCall), [*environments queries get*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentQueryGetCall), [*environments queries get result*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentQueryGetResultCall), [*environments queries list*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentQueryListCall), [*environments references create*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentReferenceCreateCall), [*environments references delete*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentReferenceDeleteCall), [*environments references get*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentReferenceGetCall), [*environments references update*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentReferenceUpdateCall), [*environments resourcefiles create*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentResourcefileCreateCall), [*environments resourcefiles delete*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentResourcefileDeleteCall), [*environments resourcefiles get*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentResourcefileGetCall), [*environments resourcefiles list*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentResourcefileListCall), [*environments resourcefiles list environment resources*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentResourcefileListEnvironmentResourceCall), [*environments resourcefiles update*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentResourcefileUpdateCall), [*environments set iam policy*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentSetIamPolicyCall), [*environments sharedflows deployments list*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentSharedflowDeploymentListCall), [*environments sharedflows revisions deployments*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentSharedflowRevisionDeploymentCall), [*environments sharedflows revisions get deployments*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentSharedflowRevisionGetDeploymentCall), [*environments stats get*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentStatGetCall), [*environments subscribe*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentSubscribeCall), [*environments targetservers create*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentTargetserverCreateCall), [*environments targetservers delete*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentTargetserverDeleteCall), [*environments targetservers get*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentTargetserverGetCall), [*environments targetservers update*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentTargetserverUpdateCall), [*environments test iam permissions*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentTestIamPermissionCall), [*environments unsubscribe*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentUnsubscribeCall), [*environments update*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentUpdateCall), [*environments update debugmask*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentUpdateDebugmaskCall), [*environments update environment*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationEnvironmentUpdateEnvironmentCall), [*get*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationGetCall), [*get sync authorization*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationGetSyncAuthorizationCall), [*keyvaluemaps create*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationKeyvaluemapCreateCall), [*keyvaluemaps delete*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationKeyvaluemapDeleteCall), [*list*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationListCall), [*operations get*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationOperationGetCall), [*operations list*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationOperationListCall), [*reports create*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationReportCreateCall), [*reports delete*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationReportDeleteCall), [*reports get*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationReportGetCall), [*reports list*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationReportListCall), [*reports update*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationReportUpdateCall), [*set sync authorization*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationSetSyncAuthorizationCall), [*sharedflows create*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationSharedflowCreateCall), [*sharedflows delete*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationSharedflowDeleteCall), [*sharedflows deployments list*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationSharedflowDeploymentListCall), [*sharedflows get*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationSharedflowGetCall), [*sharedflows list*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationSharedflowListCall), [*sharedflows revisions delete*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationSharedflowRevisionDeleteCall), [*sharedflows revisions deployments list*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationSharedflowRevisionDeploymentListCall), [*sharedflows revisions get*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationSharedflowRevisionGetCall), [*sharedflows revisions update shared flow revision*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationSharedflowRevisionUpdateSharedFlowRevisionCall) and [*update*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/api::OrganizationUpdateCall)




# Structure of this Library

The API is structured into the following primary items:

* **[Hub](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/Apigee)**
    * a central object to maintain state and allow accessing all *Activities*
    * creates [*Method Builders*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/client::MethodsBuilder) which in turn
      allow access to individual [*Call Builders*](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/client::CallBuilder)
* **[Resources](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/client::Resource)**
    * primary types that you can apply *Activities* to
    * a collection of properties and *Parts*
    * **[Parts](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/client::Part)**
        * a collection of properties
        * never directly used in *Activities*
* **[Activities](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/client::CallBuilder)**
    * operations to apply to *Resources*

All *structures* are marked with applicable traits to further categorize them and ease browsing.

Generally speaking, you can invoke *Activities* like this:

```Rust,ignore
let r = hub.resource().activity(...).doit()
```

Or specifically ...

```ignore
let r = hub.organizations().apis_revisions_get(...).doit()
let r = hub.organizations().apis_revisions_update_api_proxy_revision(...).doit()
let r = hub.organizations().apis_create(...).doit()
let r = hub.organizations().environments_keystores_aliases_create(...).doit()
let r = hub.organizations().environments_keystores_aliases_csr(...).doit()
let r = hub.organizations().environments_keystores_aliases_get_certificate(...).doit()
let r = hub.organizations().environments_keystores_aliases_update(...).doit()
let r = hub.organizations().environments_queries_get_result(...).doit()
let r = hub.organizations().environments_resourcefiles_create(...).doit()
let r = hub.organizations().environments_resourcefiles_get(...).doit()
let r = hub.organizations().environments_resourcefiles_update(...).doit()
let r = hub.organizations().sharedflows_revisions_get(...).doit()
let r = hub.organizations().sharedflows_revisions_update_shared_flow_revision(...).doit()
let r = hub.organizations().sharedflows_create(...).doit()
```

The `resource()` and `activity(...)` calls create [builders][builder-pattern]. The second one dealing with `Activities` 
supports various methods to configure the impending operation (not shown here). It is made such that all required arguments have to be 
specified right away (i.e. `(...)`), whereas all optional ones can be [build up][builder-pattern] as desired.
The `doit()` method performs the actual communication with the server and returns the respective result.

# Usage

## Setting up your Project

To use this library, you would put the following lines into your `Cargo.toml` file:

```toml
[dependencies]
google-apigee1 = "*"
# This project intentionally uses an old version of Hyper. See
# https://github.com/Byron/google-apis-rs/issues/173 for more
# information.
hyper = "^0.10"
hyper-rustls = "^0.6"
serde = "^1.0"
serde_json = "^1.0"
yup-oauth2 = "^1.0"
```

## A complete example

```Rust
extern crate hyper;
extern crate hyper_rustls;
extern crate yup_oauth2 as oauth2;
extern crate google_apigee1 as apigee1;
use apigee1::api::GoogleApiHttpBody;
use apigee1::{Result, Error};
use std::default::Default;
use oauth2::{Authenticator, DefaultAuthenticatorDelegate, ApplicationSecret, MemoryStorage};
use apigee1::Apigee;

// Get an ApplicationSecret instance by some means. It contains the `client_id` and 
// `client_secret`, among other things.
let secret: ApplicationSecret = Default::default();
// Instantiate the authenticator. It will choose a suitable authentication flow for you, 
// unless you replace  `None` with the desired Flow.
// Provide your own `AuthenticatorDelegate` to adjust the way it operates and get feedback about 
// what's going on. You probably want to bring in your own `TokenStorage` to persist tokens and
// retrieve them from storage.
let auth = Authenticator::new(&secret, DefaultAuthenticatorDelegate,
                              hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())),
                              <MemoryStorage as Default>::default(), None);
let mut hub = Apigee::new(hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())), auth);
// As the method needs a request, you would usually fill it with the desired information
// into the respective structure. Some of the parts shown here might not be applicable !
// Values shown here are possibly random and not representative !
let mut req = GoogleApiHttpBody::default();

// You can configure optional parameters by calling the respective setters at will, and
// execute the final call using `doit()`.
// Values shown here are possibly random and not representative !
let result = hub.organizations().environments_keystores_aliases_create(req, "parent")
             .ignore_newline_validation(true)
             .ignore_expiry_validation(false)
             .format("amet.")
             .alias("takimata")
             ._password("amet.")
             .doit();

match result {
    Err(e) => match e {
        // The Error enum provides details about what exactly happened.
        // You can also just use its `Debug`, `Display` or `Error` traits
         Error::HttpError(_)
        |Error::MissingAPIKey
        |Error::MissingToken(_)
        |Error::Cancelled
        |Error::UploadSizeLimitExceeded(_, _)
        |Error::Failure(_)
        |Error::BadRequest(_)
        |Error::FieldClash(_)
        |Error::JsonDecodeError(_, _) => println!("{}", e),
    },
    Ok(res) => println!("Success: {:?}", res),
}

```
## Handling Errors

All errors produced by the system are provided either as [Result](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/client::Result) enumeration as return value of
the doit() methods, or handed as possibly intermediate results to either the 
[Hub Delegate](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/client::Delegate), or the [Authenticator Delegate](https://docs.rs/yup-oauth2/*/yup_oauth2/trait.AuthenticatorDelegate.html).

When delegates handle errors or intermediate values, they may have a chance to instruct the system to retry. This 
makes the system potentially resilient to all kinds of errors.

## Uploads and Downloads
If a method supports downloads, the response body, which is part of the [Result](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/client::Result), should be
read by you to obtain the media.
If such a method also supports a [Response Result](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/client::ResponseResult), it will return that by default.
You can see it as meta-data for the actual media. To trigger a media download, you will have to set up the builder by making
this call: `.param("alt", "media")`.

Methods supporting uploads can do so using up to 2 different protocols: 
*simple* and *resumable*. The distinctiveness of each is represented by customized 
`doit(...)` methods, which are then named `upload(...)` and `upload_resumable(...)` respectively.

## Customization and Callbacks

You may alter the way an `doit()` method is called by providing a [delegate](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/client::Delegate) to the 
[Method Builder](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/client::CallBuilder) before making the final `doit()` call. 
Respective methods will be called to provide progress information, as well as determine whether the system should 
retry on failure.

The [delegate trait](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/client::Delegate) is default-implemented, allowing you to customize it with minimal effort.

## Optional Parts in Server-Requests

All structures provided by this library are made to be [encodable](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/client::RequestValue) and 
[decodable](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/client::ResponseResult) via *json*. Optionals are used to indicate that partial requests are responses 
are valid.
Most optionals are are considered [Parts](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/client::Part) which are identifiable by name, which will be sent to 
the server to indicate either the set parts of the request or the desired parts in the response.

## Builder Arguments

Using [method builders](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/client::CallBuilder), you are able to prepare an action call by repeatedly calling it's methods.
These will always take a single argument, for which the following statements are true.

* [PODs][wiki-pod] are handed by copy
* strings are passed as `&str`
* [request values](https://docs.rs/google-apigee1/1.0.14+20200625/google_apigee1/client::RequestValue) are moved

Arguments will always be copied or cloned into the builder, to make them independent of their original life times.

[wiki-pod]: http://en.wikipedia.org/wiki/Plain_old_data_structure
[builder-pattern]: http://en.wikipedia.org/wiki/Builder_pattern
[google-go-api]: https://github.com/google/google-api-go-client

# License
The **apigee1** library was generated by Sebastian Thiel, and is placed 
under the *MIT* license.
You can read the full text at the repository's [license file][repo-license].

[repo-license]: https://github.com/Byron/google-apis-rsblob/master/LICENSE.md
