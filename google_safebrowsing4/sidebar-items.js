initSidebarItems({"enum":[["Error",""]],"fn":[["remove_json_null_values",""]],"struct":[["Checksum","The expected state of a client's local database."],["ClientInfo","The client metadata associated with Safe Browsing API requests."],["Constraints","The constraints for this update."],["DefaultDelegate","A delegate with a conservative default implementation, which is used if no other delegate is set."],["ErrorResponse","A utility to represent detailed errors we might see in case there are BadRequests. The latter happen if the sent parameters or request structures are unsound"],["FetchThreatListUpdatesRequest","Describes a Safe Browsing API update request. Clients can request updates for multiple lists in a single request. NOTE: Field index 2 is unused. NEXT: 4"],["FetchThreatListUpdatesResponse","There is no detailed description."],["FindFullHashesRequest","Request to return full hashes matched by the provided hash prefixes."],["FindFullHashesResponse","There is no detailed description."],["FindThreatMatchesRequest","Request to check entries against lists."],["FindThreatMatchesResponse","There is no detailed description."],["FullHasheFindCall","Finds the full hashes that match the requested hash prefixes."],["FullHasheMethods","A builder providing access to all methods supported on *fullHashe* resources. It is not used directly, but through the `Safebrowsing` hub."],["ListThreatListsResponse","There is no detailed description."],["ListUpdateRequest","A single list update request."],["ListUpdateResponse","An update to an individual list."],["MetadataEntry","A single metadata entry."],["MethodInfo","Contains information about an API request."],["MultiPartReader","Provides a `Read` interface that converts multiple parts into the protocol identified by RFC2387. **Note**: This implementation is just as rich as it needs to be to perform uploads to google APIs, and might not be a fully-featured implementation."],["RawHashes","The uncompressed threat entries in hash format of a particular prefix length. Hashes can be anywhere from 4 to 32 bytes in size. A large majority are 4 bytes, but some hashes are lengthened if they collide with the hash of a popular URL. Used for sending ThreatEntrySet to clients that do not support compression, or when sending non-4-byte hashes to clients that do support compression."],["RawIndices","A set of raw indices to remove from a local list."],["RiceDeltaEncoding","The Rice-Golomb encoded data. Used for sending compressed 4-byte hashes or compressed removal indices."],["Safebrowsing","Central instance to access all Safebrowsing related resource activities"],["ThreatEntry","An individual threat; for example, a malicious URL or its hash representation. Only one of these fields should be set."],["ThreatEntryMetadata","The metadata associated with a specific threat entry. The client is expected to know the metadata key/value pairs associated with each threat type."],["ThreatEntrySet","A set of threats that should be added or removed from a client's local database."],["ThreatInfo","The information regarding one or more threats that a client submits when checking for matches in threat lists."],["ThreatListDescriptor","Describes an individual threat list. A list is defined by three parameters: the type of threat posed, the type of platform targeted by the threat, and the type of entries in the list."],["ThreatListListCall","Lists the Safe Browsing threat lists available for download."],["ThreatListMethods","A builder providing access to all methods supported on *threatList* resources. It is not used directly, but through the `Safebrowsing` hub."],["ThreatListUpdateFetchCall","Fetches the most recent threat list updates. A client can request updates for multiple lists at once."],["ThreatListUpdateMethods","A builder providing access to all methods supported on *threatListUpdate* resources. It is not used directly, but through the `Safebrowsing` hub."],["ThreatMatch","A match when checking a threat entry in the Safe Browsing threat lists."],["ThreatMatcheFindCall","Finds the threat entries that match the Safe Browsing lists."],["ThreatMatcheMethods","A builder providing access to all methods supported on *threatMatche* resources. It is not used directly, but through the `Safebrowsing` hub."]],"trait":[["CallBuilder","Identifies types which represent builders for a particular resource method"],["Delegate","A trait specifying functionality to help controlling any request performed by the API. The trait has a conservative default implementation."],["Hub","Identifies the Hub. There is only one per library, this trait is supposed to make intended use more explicit. The hub allows to access all resource methods more easily."],["MethodsBuilder","Identifies types for building methods of a particular resource type"],["NestedType","Identifies types which are only used by other types internally. They have no special meaning, this trait just marks them for completeness."],["Part","Identifies types which are only used as part of other types, which usually are carrying the `Resource` trait."],["ReadSeek","A utility to specify reader types which provide seeking capabilities too"],["RequestValue","Identifies types which are used in API requests."],["Resource","Identifies types which can be inserted and deleted. Types with this trait are most commonly used by clients of this API."],["ResponseResult","Identifies types which are used in API responses."],["ToParts","A trait for all types that can convert themselves into a *parts* string"]],"type":[["Result","A universal result type used as return for all calls."]]});