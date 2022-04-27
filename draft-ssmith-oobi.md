---
title: "Out-Of-Band-Introduction (OOBI) Protocol"
abbrev: "OOBI"
category: info

docname: draft-ssmith-oobi-latest
v: 3
area: AREA
workgroup: WG Working Group
keyword: Internet-Draft
venue:
  group: WG
  type: Working Group
  mail: WG@example.com
  arch: https://example.com/WG
  github: USER/REPO
  latest: https://example.com/LATEST

author:
 -
    fullname: Samuel M. Smith
    organization: ProSapien LLC
    email: sam@prosapien.com

normative:

  OOBI_ID:
    target: https://github.com/WebOfTrust/ietf-oobi
    title: IETF OOBI (Out-Of-Band-Introduction) Internet Draft
    author:
      ins: S. Smith
      name: Samuel M. Smith
      org: ProSapien LLC
    date: 2022

  KERI_ID:
    target: https://github.com/WebOfTrust/ietf-keri
    title: IETF KERI (Key Event Receipt Infrastructure) Internet Draft
    author:
      ins: S. Smith
      name: Samuel M. Smith
      org: ProSapien LLC
    date: 2022
    
  SAID_ID:
    target: https://github.com/WebOfTrust/ietf-said
    title: IETF SAID (Self-Addressing IDentifier) Internet Draft
    author:
      ins: S. Smith
      name: Samuel M. Smith
      org: ProSapien LLC
    date: 2022
    
  CESR_ID:
    target: https://github.com/WebOfTrust/ietf-cesr
    title: IETF CESR (Composable Event Streaming Representation) Internet Draft
    author:
      ins: S. Smith
      name: Samuel M. Smith
      org: ProSapien LLC
    date: 2022
    
  ACDC_ID:
    target: https://github.com/trustoverip/tswg-acdc-specification
    title: IETF ACDC (Authentic Chained Data Containers) Internet Draft
    author:
      ins: S. Smith
      name: Samuel M. Smith
      org: ProSapien LLC
    date: 2022

  RFC3986:
    target: https://datatracker.ietf.org/doc/html/rfc3986
    title: "Uniform Resource Identifier (URI): Generic Syntax"
    
  RFC8820:
    target: https://datatracker.ietf.org/doc/html/rfc8820
    title: URI Design and Ownership


informative:
  
  KERI:
    target: https://arxiv.org/abs/1907.02143
    title: Key Event Receipt Infrastructure (KERI)
    author:
      ins: S. Smith
      name: Samuel M. Smith
      org: ProSapien LLC
    date: 2021

  IDSys:
    target: https://github.com/SmithSamuelM/Papers/blob/master/whitepapers/Identity-System-Essentials.pdf
    title: Identity System Essentials 

  PT:
    target: https://en.wikipedia.org/wiki/Percolation_theory
    title: Percolation Theory
    
  FPP:
    target: https://en.wikipedia.org/wiki/First_passage_percolation
    title: First Passage Percolation

  IPT:
    target: https://www.physics.purdue.edu/flow/MMproject/Wilkinson1983.pdf
    title: Invasion Percolation
    
  DOMIP:
    target: https://journals.aps.org/prl/abstract/10.1103/PhysRevLett.103.018701
    title: Dynamic Opinion Model and Invasion Percolation

  PTEL_ID:
    target: https://github.com/WebOfTrust/ietf-ptel
    title: IETF PTEL (Public Transaction Event Log) Internet Draft
    author:
      ins: P. Feairheller
      name: Phil Feairheller
      org: GLEIF
    date: 2022
    
  Proof_ID:
    target: https://github.com/WebOfTrust/ietf-cesr-proof
    title: IETF CESR-Proof Internet Draft
    author:
      ins: P. Feairheller
      name: Phil Feairheller
      org: GLEIF
    date: 2022
 
  IPEX_ID:
    target: https://github.com/WebOfTrust/keripy/blob/master/ref/Peer2PeerCredentials.md
    title: IPEX (Issuance and Presentation EXchange) Internet Draft
    author:
      ins: P. Feairheller
      name: Phil Feairheller
      org: GLEIF
    date: 2022

  DIDK_ID:
    target: https://github.com/WebOfTrust/ietf-did-keri
    title: IETF DID-KERI Internet Draft
    author:
      ins: P. Feairheller
      name: Phil Feairheller
      org: GLEIF
    date: 2022

  JSON:
    target: https://www.json.org/json-en.html
    title: JavaScript Object Notation Delimeters
    
  RFC8259:
    target: https://datatracker.ietf.org/doc/html/rfc8259
    title: JSON (JavaScript Object Notation)
    
  RFC4627:
    target: https://datatracker.ietf.org/doc/rfc4627/
    title: The application/json Media Type for JavaScript Object Notation (JSON)
    
  URL:
    target: https://en.wikipedia.org/wiki/URL
    title: URL
    
  QR:
    target: https://en.wikipedia.org/wiki/QR_code
    title: QR Code
    
  DM:
    target: https://en.wikipedia.org/wiki/Data_Matrix
    title: Data Matrix
    
  RTE:
    target: https://gdpr-info.eu/art-17-gdpr/
    title: GDPR Right to Erasure
    

--- abstract

An Out-Of-Band Introduction (OOBI) provides a discovery mechanism that associates a given URI or URL with a given AID (Autonomic IDentifier) or SAID (Self-Addressing IDentifier) {{KERI_ID}}{{KERI}}{{SAID_ID}}{{OOBI_ID}}. The URI provided by an OOBI acts as a service endpoint for the discovery of verifiable information about the AID or SAID. As such an OOBI itself is not trusted but must be verified. To clarify, any information obtained from the service endpoint provided in the OOBI must be verified by some other mechanism. An OOBI, however, enables any internet and web search infrastructure to act as an out-of-band infrastructure to discover information that is verified using an in-band mechanism or protocol. The primary in-band verification protocol is KERI {{KERI_ID}}{{KERI}}. The OOBI protocol provides a web-based bootstrap and/or discovery mechanism for the KERI and the ACDC (Authentic Chained Data Container) protocols {{KERI_ID}}{{ACDC_ID}}{{OOBI_ID}}. Thus the security (or more correctly the lack of security) of an OOBI is out-of-band with respect to a KERI AID or an ACDC that uses KERI. To clarify, everything in KERI or that depends on KERI is end-verifiable, therefore it has no security dependency nor does it rely on security guarantees that may or may not be provided by web or internet infrastructure.  OOBIs provide a bootstrap that enables what we call Percolated Information Discovery (PID) which is based on Invasion Percolation Theory {{IPT}}{{DOMIP}{{PT}}{{FPP}}. This bootstrap may then be parlayed into a secure mechanism for accepting and updating data. The principal data acceptance and update policy is denoted BADA (Best-Available-Data-Acceptance).


--- middle

# Introduction

Vacuous discovery of IP resources such as service endpoints associated with a KERI AID (Autonomic IDentifier) or SAID (Self-Addressing IDentifier) requires an Out-Of-Band Introduction (OOBI) to associate a given URL with a given AID (Autonomic IDentifier) or SAID (Self-Addressing IDentifier) {{KERI_ID}}{{KERI}}{{SAID_ID}}{{OOBI_ID}}{{URL}}. The principal reason for this requirement is that KERI AIDs are derived in a completely decentralized manner. The root-of-trust of a KERI AID is completely independent of internet and DNS addressing infrastructure. Thus an IP address or URL could be considered a type of Out-Of-Band Infrastructure (OOBI) for KERI.  In this context, an introduction is an association between a KERI AID and a URL that may include either an explicit IP address or a DNS name for its host {{RFC3986}}{{URL}}. We call this a KERI OOBI (Out-Of-Band-Introduction) and is a special case of Out-Of-Band-Infrastructure (OOBI) with a shared acronym. For the sake of clarity, unless otherwise qualified, OOBI is used to mean this special case of an *introduction* and not the general case of *infrastructure*.

Moreover, because IP infrastructure is not trusted by KERI, a KERI OOBI by itself is considered insecure with respect to KERI, and any OOBI must therefore be later verified using a KERI BADA (Best-Available-Data-Acceptance) mechanism. The principal use case for an OOBI is to jump-start the discovery of a service endpoint for a given AID. To reiterate, the OOBI by itself is not sufficient for discovery because the OOBI itself is insecure. The OOBI merely jump-starts authenticated discovery.  

Using IP and DNS infrastructure to introduce KERI AIDs which AIDs are then securely attributed allows KERI to leverage IP and DNS infrastructure for discovery. KERI does not, therefore, need its own dedicated discovery network, OOBIs with URLs will do.

A secondary use case for OOBI's is to provide service endpoints or URIs for SAD (Self-Addressed Data) items identifier by their SAID (Self-Addressing IDentifier). A SAID is a content address derived from a cryptographic digest of the serialization of a data item. The SAID protocol provides a derivation process where the SAID is actually included in the SAD. This makes a SAID self-referential. Verification of a SAD resource obtained by querying a URI that includes the SAD's SAID is accomplished by simply re-deriving the SAID of the SAD in the reply and comparing it to the SAID in the URI. The `sad` URI scheme may be simply expressed as `sad:said` where *said* is replaced with the actual SAID of the referenced SAD item. The mime-type of the returned SAD is determined by the serialization type such as JSON or CBOR for example.

# Basic OOBI

The simplest form of a KERI  OOBI is a namespaced string, a tuple, a mapping, a structured message, or a structured attachment that contains both a KERI AID and a URL (or URI). The OOBI associates the URL with the AID. By convention the URL typically include the word `oobi` in its path to indicate that it is to be used as an OOBI but this is not required. In tuple form this abstractly,

~~~python
(url, aid)
~~~

and concretely,

~~~python
("http://8.8.5.6:8080/oobi", "EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM")
~~~

An OOBI itself is not signed or otherwise authenticatable by KERI but may employ some other Out-Of-Band-Authentication (OOBA) mechanism i.e. non-KERI.

The OOBI is intentionally simplistic to enable very low byte count introductions such as a may be conveyed by a QR code or Data matrix {{QR}}{{DM}}. 


# BADA (Best-Available-Data-Acceptance) Policy

The recipient of an OOBI verifies the OOBI by authenticating the endpoint URL given by the OOBI with respect to an authorization signed by the controller of the AID given by the OOBI. This authorization follows the BADA (Best Available Data Acceptance) policy. The BADA policy provides monotonicity for updates to authentically signed data at rest. This follows best practices for zero-trust computing infrastructure for authentic data. The authorization is usually obtained as a resource in reply to a query to the OOBI URL. Specifically, the service endpoint at the URL responds with a resource that contains the supporting reply messages that are KERI authenticatable. 

## Security Issues

KERI follows a "zero-trust" security model for authentic or securely attributable data. That means that data is signed both in motion and at rest. The primary attack against signed data is a replay attack. In a replay attack, an adversary obtains a copy of data with a verifiable signature and then replays it later. Without some other information, it is difficult for a host to detect that it is indeed a replay or malicious reuse of signed data and not the original use of that data.

To elaborate, there are two primary types of attacks on authentic or authenticatable data-at-rest. The first is a replay attack. The second is a deletion attack. In a replay attack, an adversary keeps a copy of an authentic message or data together with its verifiable signature that has already been created and used by the controller of a KERI AID and then sometime later replays that same message with the signature. A verifier may thereby be fooled into believing that the replay is actually a new message and not a stale message. There are both interactive and non-interactive mitigations to replay attacks. Interactive mitigations use some type of nonce exchanged between updater and updatee. The nonce exchange introduces latency, scalability, and synchronization limitations. Non-interactive mitigations require a monotonic ordering mechanism. Typically monotonic ordering is based on logic rooted in a sequence number or date-time stamp. Because non-interactive mitigations are asynchronous, however, they do not have the latency and scalability limitations of interactive mitigations and are therefore preferred.

The KEL (Key Event Log) of a KERI AID provides such a monotonic ordering mechanism as it employs both a sequence number and digest chaining. For authentic data directly anchored to or determined by a KEL, the relative KEL location determines the monotonic order. This ordering determination includes TEL (Transaction Event Logs) which are monotonically ordered with respect to anchoring seals in the associated KEL {{PTEL_ID}}.  For authentic data not directly anchored or included in a KEL, the relative key state (which is determined by the KEL) may be used in combination with a date-time stamp to ensure monotonic ordering. Finally, for any AID whose key state is fixed, a date-time stamp may be used with appropriate update logic to ensure monotonic ordering. The logic that ensures monotonic ordering is called BADA (Best Available Data Acceptance) and is described later in this section.

A deletion attack is related to a replay attack. Once erased or deleted, a verifier may not be able to detect a replay attack of the deleted data because it has lost a record of the prior play to compare against. To elaborate, once erased, any stale authenticated data acting as authorization may be replayed without detection. This exposes a problem with the GPDR right-to-erasure, which if naively implemented as total erasure, exposes the data controller to a replay attack of erased data. 

The primary mitigation mechanism for deletion attacks is to maintain redundant copies of the signed authentic data. As long as one of the redundant copies has not been deleted then a comparison between the hosts of the redundant copies will expose the deletion attack given there is at least one undeleted copy. The monotonicity of the data is preserved in each copy. The host need merely compare copies. Only the current data item needs to be kept in full in order to support the use of that data.  For protection against replay attacks using stale data, only copies of the digest or signature of the data need to be kept. To reiterate, a replay attack can be detected by comparing the digest or signature (which is a type of digest) of any undeleted copy with the presented data. 

To summarize, authentic data at rest consists of the data item and signature(s). The two primary attacks are replay and deletion. Replay attack mitigation relies on replay monotonicity in data updates. Deletion attack mitigation relies on the redundancy of monotonic data.

## BADA Rules

The BADA (Best-Available-Data-Acceptance) rules apply to any data item stored in a database record whose value is used for some defined purpose. Updates are sourced from the controller of an associated KERI AID. The primary purpose of BADA policy is to enforce monotonicity of the updates with respect to the key state of that associated AID. This primarily protects against replay attacks on the database record. For example, a rollback to an earlier value via replay of an earlier update. An *Update* or change to the database record is *accepted* when it follows the BADA rules (policy) for acceptance. The BADA rules ensure the monotonicity of all updates. 

There are two different mechanisms for the controller of an AID to authorize updates to a given database record. The first is by including a reference to the update in the KEL of the authorizing AID. All entries in a KEL must be signed by the current signing key-pair(s) given by the key-state for that KEL. The second is by signing a date-time stamped update. In this case, the update either includes a reference to the key-state in the authorizing AID's KEL from which the signing key-pair(s) needed to verify the signature is obtained or the AID is ephemeral with a fixed key-state (has a non-transferable derivation code). The rules differ for each of the two mechanisms. 

### KEL Anchored Updates

The *Update* to some record is included in or anchored via a seal to the AID’s key-state in its KEL. In either case, the *Update* is referenced in an event in the KEL of the AID. By virtue of the reference, the Controller of that KEL's AID is authorizing that Update. The record may have a *Prior* value that is being updated or the *Update* serves to create the initial value of the record. *Prior* means the prior record.

~~~
Rules for the acceptance of the *Update*:  (in order of priority)
  Confirm *Update* is anchored or included in AID's KEL.
  
  WHEN Update is anchored in AID's KEL AND...
    IF no *Prior* THEN accept. (always)
    IF *Prior* AND...
      *Update’s* anchor appears later in KEL than the Prior’s anchor THEN accept.  
  Otherwise, do not accept.
~~~

### Signed (Not Anchored) Updates

The *Update* to some record is signed by the controller of the AID, but the *Update* itself is NOT included in or anchored to the AID’s KEL. The record may have a *Prior* value that is being updated or the *Update* serves to create the initial value of the record. *Prior* means the prior record. All date-times are relative to the controller's date-time, NOT the database host's date-time.
There are two cases. These are as follows.

1. Ephemeral AID whose key-state is fixed (no KEL needed)
2. Persistent AID whose key-state is provided by KEL  

~~~
Rules for the acceptance of the *Update*:  (in order of priority)
  Confirm signature on the *Update* verifies against indicated key-state under which signature was made.
  
  WHEN signature verifies AND...
    IF no *Prior* THEN accept (always).
    IF *Prior* THEN ...
      Compare the *Update’s* verified signature key-state against the *Prior's* verified signature key-state.
      IF the *Update’s* key-state appears later in KEL than the *Prior's* key-state THEN accept.
      IF both the *Update’s* and the *Prior's* key-states appear at the same location in KEL AND...
              *Update’s* date-time is later than the *Prior's* date-time THEN accept.           
  Otherwise, do not accept.
~~~

                    
## RUN off the CRUD  

In the conventional client-server database architecture, the database server is responsible for creating records on the behalf of clients and assigning unique identifiers for each record. The server returns to the client the unique record identifier when it creates a record. The server is the source of truth.  But in a zero-trust (end-verifiable) decentralized peer-to-peer architecture, there is no client/server. Every host is a Peer. Each Peer is the source of truth for its own data. Therefore each Peer MUST be able to create unique identifiers for its own data. This inverts the architecture because each Peer creates a unique identifier for each of its own data items and sends that identifier with the data item to the other Peers. Each peer is storing data on the behalf of the other peers. This inverted architecture enables consistent authentic data update policies that work asynchronously across multiple Peers and are replay and deletion attack resistant. Each Peer has an end-verifiable (via signature) monotonically updated view of the data records sourced from the other Peers.

The acronym for the traditional client-server database update policy is CRUD (Create, Read, Update, Delete). The acronym for the new peer-to-peer end-verifiable monotonic update policy is RUN (Read, Update, Nullify). As described above, because the source of truth for each data item is a decentralized controller Peer, a given database hosted by any Peer does not *create* records in the traditional sense of a server creating records for a client. The hosting Peer merely stores a copy of an Update sent out by the source Peer (controller). Thus there is no Create only Update. To clarify, a source Peer updates other Peers. Moreover, non-interactive monotonic update logic that is replay and deletion attack resistant means that a hosting Peer MUST NOT ever delete a record storing the latest version of an Update. Thus there is no Delete. Instead of Delete, Peers Nullify. A Nullify is a special type of Update that indicates that the data in the record is no longer valid without erasing the record that includes a reference to the latest monotonic determining anchor and/or date-time. There are two ways to indicate Nullification. The first is to assign a `null` value to the record. This works for single field records. The second is to assign a Boolean logic flag field that indicates the record has been Nullified. This works for multi-field records.


## Authorized Endpoint Disclosure 

Primary Discovery Data are Endpoints of KERI Components:
Controllers, Agents, Backers (Witness, Registrar), Watchers, Jurors, Judges, Forwarders
Endpoint is URL IP Scheme, Host, Port, Path etc
Data Model for Securely Managing EndPoint Data
Controller (Principal AID) 
Authorizes a Component to act as Player in Role
Player is AID of Component Controller
Role is purpose or function such as Watcher
Zero Trust Data as  Authorization in context of KERI KeyState
ACDC Issue Revoke Reissue model


RUN model (Read, Update, Nullify) 
Anchored or Signed with replay and deletion attack protection

Minimally Sufficient Means
Leverage existing internet but safely, with end-verifiability
Internet DNS/CA is out-of-band w.r.t. KERI security
Use DSN/CA for out-of-band introductions w.r.t. KERI only, not authentication
Use IP addresses (128.187.16.184) for communication 

Non-interactive.
Memory (sequence number, date-time stamp, nullification)
More scalable  

Zero Trust Percolated Discovery

### OOBI KERI Endpoint Authorization (OKEA)

Example application of BADA-RUN

Datetime stamped BADA authorization by CID of EID in Role (Update)
Datetime stamped BADA deauthorization by CID of EID in Role (Nullify)
Datetime stamped BADA authorization by EID of  URL for scheme (Update).
Datetime stamped BADA deauthorization by EID of URL for scheme  (Nullify)  


Upon acceptance of an OOBI the recipient queries the provided URL for proof that the URL is an authorized endpoint for the given AID. The proof format may depend on the actual role of the endpoint. A current witness for an AID is designated in the current key state's latest establishment event in the AID's KEL. Therefore merely replying with the Key State or KEL may serve as proof for a witness introduced by an OOBI. 

Other roles are not part of key state (i.e. are not designated in KEL establishment events) and therefore must be authorized by another mechanism. This typically will be a signed /end/role/ reply message. So the query of the OOBI URL could return as proof an associated authorizing reply message. For example,

Example reply message.

~~~json
{
  "v" : "KERI10JSON00011c_",
  "t" : "rpy",
  "d": "EZ-i0d8JZAoTNZH3ULaU6JR2nmwyvYAfSVPzhzS6b5CM",
  "dt": "2020-08-22T17:50:12.988921+00:00",
  "r" : "/end/role/add",
  "a" :
  {
     "cid":  "EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM",
     "role": "watcher", 
     "eid": "BrHLayDN-mXKv62DAjFLX1_Y5yEUe0vA9YPe_ihiKYHE",
  }
}
~~~



# OOBI Variants

## Multi-OOBI (MOOBI)

An OOBI may include a list of URLs thus simultaneously making an introductory association between the AID and multiple URLs. This would be a multi-OOBI (MOOBI). In general we may refer to a multi-OOBI as a special case of an OOBI without making a named distinction. 


## OOBI as URL (iurl)

URLs provide a namespace which means that the mapping between URL and AID can be combined into one namespaced URL where the AID is in the path component and any other hints such as roles or names are in the query component of the URL. This would be a type of self-describing OOBI URL.  

For example, suppose the  `aid`  is 

~~~python
EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM
~~~

This may be included as a path component of the `url` such as,

~~~python
http://8.8.5.6:8080/oobi/EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM
~~~

This is called an ***OOBI URL*** or `iurl` for short.
This means that all that is needed to bootstrap discovery of a KERI AID is an `iurl`. KERI can leverage the full IP/DNS infra-structure for discovery bootstrap of an `aid` by providing an `iurl` with that `aid` for lookup. 

The aid may act in any of the KERI roles such as `watcher`, `witness`, `juror`, `judge` or `registrar` but is usually a  `controller`. In the later case the url may be a service endpoint provided by one of the supporting components for a given controller. Thus the `aid` in an OOBI may be either a controller id, `cid` or an endpoint provider id, `eid`. The resource at that URL in the OOBI is ultimately responsible for providing that detail but an OOBI as URL may contain hints in the query string for the URL such as a `role` or `name` designation.

~~~python
http://8.8.5.6:8080/oobi/EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM?role=watcher&name=eve

https://example.com/oobi/EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM?role=witness
~~~

When the role is provided in the `iurl`, the AID (EID) of the endpoint provider for that role would be discovered via the proof returned by querying the URL. The proof returned may indicate a different URL for that role. Thus a self-describing OOBI URL may act as a forwarding mechanism. 

To clarify, the minimum information in an OOBI is pair, `(url, aid)`. A compact representation of an OOBI leverages the namespacing of the URL itself to provide the AID. Furthermore, the query string in the URL namespace may contain other information or hints such as the role of the service endpoint represented by the URL or a user-friendly name.  


## Well-Known
An OOBI may be returned as the result of a get request to an IETF RFC 5785  well-known URL. For example,

~~~python
 /.well-known/keri/oobi/EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM
~~~

Where `EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM` is the AID
and the result of the request is either target URL or a redirection to the target URL where the target URL is something like

~~~python
https://example.com/witness/witmer

http://8.8.5.5:8080/witness/witmer

http://10.0.5.15:8088/witness/witmer
~~~

The resultant target URL may be in a different domain or IP address from the well-known resource.


## Full CID and EID
A more verbose version would also include the endpoint role and the AID (EID) of the endpoint provider in a self-describing OOBI URL. For example,

~~~python
https://example.com/oobi/EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM/witness/BrHLayDN-mXKv62DAjFLX1_Y5yEUe0vA9YPe_ihiKYHE

http://8.8.5.6/oobi/EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM/witness/BrHLayDN-mXKv62DAjFLX1_Y5yEUe0vA9YPe_ihiKYHE
~~~


Where 
`EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM` is the AID (CID) of the controller and 

`BrHLayDN-mXKv62DAjFLX1_Y5yEUe0vA9YPe_ihiKYHE` is the AID (EID) of the controller's endpoint provider acting in the role of `witness`.

## KERI Reply Messages as OOBIs

A more verbose expression for an OOBI would be a KERI reply message `rpy` that is unsigned. The route specifies that it is an OOBI so the recipient knows to apply OOBI processing logic to the message. A list of URLs is provided so that it may provide multiple introductions.   For example,

~~~json
{
          "v" : "KERI10JSON00011c_",
          "t" : "rpy",
          "d": "EZ-i0d8JZAoTNZH3ULaU6JR2nmwyvYAfSVPzhzS6b5CM",
          "dt": "2020-08-22T17:50:12.988921+00:00",
          "r" : "/oobi/witness",
          "a" :
          {
             "urls":  ["http://example.com/watcher/watson", "http://example.com/witness/wilma"]
             "aid":  "EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM"
          }
}
~~~

A service endpoint location reply message could also be re-purposed as an OOBI by using a special route path that includes the AID being introduced and optionally the role of the service endpoint provider as follows,

~~~json
{
          "v" : "KERI10JSON00011c_",
          "t" : "rpy",
          "d": "EZ-i0d8JZAoTNZH3ULaU6JR2nmwyvYAfSVPzhzS6b5CM",
          "dt": "2020-08-22T17:50:12.988921+00:00",
          "r" : "/oobi/EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM/watcher",
          "a" :
          {
             "eid": "BrHLayDN-mXKv62DAjFLX1_Y5yEUe0vA9YPe_ihiKYHE",
             "scheme": "http", 
             "url":  "http://example.com/watcher/wilma"
          }
}
~~~

This more verbose approach includes the AID (EID) of the service endpoint provider which may allow a short cut to authenticating the service endpoint.

# Self and Blind Introductions

A bare URL but no AID may be used as a bare OOBI for blind or self-introductions e.g. a blind OOBI or self OOBI. Querying that bare OOBI may return or result in a default target OOBI or default target endpoint reply. This provides a mechanism for self-introduction or blind i.e. self OOBI (SOOBI). Consider examples of bare OOBIs below.


~~~python
http://8.8.5.7:8080/oobi

http://localhost:8080/oobi

http://8.8.5.7:8080/oobi?role=controller&name=eve

http://localhost:8080/oobi?role=controller&name=eve
~~~ 


By default, the result of get request to this OOBI URL could be another OOBI with an AID that is the `self` AID of the node providing the bare OOBI endpoint or the actual authenticatable `self` endpoint with its AID or a default set of authenticatable endpoints. This is useful to bootstrap components in an infrastructure where the target URLs do not use a public DNS address but use instead something more secure like an explicit public IP address or a private IP or private DNS address. A self-introduction provides a bootstrap mechanism similar to a hostname configuration file with the exception that in the OOBI case the AID is not in the configuration file just the bare OOBI URL and the given node queries that bare OOBI to get the target endpoint AID.  This allows bootstrap using bare IP addresses in systems where the IP infrastructure is more securely managed than public DNS or where some other Out-Of-Band-Authentication (OOBA) mechanism is used in concert. 


Because a blind OOBI does not expose an AID, the resultant response when querying the OOBI may depend on other factors such as the source IP of the querier (requester) and/or another out-of-band-authentication (OOBA) mechanism. This supports the private bootstrap of infrastructure. 
Of course one could argue that this is just kicking the can down the road but IP addresses are correlatable and a blind OOBI can leverage IP infrastructure for discovery when used in combination with some other OOBA mechanism without unnecessary correlation.
Onion Routing with Blind OOBI
did-comm with Blind OOBI

This may be especially useful to bootstrap components in an infrastructure where the target URLs do not use a public DNS address but use instead something more secure like an explicit public IP address or a private IP or private DNS address. A self-introduction provides a bootstrap mechanism similar to a hostname configuration file with the exception that in the OOBI case the AID is not in the configuration file just the bare OOBI URL and the given node queries that bare OOBI to get the target endpoint AID.  This allows bootstrap using bare IP addresses in systems where the IP infrastructure is more securely managed than public DNS or where some other Out-Of-Band-Authentication (OOBA) mechanism is used in concert.  Because the OOBI itself does not contain an AID the association of the resultant AID is not provided by the OOBI and the resultant AID's association must be secured by some other mechanism. 

For example, a given indirect mode controller is identified by its AID (CID). The controller must also create witness hosts with endpoints. This means first spinning up witness host nodes and creating witness AIDs (WIDs) for those nodes. Given that these WIDs must be eventually designated in the KEL for the CID, the controller of the CID can confirm using its KEL that the signed endpoint reply provided by a bare OOBI request is indeed signed by the corresponding private keys for a WID designated in its KEL. This means that the only place that the WID must appear is in the KEL and not in all the config files used to boostrap communications between the CID host and its designated WID hosts. Bare OOBIs will do. The redundant configuration information may be a vector for a type of DDOS attack where corrupted inconsistent redundant configuration information results in a failure to boot a system that must be manually fixed. Redundancy for security is best applied in the context of a self-healing or resilient threshold structure that explicitly manages the redundancy as a security mechanism not as un-managed inadvertent redundancy.


Equivalently a bare OOBI (no AID) provides a mechanism for blind introductions, i.e. a blind or bare OOBI (BOOBI). Because the OOBI does not expose an AID, the resultant response when querying the OOBI may depend on other factors such as the source IP of the querier (requester) and/or another out-of-band-authentication (OOBA) mechanism. This supports private bootstrap of infrastructure. Of course one could argue that this is just kicking the can down the road but IP addresses are correlatable and a blind OOBI can leverage IP infrastructure for discovery when used in combination with some other OOBA mechanism without unnecessary correlation.


# OOBI Forwading  


In every case, an OOBI may result in a proof for a different URL than that provided in the OOBI itself. The allows OOBI forwarding so that introductions produced as hard copies such as QR codes do not necessarily become stale. The recipient of the OOBI may choose to accept that proof or not. Ultimately the recipient only treats URLs as valid endpoints when they are fully KERI authenticated. Given that an OOBI result is always KERI authenticated before use in a given role, the worst case from a security perspective is that an OOBI may be part of a DDOS attack but not as part of a service endpoint cache poison attack.



# OOBI with MFA

An OOBI may be augmented with one or more Out-Of-Band Authentications (OOBAs) to minimize the likelihood of a DDOS OOBI attack. A given recipient may require as a precondition to accepting an OOBI one or more  OOBA mechanisms such as text messages, emails, etc that together provide some degree of non-KERI-based security to the OOBI. Thus an OOBI could employ out-of-band (with respect to KERI) multi-factor-authentication (MFA) to preclude any OOBI-based DDOS attacks on KERI.

# KERI OOBI Use in Installation Configuration 

## OOBI Discovery

The main value of an OOBI is that it is compact and is not encumbered by authentication proofs but may be used to kick-start the process of authentication (proving).

One way to pre-configure a vacuous KERI installation is to provide OOBIs in a configuration file. The bootstrap process of the installation then queries the associated URLs to retrieve the KERI authentication proofs (BADA) that then are used to populate its database securely. This simplifies the configuration file.

In contrast, an alternative would be to populate the configuration file with the KERI authentication proofs. But these proofs may be quite verbose and cumbersome and may make the config file somewhat difficult to manage in human-readable/writable form. Furthermore if one already had the proofs one could just pre-populate the database with those proofs. Therefore OOBI based configuration files may be advantageous as either easier to manage or as a viable option when the proofs are not yet available at configuration time.

Furthermore, a clean clone replay restart of a given KERI component is designed to fix any unverified corruption of its associated KELs.
If each component uses OOBIs to retrieve the authentication proofs from other components then all the components will have clean proofs instead of stale proofs. 


## OOBI Response

Each KERI installation may also optionally provide an OOBI permissioning record list associated with each habitat to indicate
which OOBI queries it will respond to.  This may also be inited with
a config file.

# Data OOBI (DOOBI)

# SPED (Speedy Percolated Endpoint Discovery)


# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Security Considerations

OOBIs are out-of-band with respect to the security of the infrastructure to which they provide an introduction. OOBIs assume that any introduced endpoints will be subsequently verified by their associated in-band mechanisms. There are no other security considerations.

# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
