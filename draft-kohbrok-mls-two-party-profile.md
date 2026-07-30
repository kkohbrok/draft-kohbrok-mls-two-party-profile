---
title: "A two-party profile for MLS"
abbrev: "2PMLS"
category: info

docname: draft-kohbrok-mls-two-party-profile-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Messaging Layer Security"
keyword:
 - handshake
 - key exchange
venue:
  group: "Messaging Layer Security"
  type: "Working Group"
  mail: "mls@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/mls/"
  github: "kkohbrok/draft-kohbrok-mls-two-party-profile"
  latest: "https://kkohbrok.github.io/draft-kohbrok-mls-two-party-profile/draft-kohbrok-mls-two-party-profile.html"

author:
 -
    fullname: Konrad Kohbrok
    organization: Phoenix R&D
    email: konrad@ratchet.ing
 -
    fullname: Raphael Robert
    organization: Phoenix R&D
    email: ietf@raphaelrobert.com

contributor:

-
    name: Russ Housley
    organization: Vigil Security
    email: housley@vigilsec.com

normative:
  RFC9420:
  I-D.ietf-mls-extensions:

informative:
  I-D.ietf-mls-pq-ciphersuites:

...

--- abstract

TODO Abstract


--- middle

# Introduction

Messaging Layer Security (MLS) {{RFC9420}} is primarily designed to be a
continuous group key agreement (and messaging) protocol. This document explores
the special case of groups of two and thus MLS's use as a (non-group) continuous
key agreement protocol with a focus on the use in synchronous scenarios.

The two-party profile of MLS described in this document can, for example, be
used as a replacement for other key exchange protocols that don't provide
post-compromise security and/or post-quantum security. Post-quantum security is
available when the profile is used with a suitable post-quantum cipher suite,
such as one defined in {{I-D.ietf-mls-pq-ciphersuites}}. This is the case with
the key exchange components for many secure channel protocols today.

TODO: For now, this document specifies a simple two party profile based on
vanilla MLS that assumes synchronous communication and a reliable transport. In
the future, we should explore the asynchronous case and add a more specialized
version that trims unnecessary things like signatures in key update messages,
etc.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document uses the TLS presentation language as modified by {{Section 2.1
of RFC9420}} to describe the structure of protocol messages.

## Two-party profile component {#component}

This document defines the `two_party_profile` application component using the
Safe Application Interface of {{I-D.ietf-mls-extensions}}. Its component ID is
TBD1 (see {{iana}}). The component is used with Safe Additional Authenticated
Data (AAD) and MAY be used with the safe exporter.

An implementation using this profile MUST include the `two_party_profile`
component ID in the `ComponentsList` values of both the `app_components` and
`safe_aad` components in the `app_data_dictionary` extension of every LeafNode
it uses with this profile. The group creator MUST include an
`app_data_dictionary` extension in the GroupContext and MUST include the
`two_party_profile` component ID in the `ComponentsList` values of both its
`app_components` and `safe_aad` components.

A client processing a KeyPackage for this profile MUST verify that its LeafNode
advertises these component requirements. A client joining a group MUST verify
that the GroupContext requires them. A member processing a Commit with an
UpdatePath MUST verify that the UpdatePath LeafNode continues to advertise
them.

The following values identify the post-establishment messages defined by this
profile:

~~~ tls
enum {
  reserved(0),
  connection_update(1),
  resumption_request(2),
  resumption_response(3),
  epoch_key_update(4),
  (255)
} TwoPartyMessageType;
~~~

Each MLSMessage created for a ConnectionUpdate, ResumptionRequest, or
ResumptionResponse, as well as each EpochKeyUpdate application message, MUST
contain a SafeAADItem for the `two_party_profile` component. The
`aad_item_data` of that item MUST contain the TLS presentation language
encoding of the TwoPartyMessageType value corresponding to the purpose for
which the MLSMessage was created. A receiver MUST verify the value before
processing the message. This allows a receiver to distinguish messages whose
MLS payloads otherwise have the same encoding.

The message type is authenticated as part of the MLSMessage and identifies the
purpose for which that MLSMessage was created. It MUST NOT be changed when a
pending MLSMessage is retransmitted during resumption. {{resumption}} defines
how this rule applies to a pending MLSMessage carried in a ResumptionRequest.

# Protocol overview {#protocol-overview}

The synchronous case assumes that both parties are online. The protocol
additionally assumes that the underlying transport delivers messages reliably
and in order while a connection is active, and that messages sent over an
interrupted connection are no longer delivered once resumption of that
connection has begun. How the parties detect an interruption is out of scope
for this document and typically depends on the transport.

The party sending the first message is the initiator and the other party the
responder. The protocol can be split into three phases.

1. Initial key agreement
2. Continuous key agreement
3. Resumption

In Phase 1, the initiator and responder exchange messages until they agree on a
shared key and thus enter Phase 2.

In Phase 2, both parties can perform key-updates to achieve forward-secrecy (FS)
and post-compromise security (PCS). To avoid de-synchronization, both parties
have to await confirmation of each update by the other party before they can
perform another one. This phase continues until the connection between the
parties is interrupted.

Phase 3 allows either party to resume the connection. During resumption,
initiator and responder exchange messages to renew their key material before
they (re-)enter Phase 2.

The initiator and responder roles are assigned during Phase 1 and re-assigned
whenever the connection is resumed in Phase 3. The roles assigned during Phase
1 are additionally referred to as the initial initiator and the initial
responder. Both parties MUST persist their initial role for the lifetime of
the group, since it is used to resolve message collisions during resumption
(see {{resumption}}).

While the synchronous two-party case is significantly simpler when it comes to
the responsibilities of the MLS Delivery Service, it still requires both parties
to interface with an Authentication Service (AS) to validate both initial
credentials and any credential updates.

A higher-level protocol using this profile MAY export key material with the MLS
exporter defined in {{Section 8.5 of RFC9420}} or with the safe exporter defined
in {{I-D.ietf-mls-extensions}}. The higher-level protocol is responsible for
defining the exporter inputs and how the resulting key material is used. See
{{Section 8.5 of RFC9420}} for guidance on the use of exported key material.

## Protocol states and error handling {#protocol-states}

At any point in the protocol, each party is in one of the following states:

Awaiting ClientHello:
: The responder has accepted a connection and waits for a ClientHello. It has
  not yet created group state.

Awaiting ServerHello:
: The initiator has sent a ClientHello and waits for the corresponding
  ServerHello.

Synced:
: The party has no pending commit and may send a new ConnectionUpdate. Its peer
  may still be in the previous epoch while waiting to receive an EpochKeyUpdate
  that this party sent.

Awaiting EpochKeyUpdate:
: The party has sent a commit as part of a ConnectionUpdate or a
  ResumptionResponse and waits for the corresponding EpochKeyUpdate.

Awaiting ResumptionResponse:
: The party has sent a ResumptionRequest and waits for the corresponding
  ResumptionResponse.

{{initial-key-agreement}}, {{continuous-key-agreement}}, and {{resumption}}
define how a party in a given state processes each message. If a party
receives a message that those sections do not explicitly permit in its current
state, or if it fails to validate a received message, this is a fatal error.
The party MUST terminate the connection and delete any group state associated
with it. Group state discarded due to a fatal error MUST NOT be used for
resumption. Communication can only be re-established through a new run of the
initial key agreement.

{{state-machine}} shows the resulting state machine in graphical form.

# Initial key agreement {#initial-key-agreement}

~~~ tls
struct {
  MLSMessage key_package;
} ClientHello;

struct {
  MLSMessage welcome;
} ServerHello;
~~~

The initiator starts the key agreement part of the protocol by creating a
KeyPackage and sending a ClientHello to the responder. It then enters the
Awaiting ServerHello state, in which the ServerHello is the only permitted
message.

The responder starts in the Awaiting ClientHello state, in which the
ClientHello is the only permitted message.

The responder MUST validate the KeyPackage as specified in {{Section 10.1 of
RFC9420}}. It MUST verify that the KeyPackage advertises the component
requirements in {{component}}. It then checks whether it supports the offered
cipher suite and whether the initiator has sufficient capabilities to support
the connection.

The responder MUST interface with the AS to ensure that the credential in the
KeyPackage is valid.

The responder then locally creates an MLS group and commits to an Add proposal
containing the initiator's KeyPackage. The responder sends the resulting Welcome
message back to the initiator as part of a ServerHello message and enters the
Synced state.

The initiator uses the Welcome to create its local group state. The initiator
then inspects the group state. It MUST verify that the group contains exactly
two non-blank leaves, that one leaf corresponds to the KeyPackage it sent, and
that the other leaf belongs to the responder. It MUST also verify that the
GroupContext contains the component requirements in {{component}} and interface
with the AS to ensure that the credential of the responder is valid. The
initiator then enters the Synced state.

If the connection is interrupted before the initial key agreement completes,
the parties MUST abandon the partial exchange and delete any group state
created solely for it. Communication can only be re-established through a new
run of the initial key agreement starting with a new ClientHello.

# Continuous key agreement {#continuous-key-agreement}

~~~ tls
struct {
  MLSMessage update;
} ConnectionUpdate;

struct {
  uint64 epoch;
} EpochKeyUpdate;
~~~

An EpochKeyUpdate is encoded as the `application_data` of an MLS application
message. The application message is sent in the new epoch and carries the
`epoch_key_update` message type in Safe AAD as specified in {{component}}.

After the initial key agreement phase, both parties can send an MLS commit with
UpdatePath to update their key material. To ensure that both agree on the order
of such commits and thus on the currently used key material, they must follow
the following rules. The initiator and responder roles referenced in these
rules are the current roles, i.e. the roles assigned during the most recent run
of Phase 1 or Phase 3.

Every Commit sent as part of a ConnectionUpdate, ResumptionRequest, or
ResumptionResponse MUST contain an empty `proposals` vector and a populated
UpdatePath. A receiver MUST reject a Commit that does not satisfy these
requirements.

- A party in the Synced state MAY send a ConnectionUpdate containing a commit
  with UpdatePath. It then enters the Awaiting EpochKeyUpdate state.
- A party in the Synced state that receives a ConnectionUpdate MUST validate
  and apply the commit and respond with an EpochKeyUpdate, where `epoch` is the
  group's new epoch. It remains in the Synced state.
- If the initiator receives a ConnectionUpdate in the Awaiting EpochKeyUpdate
  state, it MUST ignore the ConnectionUpdate and remain in the Awaiting
  EpochKeyUpdate state.
- If the responder receives a ConnectionUpdate in the Awaiting EpochKeyUpdate
  state, it MUST drop its locally pending commit and then process the
  ConnectionUpdate as if it were in the Synced state. It thereby enters the
  Synced state.
- A party in the Awaiting EpochKeyUpdate state that receives an EpochKeyUpdate
  MUST decrypt and authenticate the application message using the group state
  resulting from its pending commit. It MUST check that the Safe AAD identifies
  an EpochKeyUpdate and that `epoch` matches the epoch created by its pending
  commit. If both checks succeed, the party MUST make that group state current
  and enter the Synced state. Otherwise, this is a fatal error (see
  {{protocol-states}}).
- A party that responds to a commit with an EpochKeyUpdate MUST start using the
  key material of the new epoch after sending the EpochKeyUpdate.
- A party that sends a commit MUST wait until it receives the corresponding
  EpochKeyUpdate before it starts using the key material of the new epoch.

In addition, a party in the Synced or Awaiting EpochKeyUpdate state may receive
a ResumptionRequest at any time. Its processing is defined in {{resumption}}.

OPEN QUESTION: We may want to allow inclusion of proposals in the future.

# Resumption {#resumption}

Either party may resume a previously interrupted protocol session based on that
session's group state. The party initiating the resumption becomes the
initiator for the resumed session and the other party the responder. The
initial roles (see {{protocol-overview}}) remain unchanged.

~~~ tls
struct {
  MLSMessage commit;
} ResumptionRequest;

struct {
  MLSMessage commit;
} ResumptionResponse;
~~~

The initiator creates a ResumptionRequest, sends it to the responder, and
enters the Awaiting ResumptionResponse state. If the initiator has a pending
commit, i.e. if it was in the Awaiting EpochKeyUpdate or Awaiting
ResumptionResponse state when the connection was interrupted, the `commit`
field MUST contain that pending commit. Otherwise, the `commit` field MUST
contain a fresh commit with UpdatePath. A fresh commit carries the
`resumption_request` message type in Safe AAD. A pending commit retains its
original message type: `connection_update`, `resumption_request`, or
`resumption_response`.

The parties do not need to agree on whether the connection was interrupted: a
party may receive a ResumptionRequest in the Synced, Awaiting EpochKeyUpdate,
or Awaiting ResumptionResponse state. A party that receives a
ResumptionRequest MUST treat the previous connection as interrupted and MUST
NOT send any further messages over it.

Before processing the commit in a ResumptionRequest in any state, a party MUST
verify that its Safe AAD message type is `resumption_request`,
`connection_update`, or `resumption_response`. The latter two values identify
a pending ConnectionUpdate or ResumptionResponse retransmitted for resumption.

A party that receives a ResumptionRequest in the Synced or Awaiting
EpochKeyUpdate state MUST process the commit in the ResumptionRequest as
follows:

- If the commit is identical to the last commit the receiver applied, the
  receiver MUST NOT apply it again and MUST drop its own pending commit, if
  it has one. This occurs when the connection was interrupted after the
  receiver applied the commit, but before the message confirming it reached
  the peer.
- If the receiver has a pending commit and the received commit builds on the
  epoch created by that pending commit, the receiver MUST first apply its
  pending commit and MUST then validate and apply the received commit. This
  occurs when the peer applied the receiver's pending commit, but the message
  confirming it was lost. The received commit only validates against a group
  state that includes the pending commit and thereby confirms it.
- Otherwise, the receiver MUST drop its pending commit, if it has one, and
  MUST validate and apply the received commit.

To recognize the first case, both parties MUST retain the last commit message
they applied, or a collision-resistant hash of it.

If a party receives a ResumptionRequest in the Awaiting ResumptionResponse
state, it has a pending commit from its own ResumptionRequest. It MUST classify
the received commit before resolving a collision:

- If the received commit is identical to the last commit the receiver applied,
  the receiver MUST process it according to the first rule above.
- If the received commit builds on the epoch created by the receiver's pending
  commit, the receiver MUST process it according to the second rule above.
- Otherwise, the receiver MUST verify that the received commit builds on its
  current epoch. If it does not, this is a fatal error. If it does, the
  received commit and the receiver's pending commit conflict. The receiver
  resolves the conflict based on its initial role:

  - The initial initiator MUST ignore the received commit and remain in the
    Awaiting ResumptionResponse state.
  - The initial responder MUST drop its pending commit and validate and apply
    the received commit.

Whenever a receiver processes a ResumptionRequest rather than ignoring it, the
receiver MUST create a fresh commit with UpdatePath, carrying the
`resumption_response` message type in Safe AAD, and send it as part of a
ResumptionResponse. Since this commit requires confirmation like any other, the
receiver enters the Awaiting EpochKeyUpdate state and the rules of
{{continuous-key-agreement}} apply from there.

A party that receives a ResumptionResponse in the Awaiting ResumptionResponse
state MUST first apply its pending commit, i.e. the commit it sent as part of
its ResumptionRequest. It MUST then validate and apply the commit in the
ResumptionResponse and respond with an EpochKeyUpdate, where `epoch` is the
group's new epoch. It then enters the Synced state.

As a result, if both parties initiate a resumption at the same time and their
commits conflict, the resumed session continues with the initial initiator as
the current initiator and the initial responder as the current responder.

After ignoring a ResumptionRequest, the initial initiator may be waiting for a
ResumptionResponse that never arrives, for example if its own ResumptionRequest
or the corresponding ResumptionResponse was lost in a further interruption.
Recovery from this situation relies on the initial initiator detecting the
interruption and initiating resumption again.

# Security Considerations

TODO: A future version of this document will provide a more complete security
analysis.

## EpochKeyUpdate authentication

An EpochKeyUpdate is an MLS application message sent under the new epoch's
keys. Its Safe AAD identifies it as an EpochKeyUpdate for this profile. The
sender of the Commit authenticates and decrypts the message using the group
state resulting from its pending Commit before making that state current. This
binds the acknowledgement to the new epoch and prevents a party that does not
know the new epoch's keys from forging it.


# IANA Considerations {#iana}

IANA is requested to register the following entry in the "MLS Component
Types" registry defined by {{I-D.ietf-mls-extensions}}:

Value:
: TBD1

Name:
: two_party_profile

Where:
: AD, ES

Recommended:
: N

Reference:
: This document


--- back

# Protocol state machine {#state-machine}

This appendix shows the protocol as a state machine. It is informative. The
normative rules are those in {{initial-key-agreement}},
{{continuous-key-agreement}}, and {{resumption}}. Transitions are labeled with
the triggering event and, after a slash, the resulting actions. Transitions
that only apply to the party holding a particular role are marked with that
role in parentheses. Fatal errors ({{protocol-states}}) are omitted from the
diagrams: in every state, receiving a message that no transition of that state
covers terminates the connection.

{{fig-establishment}} shows the initial key agreement
({{initial-key-agreement}}) and continuous key agreement
({{continuous-key-agreement}}) phases.

~~~ aasvg
                          START
                            |
            +---------------+-------------------+
            |                                   |
            | send ClientHello                  | accept connection
            v                                   v
  +--------------------+              +--------------------+
  |      AWAITING      |              |      AWAITING      |
  |     SERVERHELLO    |              |     CLIENTHELLO    |
  +--------------------+              +--------------------+
            |                                   |
            | recv ServerHello                  | recv ClientHello /
            |                                   | send ServerHello
            +----------------+------------------+
                             |
                             v
    +---------------------------------------------------+
    |                       SYNCED                      |--+
    |                                                   |<-+
    +---------------------------------------------------+
       |                  ^                ^     recv ConnectionUpdate /
       |                  |                |     send EpochKeyUpdate
       | send             | recv           | recv
       | Connection-      | EpochKeyUpdate | ConnectionUpdate
       | Update           | / apply        | (as responder) /
       |                  | pending commit | drop pending commit,
       |                  |                | apply commit,
       |                  |                | send EpochKeyUpdate
       v                  |                |
    +---------------------------------------------------+
    |               AWAITING EPOCHKEYUPDATE             |--+
    |                                                   |<-+
    +---------------------------------------------------+
                                                recv ConnectionUpdate
                                                (as initiator) / ignore
~~~
{: #fig-establishment title="Initial and continuous key agreement"}

The transitions that abandon an interrupted initial key agreement and return
to START are omitted from {{fig-establishment}}.

{{fig-resumption}} shows the resumption phase ({{resumption}}). The Synced and
Awaiting EpochKeyUpdate states are the same states as in
{{fig-establishment}}, and the transitions shown there remain available. The
transition labels are listed below the diagram.

~~~ aasvg
        +--------------------------------------+
  +---->|                SYNCED                |---------+
  |     +--------------------------------------+         |
  |        |                                             |
  |        | (1)                                         |
  |        v                                             |
  |     +--------------------------------------+         |
  |     |                                      |--+      |
  |     |        AWAITING EPOCHKEYUPDATE       |  | (1)  | (2)
  |     |                                      |<-+      |
  |     +--------------------------------------+         |
  |        |                    ^                        |
  |        | (2)                | (3)                    |
  |        v                    |                        |
  |     +--------------------------------------+         |
  |     |                                      |<--------+
  |     |      AWAITING RESUMPTIONRESPONSE     |--+
  |     |                                      |<-+ (4), (6)
  |     +--------------------------------------+
  |        |
  |        | (5)
  |        |
  +--------+
~~~
{: #fig-resumption title="Resumption"}

(1)
: recv ResumptionRequest / process the commit as described in {{resumption}},
  send ResumptionResponse

(2)
: connection interrupted / send ResumptionRequest containing the pending
  commit, or a fresh commit if there is none

(3)
: recv ResumptionRequest / process the commit as described in {{resumption}},
  send ResumptionResponse

(4)
: recv conflicting ResumptionRequest (as initial initiator) / ignore

(5)
: recv ResumptionResponse / apply pending commit, apply commit in the
  ResumptionResponse, send EpochKeyUpdate

(6)
: connection interrupted / retransmit ResumptionRequest containing the pending
  commit

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
