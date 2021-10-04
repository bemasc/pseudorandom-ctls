---
title: "The Pseudorandom Extension for cTLS"
abbrev: "Pseudorandom cTLS"
docname: draft-cpbs-pseudorandom-ctls-latest
category: exp

ipr: trust200902
area: Security
workgroup: TLS WG
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: B. Schwartz
    name: Benjamin Schwartz
    organization: Google LLC
    email: bemasc@google.com
 -
    ins: C. J. Patton
    name: Christopher Patton
    organization: Cloudflare
    email: cpatton@cloudflare.com

normative:
  RFC2119:

informative:
  SLIPSTREAM:
    target: https://samy.pl/slipstream/
    title: NAT Slipstreaming v2.0


--- abstract

This draft describes a cTLS extension that allows each party to emit a purely pseudorandom bitstream.

--- middle

# Conventions and Definitions

The contents of a two-party protocol as perceived by a third party are called the "wire image".

A Strong Tweakable Pseudorandom Permutation (STPRP) is a variable-input-length block cipher that accepts a high-entropy "key" and low-entropy "tweak".

{::boilerplate bcp14}

# Introduction

## Background

Compact TLS (cTLS) is a compact representation of TLS 1.3 (or later), intended for uses where compatibility with previous versions of TLS is not required {{!cTLS=I-D.draft-ietf-tls-ctls}}.  It defines a pre-configuration object called a "template" that contains a profile of the capabilities and behaviors of a TLS server, which is known by both client and server before they initiate a connection.  The template allows both parties to omit information that is irrelevant or redundant, allowing secure connection setup while exchanging less information.

Every cTLS template potentially results in a distinct wire image, with important implications for user privacy and ossification risk.

One interesting consequence of protocols with a nontrivial wire image is the risk of protocol confusion attacks.  For example, in the NAT Slipstreaming attacks {{SLIPSTREAM}}, a web server causes a browser to send HTTP data that can be confused for another protocol (e.g. SIP) that is processed by a firewall.  Because firewalls are typically focused on attacks arriving from outside the network, data sent by a trusted client can trick some firewalls into disabling their own protections.

## Goal

The goal of this extension is to enable two endpoints to agree on a TLS-based protocol whose wire image is purely pseudorandom.

### Requirements

* Ossification and protocol confusion: Each party must be able to prove that every byte they send on the underlying transport is pseudorandom to an observer who does not know the cTLS template.
* Privacy: A third party must not be able to determine which of two cTLS templates was in use on a given connection, if both templates use this extension.
* Efficiency: Zero size overhead and minimal CPU cost.

### Non-requirements

* Efficient support for demultiplexing on servers that use many distinct cTLS templates.
* Addressing information leakage in the length and timing of transmissions.

# The Pseudorandom Extension

## Form

A cTLS template is structured as a JSON object.  This extension is represented by an additional key, "pseudorandom", whose value is an object with two string-valued keys: "stprp" (a name from the STPRP registry (see {{iana}})) and "key" (a base64-encoded shared secret).  For example, a cTLS template might contain an entry like:

```json
"pseudorandom": {
  "stprp": "aes-128-cbc-mask-cbc",
  "key": "nx2kEm50FCE...TyOhGOw477EHS"
},
```

> QUESTION: Can we come up with a better name than "pseudorandom"?

## Use

Pseudorandom cTLS transforms the cTLS Record Layer into a pseudorandom byte sequence.  Conceptually, it sits between the cTLS Record Layer and the underlying transport (e.g. TCP, UDP).  The transformation is based on an STPRP represented by this syntax:

```
STPRP(key, tweak, message) -> ciphertext
Inverse-STPRP(key, tweak, ciphertext) -> message
```

The Pseudorandom cTLS design assumes that the negotiated AEAD cipher produces purely pseudorandom ciphertext.  This is not strictly a requirement of the AEAD specification, but it is true of all currently registered AEAD algorithms.

Pseudorandom cTLS applies the STPRP to blocks containing the header and at least as much ciphertext as the AEAD algorithm's authentication strength (i.e. the tag length).  This ensures that the header becomes pseudorandom.

When transforming handshake records, Pseudorandom cTLS first applies the STPRP to the entire handshake message.  As long as there is sufficient entropy in the `key_share` or `Random`, the STPRP output will be pseudorandom.

### With Streaming Transports

When used over a streaming transport, Pseudorandom cTLS requires that headers have a fixed length.  This creates the following limitations:

* If a Connection ID is negotiated, it MUST always be included.
* If the Sequence Number is not suppressed in the template, it MUST always have 16-bit length.

Normally, Connection IDs and Sequence Numbers are not used with streaming transports, so this is not expected to be a significant limitation.

Transformation, performed by the sender, takes the following inputs:

* `STPRP()` and `key` from `template.pseudorandom`
* `hdr_length`, the length of the cTLS Unified Header (normally 3)
* `tag_length`, the minimum size of the AEAD output (normally 16)
* `template.profile_id` and `template.random`, from the cTLS template

The sender transforms each cTLS record as follows:

1. If the record is CTLSPlaintext, transform its `fragment` as follows:
  a. Set `tweak = "client hs" + profile_id` if sent by the client, or `"server hs" + profile_id` if sent by the server.
  b. Replace `fragment` with `STPRP(key, tweak, fragment)`.
2. Transform the record as follows
  a. Let `top` be the first `hdr_length + tag_length` bytes of the record.
  b. Let `tweak_tag = is_handshake ? profile_id : sequence_number`, using the record's full 64-bit sequence number.
  c. Set `tweak = "client" + tweak_tag` if sent by the client, or `"server" + tweak_tag` if sent by the server.
  d. Replace `top` with `STPRP(key, tweak, top)`.

> QUESTION: How should we define `sequence_number` here?

Note: This requires that cTLS handshake messages always have length at least `hdr_length + tag_length - (len(profile_id) + 2)`.  In the unlikely event that this condition is not met naturally, senders MUST add padding to their handshake messages. 

> TODO: How should we actually form the tweaks?  Assuming they need to be fixed-length, can we avoid using a hash?  Should we add some kind of chaining, within a stream or binding ServerHello to ClientHello?

### With Datagram Transports

Pseudorandom cTLS applies to datagram applications of cTLS without restriction.  In this case, it's easier to specify the inverse transformation applied by the recipient.

Given the inputs:

* `payload`, an entire datagram that may contain multiple cTLS records.
* `STPRP()` and `key` from `template.pseudorandom`
* `template.profile_id`
* `connection_id`, the ID expected on incoming CTLSCiphertext records
* `tag_length`, the minimum size of the AEAD output (normally 16)

1. Let `max_hdr_length = max(len(profile_id) + 5, len(connection_id) + 5)`.  This represents the most data that might be needed to read the type and length of either record type.
2. Let `index = 0`
3. While `index != len(payload)`:
  a. Let `top = payload[index : min(len(payload), index + max_hdr_length + tag_length)]`
  b. Let `tweak = "client datagram" + len(payload) + index` if sent by the client, or `"server datagram" + len(payload) + index` if sent by the server.
  c. Replace `top` with `Inverse-STPRP(key, tweak, top)`
  d. If `top[0] == ctls_handshake`
    i. Let `tweak` be `"client datagram hs" + profile_id + len(payload) + index` if sent by the client, or `"server datagram hs" + profile_id + len(payload) + index` if sent by the server.
    i. Replace `CTLSPlaintext.fragment` with `Inverse-STPRP(key, tweak, fragment)`.
  e. Set `index` to the end of this record.

> TODO: Simplify if cTLS removes varints.

# Handling failures

TODO: Describe behavior upon receiving nonsense to avoid alert-based attacks.

# Operational Considerations

Pseudorandom cTLS can interfere with the use of multiple profiles on a single server.  To use Pseudorandom cTLS with multiple profiles, servers must use the same STPRP key and the same lengths of `profile_id` and `connection_id`.

Pseudorandom cTLS adds a constant, symmetric computational cost to sending and receiving every record, roughly similar to the cost of encrypting a very small record.  The cryptographic cost of delivering small records will therefore be increased by a constant factor, and the computational cost of delivering large records will be almost unchanged.

> TODO: Talk about compatibility.  Pseudorandom isn't backwards-compatible.  Is there even such a thing as a "cTLS extension"?

> TODO: Key rotation.  How does it work?  If the profile_id were longer we could possibly use it as a MAC for key rotation by trial decryption, but at 32 bits it's not really long enough.

# Security Considerations

Pseudorandom cTLS operates as a layer between cTLS and its transport, so the security properties of cTLS are largely preserved.  However, there are some small differences.

In datagram mode, the `profile_id` and `connection_id` fields allow a server to reject almost all packets from a sender who does not know the template (e.g. a DDoS attacker), with minimal CPU cost.  Pseudorandom cTLS requires the server to apply a decryption operation to every incoming datagram before establishing whether it might be valid.  This operation is O(1) and uses only symmetric cryptography, so the impact is expected to be bearable in most deployments.

# Privacy Considerations

Pseudorandom cTLS is intended to improve privacy in scenarios where the adversary lacks access to the cTLS template.  However, if the adversary does have access to the cTLS template, Pseudorandom cTLS can reduce privacy, by enabling strong confirmation that a connection is indeed using that template.

# IANA Considerations {#iana}

We assume the existence of an IANA registry of Strong Tweakable Pseudorandom Permutations (STPRPs).  However, no such registry exists at present.  This draft is blocked until someone documents and registers a suitable STPRP algorithm.

--- back

# Acknowledgments
{:numbered="false"}

TODO