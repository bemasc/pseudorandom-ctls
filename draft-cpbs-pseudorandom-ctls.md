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
    ins: C. Patton
    name: Christopher Patton
    organization: Cloudflare, Inc.
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

A Tweakable Strong Pseudorandom Permutation (TSPRP) is a variable-input-length block cipher that is parameterized by a secret "key" and a public "tweak".  Also known as a "super-pseudorandom permutation" or "wide block cipher".

{::boilerplate bcp14}

# Introduction

## Background

Compact TLS {{!cTLS=I-D.draft-ietf-tls-ctls-04}} is a compact representation of TLS 1.3 (or later), intended for uses where compatibility with previous versions of TLS is not required.  It defines a pre-configuration object called a "template" that contains a profile of the capabilities and behaviors of a TLS server, which is known to both client and server before they initiate a connection.  The template allows both parties to omit information that is irrelevant or redundant, allowing a secure connection to be established while exchanging fewer bits on the wire.

Every cTLS template potentially results in a distinct wire image, with important implications for user privacy and ossification risk.

One interesting consequence of conventional wire formats (i.e. not pseudorandom) is the risk of protocol confusion attacks.  For example, in the NAT Slipstreaming attacks {{SLIPSTREAM}}, a web server causes a browser to send HTTP data that can be confused for another protocol (e.g. SIP) that is processed by a firewall.  Because firewalls are typically focused on attacks arriving from outside the network, malicious payloads sent from a trusted client can trick some firewalls into disabling their own protections.

## Goal

The goal of this extension is to enable two endpoints to agree on a TLS-based protocol whose wire image is purely pseudorandom.

### Requirements

* Protocol confusion attack resistance: Neither party has any influence over the bytes emitted by the other party.
* Privacy: A third party without access to the template cannot tell whether two connections are using the same pseudorandom cTLS template, or two different pseudorandom cTLS templates.
* Ossification risk: Every byte sent on the underlying transport is pseudorandom to an observer who does not know the cTLS template.
* Efficiency: Zero size overhead and minimal CPU cost.  Support for servers with many cTLS templates, when appropriately constructed.

### Non-requirements

* Efficient support for demultiplexing arbitrary cTLS templates.
* Addressing information leakage in the length and timing of transmissions.

# The Pseudorandom Extension

## Form

A cTLS template is structured as a JSON object.  This extension is represented by an additional key, "pseudorandom", whose value is an object with at least two string-valued keys: "tsprp" (a name from the TSPRP registry (see {{iana}})) and "key" (a base64-encoded shared secret whose length is specified by the TSPRP).  For example, a cTLS template might contain an entry like:

~~~json
"pseudorandom": {
  "tsprp": "hctr2",
  "key": "nx2kEm50FCE...TyOhGOw477EHS"
},
~~~

> TODO: Talk about compatibility.  Pseudorandom isn't backwards-compatible.  Is there even such a thing as a "cTLS extension"?

> TODO: Consider having two keys, one for sending data from client to server and another for sending data from server to client, to align better with the TLS key schedule.  These could be specified explicitly or generated from a single secret by a KDF.

## Use

The cTLS Record Layer protocol is comprised of AEAD-encrypted ciphertext fragments interleaved with plaintext fragments.  Each record is prefixed by a plaintext header, and some records, like those containing the ClientHello and ServerHello, are not encrypted at all.  The ciphertext fragments are pseudorandom already, so this extension specifies a transformation of the plaintext fragments that ensures that all bits written to the wire are pseudorandom.

Conceptually, the extension sits between the cTLS Record Layer and the underlying transport (e.g. TCP, UDP).  The transformation is based on a TSPRP with the following syntax:

~~~
TSPRP-Encipher(key, tweak, message) -> ciphertext
TSPRP-Decipher(key, tweak, ciphertext) -> message
~~~

The TSPRP specifies the length (in bytes) of the key.  The tweak is a byte string of any length.  The TSPRP uses the key and tweak to encipher the input message, which also may have any length.  The output ciphertext has the same length as the input message.

The Pseudorandom cTLS design assumes that the negotiated AEAD algorithm produces pseudorandom ciphertexts.  This is not a requirement of the AEAD specification {{!RFC5116}}, but it is true of popular AEAD algorithms like AES-GCM and ChaCha20-Poly1305.


Pseudorandom cTLS uses the TSPRP to encipher all plaintext handshake records, including the record headers.  As long as there is sufficient entropy in the `key_share` extension or `random` field of the ClientHello (resp. ServerHello) the TSPRP output will be pseudorandom.

> TODO: Check that the assumptions hold for HelloRetryRequest.  As long as no handshake messages are repeated verbatim, it should be fine, but we need to check whether an active attacker can trigger a replay.

Pseudorandom cTLS also enciphers every record header.  In addition to the header, 16 bytes of the AEAD ciphertext itself is enciphered to ensure the input has enough entropy.  All currently registered AEAD algorithms produce at least this much ciphertext from any input.  Any AEAD algorithm that can produce smaller ciphertexts is not compatible with this specification.

### With Streaming Transports

When used over a streaming transport, Pseudorandom cTLS requires that headers have predictable lengths.  This creates the following limitations:

* If a Connection ID is negotiated, it MUST always be included.
* If the Sequence Number is not suppressed in the template, it MUST always have 16-bit length.

Normally, when TLS runs on top of a streaming transport, Connection IDs are not enabled and Sequence Numbers are omitted, so this is not expected to be a significant limitation.

The transformation performed by the sender takes the following inputs:

* `TSPRP-Encipher()` and `key` from `template.pseudorandom`
* `template.profile_id` from the cTLS template

The sender first constructs any CTLSPlaintext records as follows:

1. Set `tweak = "client hs" + profile_id` if sent by the client, or `"server hs" + profile_id` if sent by the server.
2. Replace the message with `TSPRP-Encipher(key, tweak, message)`.
3. Fragment the message if necessary, ensuring each fragment is at least 16 bytes long.
4. Change the `content_type` of the final fragment to `ctls_handshake_end(TBD)`.

Note: This procedure requires that handshake messages are at least 16 bytes long.  This condition is automatically true in most configurations.

The sender then constructs cTLS records as usual, but applies the following transformation before sending each record:

1. Let `hdr_length` be the length of the record header (normally 3 for CTLSCiphertext or 4 for CTLSPlaintext).
2. Let `prefix` be the first `hdr_length + 16` bytes of the record.
3. Set `tweak = "client"` if sent by the client, or `"server"` if sent by the server.
4. If the record is CTLSCiphertext, append the 64-bit Sequence Number to `tweak`.
5. Replace `prefix` with `TSPRP-Encipher(key, tweak, prefix)`.

> OPEN ISSUE: How should we actually form the tweaks?  Can we assume arbitrary length?  Should we add some kind of chaining, within a stream or binding ServerHello to ClientHello?

### With Datagram Transports

Pseudorandom cTLS applies to datagram applications of cTLS without restriction.  If there are multiple records in the datagram, encipherment starts with the last record header and proceeds back-to-front.

Given the inputs:

* `payload`, an entire datagram that may contain multiple cTLS records.
* `TSPRP-Decipher()` and `key` from `template.pseudorandom`
* `template.profile_id`
* `connection_id`, the ID expected on incoming CTLSCiphertext records

The recipient deciphers the datagram as follows:

1. Let `max_hdr_length = max(16, len(connection_id) + 5)`.  This represents the most data that might be needed to read the DTLS Handshake header ({{Section 5.2 of !DTLS13=I-D.draft-ietf-tls-dtls13-43}}) or the CTLSCiphertext header.
2. Let `index = 0`.
3. While `index != len(payload)`:
    1. Let `prefix = payload[index : min(len(payload), index + max_hdr_length + 16)]`
    2. Let `tweak = "client datagram" + len(payload) + index` if sent by the client, or `"server datagram" + len(payload) + index` if sent by the server.
    3. Replace `prefix` with `TSPRP-Decipher(key, tweak, prefix)`.
    5. Set `index` to the end of this record.

CTLSPlaintext records are subject to an additional decipherment step:

1. Perform fragment reassembly to recover the complete `Handshake.body` ({{Section 5.5 of !DTLS13}}).
2. Let `tweak` be `"client datagram hs" + profile_id + Handshake.msg_type` if sent by the client, or `"server datagram hs" + profile_id + Handshake.msg_type` if sent by the server.
3. Replace `Handshake.body` with `TSPRP-Decipher(key, tweak, Handshake.body)`.

## Optional Keys

### "start-tag"

In some deployments, it may be necessary or valuable to authenticate that a ClientHello was issued with a particular Pseudorandom cTLS configuration.  Merely deciphering the ClientHello, and observing that it parses correctly, does not conclusively prove that it was issued as expected.  It is possible, though not likely, that a random byte sequence could be parsed as a valid cTLS ClientHello.

To require proof that the sender was using a particular Pseudorandom cTLS template, the template MAY include the optional key "start-tag" whose value is an integer `T` in the range `1..32`.  When this key is present, the client MUST prepend `T` zero bytes to the ClientHello before calling `TSPRP-Encipher()` on the ClientHello payload, and the server SHOULD verify that these bytes are zero after calling `TSPRP-Decipher()`.  This arrangement authenticates the TSPRP.  The indicated length in the `Handshake` header is not altered, so this does not reduce the maximum handshake message size.

Start tags can be used to enable rotation of the Pseudorandom cTLS key.  With a tag in place, servers can use trial decryption to identify which key (old or new) is in use for each new connection.  To avoid false matches, values of `T` less than 8 are NOT RECOMMENDED.

# Plaintext Alerts

Representing plaintext alerts (i.e. CTLSPlaintext messages with `content_type = alert(TBD)`) requires additional steps, because Alert fragments have little entropy.

A standard TLS Alert fragment is always 2 bytes long.  In Pseudorandom cTLS, senders MUST append at least 16 random bytes to any plaintext Alert fragment.  Enciphering and deciphering then proceed identically to other CTLSPlaintext messages.  The recipient MUST remove these bytes before passing the CTLSPlaintext to the cTLS implementation.

Servers SHOULD expand any Alert message following the ClientHello to the same size as their usual ServerHello, and SHOULD send additional random TCP segments or datagrams to match the sizes of subsequent components of their ordinary success response.  Otherwise, an adversary could use probing to learn the allowed lengths of ClientHellos and the fraction of ciphertexts that decipher to valid ClientHellos.

> QUESTION: Are there client-issued Alerts in response to malformed ServerHello?

# Operational Considerations

Pseudorandom cTLS can interfere with the use of multiple profiles on a single server.  To use Pseudorandom cTLS with multiple profiles, servers must use the same TSPRP key and the same lengths of `connection_id`.

Pseudorandom cTLS adds a constant, symmetric computational cost to sending and receiving every record, roughly similar to the cost of encrypting a very small record.  The cryptographic cost of delivering small records will therefore be increased by a constant factor, and the computational cost of delivering large records will be almost unchanged.

# Security Considerations

Pseudorandom cTLS operates as a layer between cTLS and its transport, so the security properties of cTLS are largely preserved.  However, there are some small differences.

In datagram mode, the `profile_id` and `connection_id` fields allow a server to reject almost all packets from a sender who does not know the template (e.g. a DDoS attacker), with minimal CPU cost.  Pseudorandom cTLS requires the server to apply a decryption operation to every incoming datagram before establishing whether it might be valid.  This operation is O(1) and uses only symmetric cryptography, so the impact is expected to be bearable in most deployments.

> TODO: More precise security properties and security proof.  The goal we're after hasn't been widely considered in the literature so far, at least as far as we can tell.  The basic idea is that the "real" protocol (Pseudorandom cTLS) should be indistinguishable from some "target" protocol that the network is known tolerate.  The assumption is that middleboxes would not attempt to parse packets whose contents are pseudorandom.  (The same idea underlies QUIC's wire encoding format {{!RFC9000}}.)   A starting point might be the formal notion of "Observational Equivalence" (https://infsec.ethz.ch/content/dam/ethz/special-interest/infk/inst-infsec/information-security-group-dam/research/publications/pub2015/ASPObsEq.pdf).

# Privacy Considerations

Pseudorandom cTLS is intended to improve privacy in scenarios where the adversary lacks access to the cTLS template.  However, if the adversary does have access to the cTLS template, and the template does not have a distinctive `profile_id`, Pseudorandom cTLS can reduce privacy, by enabling strong confirmation that a connection is indeed using that template.

# IANA Considerations {#iana}

We assume the existence of an IANA registry of Strong Tweakable Pseudorandom Permutations (TSPRPs).  However, no such registry exists at present.  This draft is blocked until someone documents and registers a suitable TSPRP algorithm.

--- back

# Acknowledgments
{:numbered="false"}

TODO
