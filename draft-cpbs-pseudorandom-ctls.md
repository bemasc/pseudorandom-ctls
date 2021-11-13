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

A Tweakable Strong Pseudorandom Permutation (TSPRP) is a variable-input-length block cipher that accepts a high-entropy "key" and low-entropy "tweak".  Also known as a "super-pseudorandom permutation" or "wide block cipher".

{::boilerplate bcp14}

# Introduction

## Background

Compact TLS {{!cTLS=I-D.draft-ietf-tls-ctls-04}} is a compact representation of TLS 1.3 (or later), intended for uses where compatibility with previous versions of TLS is not required.  It defines a pre-configuration object called a "template" that contains a profile of the capabilities and behaviors of a TLS server, which is known to both client and server before they initiate a connection.  The template allows both parties to omit information that is irrelevant or redundant, allowing a secure connection to be established while exchanging fewer bits on the wire.

Every cTLS template potentially results in a distinct wire image, with important implications for user privacy and ossification risk.

One interesting consequence of conventional wire formats (i.e. not pseudorandom) is the risk of protocol confusion attacks.  For example, in the NAT Slipstreaming attacks {{SLIPSTREAM}}, a web server causes a browser to send HTTP data that can be confused for another protocol (e.g. SIP) that is processed by a firewall.  Because firewalls are typically focused on attacks arriving from outside the network, malicious payloads sent from a trusted client can trick some firewalls into disabling their own protections.

## Goal

The goal of this extension is to enable two endpoints to agree on a TLS-based protocol whose wire image is purely pseudorandom.

### Requirements

* Protocol confusion attack resistance: Neither party has any influence over the wire format bytes emitted by the other party.  An attacker who controls both parties' plaintext, and has access to all keys, cannot efficiently control any part of the ciphertext.
* Privacy: A third party without access to the template cannot tell whether two connections are using the same pseudorandom cTLS template, or two different pseudorandom cTLS templates.
* Ossification risk: Every byte sent on the underlying transport is pseudorandom to an observer who does not know the cTLS template.
* Efficiency: Zero size overhead and minimal CPU cost.  Support for servers with many cTLS templates, when appropriately constructed.

### Non-requirements

* Efficient support for demultiplexing arbitrary cTLS templates.
* Addressing information leakage in the length and timing of transmissions.

# The Pseudorandom Extension

The cTLS Record Layer protocol is comprised of AEAD-encrypted ciphertext fragments interleaved with plaintext fragments.  Each record is prefixed by a plaintext header, and some records, like those containing the ClientHello and ServerHello, are not encrypted at all.  This extension specifies a transformation of the cTLS bitstream that ensures that all bits written to the wire are pseudorandom.

This transformation proceeds in two phases.  First, each message is transformed.  For handshake messages, the output is guaranteed to be pseudorandom as long as there is sufficient entropy in the `key_share` extension or `random` field of the ClientHello (resp. ServerHello).  For other messages, uniqueness is ensured by the AEAD, and the transformation ensures that unique messages become pseudorandom.

> TODO: Check that the assumptions hold for HelloRetryRequest.  As long as no handshake messages are repeated verbatim, it should be fine, but we need to check whether an active attacker can trigger a replay.

Pseudorandom cTLS also enciphers every record header.  In addition to the header, 16 bytes of the transformed message is enciphered to ensure the input has enough entropy.  (Any AEAD algorithm that can produce smaller ciphertexts is not compatible with this specification.)

## Form

A cTLS template is structured as a JSON object.  This extension is represented by an additional key, "pseudorandom", whose value is an object with two string-valued keys: "suite" (a name from the Pseudorandom cTLS Cipher Suite registry (see {{iana}})) and "key" (a base64-encoded shared secret whose length is specified by the cipher suite).  For example, a cTLS template might contain an entry like:

~~~json
"pseudorandom": {
  "suite": "hctr2-sha256",
  "key": "nx2kEm50FCE...TyOhGOw477EHS"
},
~~~

> TODO: Talk about compatibility.  Pseudorandom isn't backwards-compatible.  Is there even such a thing as a "cTLS extension"?

> TODO: Consider having two keys, one for sending data from client to server and another for sending data from server to client, to align better with the TLS key schedule.  These could be specified explicitly or generated from a single secret by a KDF.

## Cipher suites

Cipher suites used in Pseudorandom cTLS consist of two elements: a Tweakable Strong Pseudorandom Permutation (TSPRP) and a "twist" operation.  These are notated here by the syntax:

~~~
TSPRP-Encipher(key, tweak, message) -> ciphertext
TSPRP-Decipher(key, tweak, ciphertext) -> message
Twist(input) -> twisted
Untwist(twisted) -> input
~~~

> QUESTION: Should we allow a key or tweak for the twist?

The cipher suite specifies the length (in bytes) of its key.  The tweak is a byte string of any length.  Both the TSPRP and "twist" accept any input with length >= 16 bytes.

In order to satisfy the requirements ({{requirements}}), `TSPRP-Encipher(key, tweak, Twist(AEAD-Encrypt(key2, nonce, plaintext)))` must be an Everywhere-Preimage-Resistant hash {{?EPRE=DOI.10.1007/978-3-540-25937-4_24}} of `plaintext` for any AEAD family.

> TODO: Formalize this notion better.

### The "hctr2-sha256" cipher suite

HCTR2 is a fast TSPRP based on AES and a polynomial MAC (closely related to the GMAC used in AES-GCM) (https://eprint.iacr.org/2021/1441).  However, HCTR2 alone is not sufficient for Pseudorandom cTLS.  For example, with knowledge of the keys, it is likely possible to control much of the output of `HCTR2(AES-GCM(plaintext))`.

To provide a suitable cipher suite, we define the "twist" function as

~~~python
hash = SHA256(input[:-16])
twisted = input[:-16] + XOR(input[-16:], hash[:16])
~~~

i.e. XOR-ing the hash of the first `N-16` bytes of input onto the last 16 bytes of input.  `Untwist()` is identical to `Twist()`.

> TODO: Verify the properties of this arrangement.

## Use

The sender first transforms each message as follows:

1. If the sender is the client, let `tweak` be `"client"`, else `"server"`.
2. If this is a datagram transport, append `" datagram"` to the tweak.
3. If this is a handshake message, append `" hs"` to `tweak`.  Otherwise, append the 64-bit sequence number.
4. Append the `profile_id` to `tweak`.
5. Replace the message with `TSPRP-Encipher(key, tweak, Twist(message))`.

Receivers construct the same `tweak`, and compute `Untwist(TSPRP-Decipher(key, tweak, ciphertext))`.

Note: In datagram modes, `message` corresponds to `Handshake.body`.

Design Note: Applying `Twist()` to the handshake messages is unnecessary, but seems likely to simplify implementation.

> OPEN ISSUE: How should we actually form the tweaks?  Can we assume arbitrary length?  Should we add some kind of chaining, within a stream or binding ServerHello to ClientHello?

If this is a handshake message, fragmentation is possible, and additional steps apply:

1. Fragment the message if necessary, ensuring each fragment is at least 16 bytes long.
2. Change the `content_type` of the final fragment to `ctls_handshake_end(TBD)`.

Note: This procedure requires that handshake messages are at least 16 bytes long.  This condition is automatically true in most configurations.

### With Streaming Transports

When used over a streaming transport, Pseudorandom cTLS requires that headers have predictable lengths.  This creates the following limitations:

* If a Connection ID is negotiated, it MUST always be included.
* If the Sequence Number is not suppressed in the template, it MUST always have 16-bit length.

Normally, when TLS runs on top of a streaming transport, Connection IDs are not enabled and Sequence Numbers are omitted, so this is not expected to be a significant limitation.

The sender applies the following transformation before sending each record:

1. Let `hdr_length` be the length of the record header (normally 3 for CTLSCiphertext or 4 for CTLSPlaintext).
2. Let `prefix` be the first `hdr_length + 16` bytes of the record.
3. Set `tweak = "client"` if sent by the client, or `"server"` if sent by the server.
4. If the record is CTLSCiphertext, append the 64-bit Sequence Number to `tweak`.
5. Replace `prefix` with `TSPRP-Encipher(key, tweak, prefix)`.

### With Datagram Transports

Pseudorandom cTLS applies to datagram applications of cTLS without restriction.  If there are multiple records in the datagram, encipherment starts with the last record header and proceeds back-to-front.

Given the inputs:

* `payload`, an entire datagram that may contain multiple cTLS records.
* `connection_id`, the ID expected on incoming CTLSCiphertext records

The recipient deciphers the headers as follows:

1. Let `max_hdr_length = max(16, len(connection_id) + 5)`.  This represents the most data that might be needed to read the DTLS Handshake header ({{Section 5.2 of !DTLS13=I-D.draft-ietf-tls-dtls13-43}}) or the CTLSCiphertext header.
2. Let `index = 0`.
3. While `index != len(payload)`:
    1. Let `prefix = payload[index : min(len(payload), index + max_hdr_length + 16)]`
    2. Let `tweak = "client datagram" + len(payload) + index` if sent by the client, or `"server datagram" + len(payload) + index` if sent by the server.
    3. Replace `prefix` with `TSPRP-Decipher(key, tweak, prefix)`.
    5. Set `index` to the end of this record.

# Plaintext Alerts

Representing plaintext alerts (i.e. CTLSPlaintext messages with `content_type = alert(TBD)`) requires additional steps, because Alert fragments have little entropy.

A standard TLS Alert fragment is always 2 bytes long.  In Pseudorandom cTLS, senders MUST append at least 16 random bytes to any plaintext Alert fragment.  Enciphering and deciphering then proceed identically to other CTLSPlaintext messages.  The recipient MUST remove these bytes before passing the CTLSPlaintext to the cTLS implementation.

Servers SHOULD expand any Alert message following the ClientHello to the same size as their usual ServerHello, and SHOULD send additional random TCP segments or datagrams to match the sizes of subsequent components of their ordinary success response.  Otherwise, an adversary could use probing to learn the allowed lengths of ClientHellos and the fraction of ciphertexts that decipher to valid ClientHellos.

> QUESTION: Are there client-issued Alerts in response to malformed ServerHello?

# Operational Considerations

Pseudorandom cTLS can interfere with the use of multiple profiles on a single server.  To use Pseudorandom cTLS with multiple profiles, servers must use the same TSPRP key and the same lengths of `connection_id`.

Pseudorandom cTLS adds a constant factor computational cost to sending and receiving every record, likely increasing overall CPU intensity by a factor of 2 to 4.

> TODO: Key rotation.  How does it work?  We could possibly use trial decryption, with parsing and profile-id matching as an implicit MAC, but it feels a bit soft.  Does it help if we put a "key ID" in the tweak?

# Security Considerations

Pseudorandom cTLS operates as a layer between cTLS and its transport, so the security properties of cTLS are largely preserved.  However, there are some small differences.

In datagram mode, the `profile_id` and `connection_id` fields allow a server to reject almost all packets from a sender who does not know the template (e.g. a DDoS attacker), with minimal CPU cost.  Pseudorandom cTLS requires the server to apply a decryption operation to every incoming datagram before establishing whether it might be valid.  This operation is O(1) and uses only symmetric cryptography, so the impact is expected to be bearable in most deployments.

A protocol confusion attack can still be mounted by brute force.  An adversary who seeks to pin `N` bits of the ciphertext can do so, but only by performing `2^N` trial encryptions.  This attack appears impractical, as any vulnerability with sufficiently small `N` would also be triggered sporadically by ordinary traffic.  The difficulty is further increased because the attacker can only start trial encryptions after the master secret has been calculated, and must attack each sequence number separately.

> TODO: More precise security properties and security proof.  The goal we're after hasn't been widely considered in the literature so far, at least as far as we can tell.  The basic idea is that the "real" protocol (Pseudorandom cTLS) should be indistinguishable from some "target" protocol that the network is known tolerate.  The assumption is that middleboxes would not attempt to parse packets whose contents are pseudorandom.  (The same idea underlies QUIC's wire encoding format {{!RFC9000}}.)   A starting point might be the formal notion of "Observational Equivalence" (https://infsec.ethz.ch/content/dam/ethz/special-interest/infk/inst-infsec/information-security-group-dam/research/publications/pub2015/ASPObsEq.pdf).

# Privacy Considerations

Pseudorandom cTLS is intended to improve privacy in scenarios where the adversary lacks access to the cTLS template.  However, if the adversary does have access to the cTLS template, and the template does not have a distinctive `profile_id`, Pseudorandom cTLS can reduce privacy, by enabling strong confirmation that a connection is indeed using that template.

# IANA Considerations {#iana}

IANA would have to open a registry for Pseudorandom cTLS Cipher Suites, with "hctr2-sha256" as the first entry.

--- back

# Acknowledgments
{:numbered="false"}

TODO
