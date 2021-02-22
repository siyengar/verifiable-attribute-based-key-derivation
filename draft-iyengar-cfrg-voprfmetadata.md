---
title: Verifiable Oblivious Pseudo-Random Functions with Public Metadata
abbrev: "TODO - Abbreviation"
docname: draft-iyengar-cfrg-voprfmetadata-latest
category: info

ipr: trust200902
area: irtf
workgroup: cfrg
keyword: Internet-Draft

stand_alone: yes
smart_quotes: no
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: S. Iyengar
    name: Subodh Iyengar
    organization: Facebook
    email: subodh@fb.com

normative:
  RFC2119:

informative:
  PrivateStats:
    title: PrivateStats, De-Identified Authenticated Logging at Scale
    target: https://research.fb.com/privatestats
    date: false
    authors:
      -
        ins: S.Iyengar, A. Raghunathan, P. Mohassel, et. al.
        org: Facebook
  Camenisch97:
    title: Proof Systems for General Statements about Discrete Logarithms
    target: https://crypto.ethz.ch/publications/files/CamSta97b.pdf
    date: false
    authors:
      -
        ins: J. Camenisch, M. Stadler
  Pythia15:
    title: The Pythia PRF Service
    target: https://eprint.iacr.org/2015/644.pdf
    date: false
    authors:
      -
        ins: A. Everspaugh et, al.
  pOPRF18:
    title: Threshold Partially-Oblivious PRFs with Applications to Key Management
    target: https://eprint.iacr.org/2018/733
    date: false
    authors:
      -
        ins: S. Jarecki, H. Krawczyk, J. Resch

--- abstract

This document describes a verifable mechansim to bind public metadata to an
existing Verifiable oblivious Pseduo-Random function {{!I-D.irtf-cfrg-voprf}}.
Using zero knowledge proofs a receiver can verify that, for an input x, a
VOPRF(k, x, metadata), is generated from a secret key k, as well as the given
metadata.

--- middle

# Introduction

A VOPRF allows a client and server to evaluate a psuedo-random function
`F(k, x)`, with secret key `k`, and input `x` without the client learning the
key `k` and the server learning the input `x`.  Additionally in a VOPRF, the
client can verify that the output was computed using the key `k`.

One challenge in VOPRFs is to be able to bind public metadata to the output
of the VOPRF while keeping the VOPRF both verifiable and oblivious.
Unlike the input x to the VOPRF, public metadata is not meant
to be secret to either the client or the server.  This public metadata is
useful in applications where being able to bind application context to a VOPRF
output is criticial to the security of the application.

In this draft we describe a mechanism to bind public metadata to a VOPRF by
deriving the public-private keypair that is used by the VOPRF from the
metadata {{PrivateStats}}.  This method allows the use of existing elliptic
curve VOPRF ciphers while only changing the way the secret key is derived.
Additionally, the key derivation mechanism of the public key can be verified by
a client using non-interactive zero-knowledge proofs to prove that the metadata
specific key is derived from a master secret.

The draft does not describe how metadata is used, but that left to specific
application protocols that use this public metadata mechanism.

## Requirements

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 {{RFC2119}} {{!RFC8174}}
when, and only when, they appear in all capitals, as shown here.

## Terminology
The following terms are used throughout this document.

- PRF: Pseudorandom Function.
- VOPRF: Verifiable Oblivious Pseudorandom Function.
- Client: Protocol initiator. Learns pseudorandom function evaluation as
  the output of the protocol.
- Server: Computes the pseudorandom function over a secret key. Learns
  nothing about the client's input.
- NIZK: Non-interactive zero knowledge.
- DLEQ: Discrete Logarithm Equality.

# Preliminaries

The document defines extensions to the VOPRF required to support metadata.
This document depends on the following:

- `GG`: A prime-order group implementing the API described in
  {{!I-D.irtf-cfrg-voprf}} as well as the additional APIs defined below in
  {{pog}}.
- `Public Metadata`: The public metadata is defined as an `n` bit vector. To
  represent `b` values, an application could use `log b` bits.

## Prime-Order Group Dependency {#pog}

We define new member functions on the prime-order group `GG` defined in
{{!I-D.irtf-cfrg-voprf}}:

- ScalarMult(point, scalar): A member function of `GG` that multiples an
  element in the group with a `scalar` from `GF(p)`.
- NewGenerator(): A member function of `GG` that samples a new generator
  for the group.

## Other Conventions
All algorithm descriptions are written in a Python-like pseudocode. All
scalar multiplications are performed modulo `GF(p)`.

## Discrete log proofs
Zero knowledge proofs for statements on discrete-logs were summarized by
{{Camenisch97}}.  We describe two algorithms used in this draft on `GG`
to prove discrete log statements.

`DLEQProve(k, A, B, C, D)` proves that `B = k * A` and `D = k * C` without
revealing the value of `k`.  This type of proof is used when `k` is a secret
value that should not be revealed to a verifier.

~~~
def DLEQProve(k, A, B, C, D):
    r = GG.RandomScalar()
    E = r * A
    F = r * C
    hashInput = A || B || C || D || E || F
    cbytes = Hash(hashInput)
    c = GG.HashToGroup(cbytes)
    z = r + k * c
    return (z, E, F)
~~~

`DLEQVerify(A, B, C, D, proof)` verifies that the proof generated by
`DLEQProve` is valid.

~~~
def DLEQVerify(A, B, C, D, proof):
    hashInput = A || B || C || D || proof.E || proof.F
    cbytes = Hash(hashInput)
    c = GG.HashToGroup(cbytes)
    cBE = cB + proof.E
    cDF = cD + proof.F
    zA = proof.z * A
    zC = proof.z * C
    return zA == cBE && zC == cDF
~~~

# Protocol

## Overview
A server first generates a main key pair `(skM, pkM)`, where `skM` is the
servers main secret key and `pkM` is the servers main public key.
Given public metadata `t`, the server generates a keypair specific to the
metadata `t`, `(skT, pkT) = PKGen(t, skM)`, where `skT` is the secret key for
metadata `t` and `pkT` is its public key. Once a metadata specific keypair is
available, the server can be used to evaluate a `VOPRF(skT, x)`, where `x` is
the input for the user.  When the VOPRF is in verifiable mode, the client also
receives a NIZK proof that `skT` and `pkT` are generated from `skM` and `pkM`
(in verifiable mode).

~~~
   Client(pkM, input, metadata)        Server(skM, pkM, metadata)
  ----------------------------------------------------------
    blind, blindedElement = Blind(input)

                       blindedElement
                        ---------->
         skT, pkT, pkProofs = PKGen(skM, metadata)

    evaluatedElement, proof = Evaluate(skT, pkT, blindedElement)

                  evaluatedElement, pkT, proof, pkProofs
                        <----------

    pkVerified = PKVerify(pkM, pkT, pkProofs)

    output = Finalize(input, blind, evaluatedElement, blindedElement, pkT, proof)
~~~

In the following sections we describe modifications to the VOPRF scheme in
{{!I-D.irtf-cfrg-voprf}} to be able to augment an existing VOPRF with public
metadata.

## Pre-Setup
We augment the offline context setup phase phase of the VOPRF in
{{!I-D.irtf-cfrg-voprf}}. In this phase, both the client and server create a
context used for executing the online phase of the protocol.

Prior to this phase, the key pair
(`skM`, `pkM`) should be generated by using `MasterKeyGen(metadataBits)`. This
keypair is used as the master key for VOPRFs.  This master key is not used
directly within the VOPRF, however, public metadata is used to generate
attribute specific keys that are used in the VOPRF evaluation.

`metadataBits` here is the number of bits of metadata that are required for
the application of the VOPRF.  `MasterKeyGen` samples `n` scalar elements
`a0, a1, ... an` from the group and a new generator `h`.  `ai` is a group
element associated with the `i`th bit of metatadata.  Public parameters
are calculated by performing scalar multiplicaton of `h` with each `ai`.

~~~
def MasterKeyGen(metadataBits):
    ais = []
    his = []
    h = GG.NewGroupGenerator()
    a0 = GG.RandomScalar()
    for i in range(metadataBits):
        ai = GG.RandomScalar()
        ais.append(ai)
    for i in range(metadataBits):
        hi = GG.ScalarMult(h, ais[i])
        his.append(hi)
    P0 = GG.ScalarBaseMult(a0)
    skM = (a0, ais)
    pkM = (GG.g, h, metadataBits, P0, his)
    return (skM, pkM)
~~~

## Evaluate VOPRF

When client and server have agreed on the metadata to use for the protocol,
the server first executes `PKGen(skM, metadata)` to generate `skT` and the
proof that `skT` is derived from `skM`.  This draft does not discuss how the
client and server agree on the metadata to use, and that is left to the
application.

Note that `skM` has one group element for each bit of the metadata `t`, as well
as the extra group element `a0`. Given metadata `t`, `PKGen` calculates the
attribute specific key by performing a scalar multiplication of all the group
elements in `skM` for each bit of `t` that is set to `1`.

To prove that `skT` is derived from `skM`, `GenProofs` generates upto `n`
discrete log proofs, one for each bit of the metadata.  Each proof proves
that `hi = ai * h` and `Pi = ai * Pi-1`.  This proves that `ai` was correctly
used for bit `i`.

~~~
def PKGen(t, skM, pkM):
    pis = []
    pi = skM.a0
    keyBits = len(metadata)
    for i in range(keyBits):
        if t[i] == 0:
            pis.append(None)
            continue
        pi = pi * skM[i]
        pis.append(pi)
    skT = pi
    pkT = GG.ScalarMultBase(skT)
    pkProofs = GenProofs(metadata, pis, skM, pkM)
    return (skT, pkT, pkProofs)

def GenProofs(t, pis, skM, pkM):
    proofs = []
    numProofs = len(pis)
    previousPi = pkM.P0
    for i in range(numProofs):
        if t[i] == 0:
            continue
        Pi = GG.ScalarBaseMult(pis[i])
        proofi = DLEQProve(skM.ais[i], pkM.h, pkM.his[i], previousPi, Pi)
        proofs.append((Pi, proofi))
        previousPi = Pi
    return proofs
~~~

Once `PKGen` has generated a public key for a set of `metadata` bits,
the client can verify that `skT` is derived from `skM`, using
`PKVerify(pkM, pkT, pkProofs)`.  This verifies the sequence of discrete-log
proofs generated by `PKGen`.

~~~
def PKVerify(pkM, pkT, t, pkProofs):
    previousPi = pkM.P0
    proofVerified = True
    for proof in pkProofs:
        if t[i] == 0:
            continue
        Pi = proof.Pi
        verified = DLEQVerify(pkM.h, pkM.his[i], previousPi, Pi, proof)
        proofVerified = proofVerified & verified
        previousPi = Pi
    return proofVerified
~~~

A server can use `skT` generated from `PKGen` as the private key for the
VOPRF mechanism in {{!I-D.irtf-cfrg-voprf}}.

# Application considerations

## Metadata bits
Applications must choose the maximum size in bits of the metadata that they
would like to support before setup of the protocol. The size of the metdata
impacts the following
- Size of the public key
- Computation time for attribute and proof generation

For `b` being the number of metadata values needed for an application, the size
of the public key scales as `O(log b)`.  Computation also scales as `O(log b)`
number of scalar multiplications for generating a public key and number of
discrete log proof generations and verifications required.

## Encoding metadata
Applications must choose the number of bits of metadata required in order to
be able to represent all possible values for the application's metadata. They
MUST define their own mechanism encode metadata into bits.

# Comparison with other approaches

## Pairings
It is possible to construct VOPRFs with public metadata using pairing-friendly
curves {{!I-D.draft-irtf-cfrg-pairing-friendly-curves}} with an approach in
{{Pythia15}}.

However this approach has some disadvantages.  Pairings are not widely
available in cryptographic libraries and are also not compatible with existing
deployed VOPRFs like in {{!I-D.irtf-cfrg-voprf}}. The approach described here
allows applications to use existing deployed VOPRFs while only changing the
mechanism of key derivation.

## Partially oblivious PRF
Another approach that could be used to bind metadata to a VOPRF evaluation is
to use a similar method in {{pOPRF18}} which uses a regular `PRF(k, metadata)`
to derive a secret key based on the metadata which is then used in the VOPRF.

The verifiability of public key could be achieved by publishing every public
key for each metadata value in a central repository, which could be checked by
the client.  For large number of values of metadata `b`, this approach
generates `O(b)` keys, which can be difficult for clients and servers to
manage. In contrast, the approach described in this document, the size of the
master public key is `O(log b)`, and the public keys of each attribute can be
verified against the master key later.

# Security Considerations

## Cryptographic security

The security properties of a VOPRF with public metadata are derived from the
proof in {{PrivateStats}} that the VOPRF defined here is a PRF even after
giving an adversary access to proofs from `PKGen`. The VOPRF defined in
{{!I-D.irtf-cfrg-voprf}} when combined with attributes results in a PRF output
of `PRF(skM, t, x) = a0 * a1 ... * an * H(x)`.

### l-exponent Diffie Hellman assumption
TODO: discuss l-exponent DH problem

### Selective security vs full security
TODO: discuss what selective security is and how to transform.

### Size of metadata
TODO: discuss how size of metadata might affect security.

# IANA Considerations

This document has no IANA actions.

--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
