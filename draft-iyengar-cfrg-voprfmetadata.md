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
  PrivateStats:
    title: PrivateStats, De-Identified Authenticated Logging at Scale
    target: https://research.fb.com/privatestats
    date: false
    authors:
      -
        ins: S.Iyengar, A. Raghunathan, P. Mohassel, et. al.
        org: Facebook

informative:



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
- `Metadata`: The metadata is defined as `n` bits.

## Prime-Order Group Dependency {#pog}

We define new member functions on the prime-order group `GG` defined in
{{!I-D.irtf-cfrg-voprf}}:

- ScalarMult(point, scalar): A member function of `GG` that multiples an
  element in the group with a `scalar` from `GF(p)`.
- NewGenerator(): A member function of `GG` that samples a new generator
  for the group.

## Other Conventions
All algorithm descriptions are written in a Python-like pseudocode.

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
    skElements = []
    pkElements = []
    h = GG.NewGroupGenerator()
    a0 = GG.RandomScalar()
    for i in range(metadataBits):
        ai = GG.RandomScalar()
        skElements.append(ai)
    for i in range(metadataBits):
        hi = GG.ScalarMult(h, skElements[i])
        pkElements.append(hi)
    P0 = GG.ScalarMult(g, a0)
    skM = (a0, skElements)
    pkM = (G, g, h, metadata_bits, P0, pkElements)
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
that `log(hi, h)  == log(Pi, Pi-1)` where `log(a, b)` represents log a to the
base b.  Since `hi = ai * h` and `Pi = ai * Pi-1`, this proves that `ai` was
correctly used for bit `i`.

~~~
def PKGen(t, skM, pkM):
    pis = []
    pi = skM.a0
    keyBits = len(metadata)
    for i in range(keyBits):
        if t[i] == 1:
            pi = pi * skM[i]
            pis.append(pi)
        else:
            pis.append(None)
    skT = pi
    pkProofs = GenProofs(metadata, pis, pkM)
    return (skT, pkProofs)

def GenProofs(t, pis, pkM):
    proofs = []
    numProofs = len(pis)
    previousPi = pkM.P0
    for i in range(numProofs):
        if t[i] == 0:
            continue
        Pi = GG.ScalarMult(g, pis[i])
        proofi = DLEQProve(pkM.h, pkM.hi[i], previousPi, Pi)
        proofs.append(proofi)
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
        verified = DLEQVerify(pkM.h, pkM.hi[i], previousPi, proof)
        proofVerified = proofVerified & verified
        previousPi = proof
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

## Regular key derivation

# Security Considerations

## Cryptographic security

### Hardness assumptions



## Selective security vs full security


# IANA Considerations

This document has no IANA actions.

--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
