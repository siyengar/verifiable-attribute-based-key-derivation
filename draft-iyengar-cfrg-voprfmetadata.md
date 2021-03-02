---
title: Verifiable Oblivious Pseudo-Random Functions with Public Metadata
abbrev: "VOPRFs with Public Metadata"
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
 -
    ins: A. Raghunathan
    name: Ananth Raghunathan
    organization: Facebook
    email: ananthr@fb.com
 -
    ins: C. A. Wood
    name: Christopher A. Wood
    organization: Cloudflare
    email: caw@heapingbits.net

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
existing Verifiable Oblivious Pseduorandom Function {{!I-D.irtf-cfrg-voprf}}
(VOPRF). With this extension, a client can verify that y = F(k, x) for
pseudorandom function F, private input x, and public metadata t, where the PRF
key k is cryptographically bound to the metadata t.

--- middle

# Introduction

A VOPRF allows a client and server to evaluate a psuedorandom function
`F(k, x)`, with secret key `k`, and input `x` without the client learning the
key `k` and the server learning the input `x`.  Additionally, in a VOPRF, the
client can verify that the output was computed using the key `k`.

One challenge in VOPRFs is to be able to bind public metadata to the output
of the VOPRF while keeping the VOPRF both verifiable and oblivious.
Unlike the client's private input `x` to the VOPRF, public metadata is not meant
to be secret to either the client or the server. This public metadata is
useful in applications where being able to bind application context to a VOPRF
output is critical to the security of the application.

In this draft we describe a mechanism to bind public metadata to a VOPRF by
deriving the public-private key pair that is used by the VOPRF from the
metadata {{PrivateStats}}. This method extends the design of {{!I-D.irtf-cfrg-voprf}}
by changing the way the OPRF evaluation secret key is derived. Specifically,
the extension in this specification allows servers to prove in zero knowledge that
a given OPRF key is bound to public metadata and derived from a given main
secret.

The draft does not describe how metadata is used, though does include application
considerations for selecting and encoding metadata.

## Requirements

{::boilerplate bcp14}

## Terminology

The following terms are used throughout this document.

- PRF: Pseudorandom Function.
- VOPRF: Verifiable Oblivious Pseudorandom Function.
- Client: Protocol initiator. Learns pseudorandom function evaluation as
  the output of the protocol.
- Server: Computes the pseudorandom function over a secret key. Learns
  nothing about the client's private input.
- NIZK: Non-Interactive Zero Knowledge.

# Preliminaries

The document defines extensions to the VOPRF required to support metadata.
This document depends on the following a prime-order group GG implementing the
API described in {{!I-D.irtf-cfrg-voprf}}. We use the same notation from that
document as well. For example, given a Scalar `k` and Element `x`, `k * x`
representations scalar multiplication of `x` by `k`. See {{!I-D.irtf-cfrg-voprf}},
Section 2 for details. Moreover, we assume that the utility functions `GenerateProof()`
and `VerifyProof()` from {{!I-D.irtf-cfrg-voprf}} are available.

Public metadata used in this document are n-bit strings, where n is a parameter
that both client and server agree upon out of band. To represent b values,
applications could use `log b` bits.

This document also uses dot notation to denote field access in structs or tuples.
For example, given a tuple `A = (x, y, z)`, we use `A.x` to denote the first
element of this tuple. We use the boolean operator `&` to denote logical AND,
i.e., `x & y` is the logical conjunction of `x` and `y`.

# Public Metadata Extension

## Overview

A server first generates a main key pair `(skM, pkM)`, where `skM` is the
servers main secret key and `pkM` is the servers main public key. (Details for
the derivation of `(skM, pkM)` are in {{main-key}}.) Given public metadata `t`,
the server generates a key pair specific to the metadata `t`, denoted
`(skT, pkT) = PublicKeyGen(t, skM)`, where `skT` is the secret key for
metadata `t` and `pkT` is its public key. Once a metadata specific key pair is
available, a client and server can engage in the VOPRF protocol described in
{{!I-D.irtf-cfrg-voprf}} to evaluate the PRF over a clients input `x`. Importantly,
the VOPRF MUST use the verifiable mode (see {{!I-D.irtf-cfrg-voprf}}, Section 3),
wherein the server produces a proof that the ORPF output `y = F(skT, x)` was
computed using key `skT`.

The public key generation step run before the VOPRF protocol is shown below.
Note that applications MAY combine these two round trips into the a single round
trip, albeit at greater computational cost. Where possible, it is RECOMMENDED
that applications run the public key generation step offline to amortize the cost
of this step (provided that the set of metadata is small).

~~~
   Client(pkM, input, metadata)        Server(skM, pkM, metadata)
  ----------------------------------------------------------

          =====  offline public key generation =====

                skT, pkT, pkProofs = PublicKeyGen(skM, metadata)

                        pkT, pkProofs
                        <-----------

    verified = PublicKeyVerify(pkM, pkT, pkProofs)

          ========  online VOPRF evaluation ========

    blind, blindedElement = Blind(input)

                       blindedElement
                        ---------->

    evaluatedElement, proof = Evaluate(skT, pkT, blindedElement)

                  evaluatedElement, proof
                        <----------

  output = Finalize(input, blind, evaluatedElement, blindedElement, pkT, proof)
~~~

In the following sections we describe modifications to the VOPRF scheme in
{{!I-D.irtf-cfrg-voprf}} to be able to augment an existing VOPRF with public
metadata.

## Main Key Generation {#main-key}

We augment the offline context setup phase phase of the VOPRF in
{{!I-D.irtf-cfrg-voprf}}. In this phase, both the client and server create a
context used for executing the online phase of the protocol.

Prior to this phase, the key pair (`skM`, `pkM`) should be generated from
`MainKeyGen(n)`, where `n` is the number of allowable metadata bits. This
key pair is used as the main key for VOPRFs.  This main key MUST NOT be used
directly within the online VOPRF evaluation. Public metadata is used to generate
attribute specific keys that are used in the VOPRF evaluation.

`MainKeyGen` samples `n` scalar elements `a0, a1, ... an` from the group and a
new generator `h`. `ai` is a group element associated with the `i`th bit of
metadata.  Public parameters are calculated by performing scalar multiplication
of `h` with each `ai`.

~~~
def MainKeyGen(n):
    ais = []
    his = []
    h = GG.ScalarBaseMult(GG.RandomScalar())
    a0 = GG.RandomScalar()
    for i in range(n):
        ai = GG.RandomScalar()
        ais.append(ai)
    for i in range(n):
        hi = h * ais[i]
        his.append(hi)
    P0 = GG.ScalarBaseMult(a0)
    skM = (a0, ais)
    pkM = (GG.g, h, n, P0, his)
    return (skM, pkM)
~~~

## Public Key Generation

When client and server have agreed on the metadata `t` to use for the protocol,
the server first executes `PublicKeyGen(skM, t)` to generate `skT` and
the proof that `skT` is derived from `skM`.  This draft does not discuss how the
client and server agree on the metadata to use, and that is left to the
application.

Note that `skM` has one group element for each bit of the metadata `t`, as well
as the extra group element `a0`. Given metadata `t`, `PublicKeyGen` calculates the
attribute specific key by performing a scalar multiplication of all the group
elements in `skM` for each bit of `t` that is set to `1`.

To prove that `skT` is derived from `skM`, `GenerateProofs` generates up to `n`
proofs, one for each bit of the metadata.  Each proof proves that `hi = ai * h`
and `Pi = ai * Pi-1`.  This proves that `ai` was correctly used for bit `i`.

~~~
def PublicKeyGen(t, skM, pkM):
    pis = []
    pi = skM.a0
    keyBits = len(t)
    for i in range(keyBits):
        if t[i] == 0:
            pis.append(None)
            continue
        pi = pi * skM[i]
        pis.append(pi)
    skT = pi
    pkT = GG.ScalarMultBase(skT)
    pkProofs = GenerateProofs(t, pis, skM, pkM)
    return (skT, pkT, pkProofs)

def GenerateProofs(t, pis, skM, pkM):
    proofs = []
    previousPi = pkM.P0
    for i in range(len(pis)):
        if t[i] == 0:
            continue
        Pi = GG.ScalarBaseMult(pis[i])
        proofi = GenerateProof(skM.ais[i], pkM.h, pkM.his[i], previousPi, Pi)
        proofs.append((Pi, proofi))
        previousPi = Pi
    return proofs
~~~

Once `PublicKeyGen` has generated a public key for a set of `n` bits, the client
can verify that `skT` is derived from `skM`, using `PublicKeyVerify(pkM, pkT, pkProofs)`.
This verifies the sequence of discrete-log proofs generated by `PublicKeyGen`.

~~~
def PublicKeyVerify(pkM, pkT, t, pkProofs):
    previousPi = pkM.P0
    proofVerified = True
    for proof in pkProofs:
        if t[i] == 0:
            continue
        Pi = proof.Pi
        verified = VerifyProof(pkM.h, pkM.his[i], previousPi, Pi, proof)
        proofVerified = proofVerified & verified
        previousPi = Pi
    return proofVerified
~~~

A server can use `skT` generated from `PublicKeyGen` as the private key for the
VOPRF mechanism in {{!I-D.irtf-cfrg-voprf}}.

# Application considerations

## Metadata bits

Applications must choose the maximum size in bits of the metadata that they
would like to support before setup of the protocol. The size of the metadata
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
main public key is `O(log b)`, and the public keys of each attribute can be
verified against the main key later.

# Security Considerations

## Cryptographic security

The security properties of a VOPRF with public metadata are derived from the
proof in {{PrivateStats}} that the VOPRF defined here is a PRF even after
giving an adversary access to proofs from `PublicKeyGen`. The VOPRF defined in
{{!I-D.irtf-cfrg-voprf}} when combined with attributes results in a PRF output
of `PRF(skM, t, x) = a0^t1 * a1^t2 ... * an^tn * H(x)`.

### n-Diffie Hellman exponent assumption
There are several variants of the Diffie-Hellman assumption and the proof of
the VOPRF with public metadata is based on the n-Diffie Hellman exponent
assumption. The n-DHE problem requires an adversary to distinguish the n+1-th
power of a secret `a` hidden in the exponent from a random element in `GG`.

Sample uniformly at random `d` in {0,1}, and a random `r` from `GF(p)`:
- Given `G` is a generator in `GG`
- Given `G`, `a * G` , `(a^2) * G`, ..., `(a^n) * G`
- if `d` == 0: `C = a^(n+1) * G` else: `C = r * a`

Output `d' == d`

### Selective security vs full security

The security properties of the VOPRF with public metadata described in this
draft is based on the proof in {{PrivateStats}} that the VOPRF is a
selectively-secure VRF. Selective-security is a weaker notion of security that
requires an adversary to commit to the challenge input (in this case, the
metadata and value x) before trying to break the PRF.

In practice, if target inputs are independent of the system parameters, there
should not be an advantage to allowing the attacker to choose the target after
seeing system parameters. To convert our VOPRF with public metadata to one
satisfying a full security notion in the random oracle model, we require that
the metadata be hashed with a collision-resistant hash function with
sufficiently large output (>=256-bits). For smaller metadata sets therefore,
the selectively-secure VRF is much more efficient.

# IANA Considerations

This document has no IANA actions.

--- back

# Acknowledgments

The editors of this document thank all authors of the {{PrivateStats}} work, where
the construction was originally described.

{:numbered="false"}

