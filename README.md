# easy-peasy-pgp 🗝
[![Build Status](https://travis-ci.org/brainchilds/easy-peasy-pgp.svg?branch=master)](https://travis-ci.org/brainchilds/easy-peasy-pgp)

An easy-peasy porcelain api for [PGP](https://de.wikipedia.org/wiki/Pretty_Good_Privacy) with a default implementation based on [Bouncy Castle](https://www.bouncycastle.org) ([OpenPGP RFC 4880](https://tools.ietf.org/html/rfc4880)).

## Motivation
During a recent project I had to decrypt data which has been encrypted with [PGP](https://de.wikipedia.org/wiki/Pretty_Good_Privacy). When looking for a Java library for that purpose, you'll soon find the [Bouncy Castle Java cryptography API](https://www.bouncycastle.org/java.html). While this is a great library for sure, I needed some time to deal with it. This is because the API is pretty close to the [OpenPGP RFC 4880](https://tools.ietf.org/html/rfc4880) specification. However I actually did not care about PGP packet formats and all I wanted to do was to:

1. Create a key pair
2. Share my public key
3. Decrypt data with my private key and password

And this is where easy-peasy-pgp kicks in. It contains a use-case-oriented porcelain API and an implementation based on [Bouncy Castle](https://www.bouncycastle.org). Besides decryption, other use-cases like signing data are also supported of course.
