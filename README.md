# PEP Go

This repo contains example code for me to better understand the concepts of polymorphic encryption and pseudonymisation (PEP) based on the Paper [The polymorphic eID scheme](https://www.cs.ru.nl/E.Verheul/papers/eID2.0/eID%20PEP%201.29.pdf) by [Eric R. Verheul](https://www.cs.ru.nl/E.Verheul/).

# What is it?

It simulates the interaction between 4 components:

## Key Management Authority (KMA)

The Key Management Authority is responsible for ditributing the correct keys between the parties. It ensures every party gets the correct keys according to its role. By doing so, it enforces the governance behind the system.

## Activation Service

The Activation Service takes a BSN from an authentication service and transforms it to a polymorphic identity (PI).

## Authentication Service

The Authentication Service authenticates a user, determins its BSN and "activates" it by calling the activation service. This results in a polymorphic identity which it can store for later use.
It can than later transform the PI to a form for a specific service provider.

## Service provider

Needs the BSN but cannot authenticate the user itself. It relies on the authentication provider to generate a PI which it can decrypt.

## How to use?

Run the following commands:

```sh
$ go run ./cmd/.
```

## What is supported?

- [x] Creating PIs for specific APs
- [x] Transforming PIs to EIs for specific SPs
- [x] Decrypting EIs by specific SP
- [ ] Creating PPs
- [ ] Transforming PPs to EPs for specific SPs
- [ ] Decrypting EPs by specific SP
