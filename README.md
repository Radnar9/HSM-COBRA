# COBRA - COnfidential Byzantine ReplicAtion SMR library

COBRA is a fully-featured state machine replication library that guarantees the confidentiality of the data. 
Confidentiality is ensured by integrating a secret sharing mechanism into the 
modified [BFT-SMaRt](https://github.com/bft-smart/library) library, a fully-featured replication library without 
confidentiality guarantees.

This repository presents all the changes made to the [original COBRA repository](https://github.com/bft-smart/cobra).
This new version of COBRA was used in my Master's thesis
[_"Virtual and Distributed Hardware Security Module for Secure Key Management"_](https://github.com/Radnar9/Virtual-Distributed-HSM).
It was adapted to allow the configuration of any elliptic curve parameters so we could generate keys for
different signature schemes that required a specific elliptic curve.

## Requirements
The COBRA library is primarily implemented in Java and currently uses Gradle to compile, package, and 
deploy compiled code for local testing. The current COBRA library was tested using Java 17.

## Compilation and Packaging
First, clone this repository. Now inside the `thesis-hsm-cobra` folder, follow the following instructions:

* To compile and package to locally test the library: Execute `./gradlew simpleLocalDeploy`. The execution of Gradle 
task `simpleLocalDeploy` will create the folder `build/local` containing all the necessary files to start testing.

## Usage
**NOTE:** Following commands considers the WSL/Linux operating system.

***Running the keygen demo (4 replicas tolerating 1 fault):***

Execute the following commands across four different server consoles from within 
the folder `build/local`:
```
build/local$ ./run.sh confidential.demo.keygen.server.Server 0
build/local$ ./run.sh confidential.demo.keygen.server.Server 1
build/local$ ./run.sh confidential.demo.keygen.server.Server 2
build/local$ ./run.sh confidential.demo.keygen.server.Server 3
```

Once all replicas are ready, the client can be launched by executing the following command in 
the same directory `build/local`:
```
build/local$./run.sh confidential.demo.keygen.client.Client 1
```

## Limitations
This library is a proof-of-concept implementation and not a production-ready implementation.

_For more info about this library access the original repository [here](https://github.com/bft-smart/cobra)._
