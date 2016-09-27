# Skryptonite
Scrypt Windows Runtime Component for UWP 

Author: Nicholas C. Bauer, Ph.D.
nicholasbauer@outlook.com

Provides a native implementation of the scrypt algorithm invented by Colin Percival for usage in Universal Windows Platform applications, managed by a C# wrapper. Implements both x86-64 and ARM vector operations for compatibility across platforms.

If you find this library or the code useful, please consider a donation: http://paypal.me/NicholasBauer/25. I put a lot of work into making sure the code was abstracted and documented as fully as possible. If you find anything unclear, please file an issue.

Installation
------------
The compiled component may be obtained from NuGet here: https://www.nuget.org/packages/Skryptonite

Usage
-----
If the parameters are known, simply create an instance of the Scrypt object and use DeriveKey() to run the algorithm.

CreateOptimal() can be used to create an instance of the algorithm conforming to the desired memory and time constraints.
