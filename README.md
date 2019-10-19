# can-server
CAN bus send/receiver daemon based on candump

This is the candump utility from can-utils package (but from 2 years ago I think) extended with a daemon (forking) and IO redirection.

The daemon forward data between a UNIX and CAN sockets. There is a simple client what prints data. The inputtest is an utility to test a device and performance. I had an IO card with 8 inputs and 8 outputs so I connect them and run the tests. You can see the results in the compressed files.

The project currently suspended.
