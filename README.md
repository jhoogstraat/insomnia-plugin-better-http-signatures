#  Better HTTP Signatures for Insomnia

This is a plugin for [Insomnia](https://insomnia.rest/) that allows the signing of HTTP Messages and is based on the [HTTP Signature Plugin](https://github.com/adnsio/insomnia-plugin-http-signature#readme).

To find out more about the http signature spec, have a look [here](https://tools.ietf.org/html/draft-cavage-http-signatures-10).

##  Installation

Install the `insomnia-plugin-better-http-signatures` plugin from Preferences -> Plugins.

##  How to use

Add the `HTTP Signature` template tag to a header. The spec suggests using the `Authorization` or `Signature` header, but you can use any header you want really.

##  Q&A

- RSA Private Keys are set without headers and newlines (`-----BEGIN RSA PRIVATE KEY-----` and `-----END RSA PRIVATE KEY-----`).

- The Live Preview will not show you the final signature, but the headers used to generate the signature. This is because the date can be signed aswell, which is only known when sending the request.

-  The `Date` header is added to the request if absent, but should be signed.

- `Signature ` is prepended to the header value if the header is not the `Signature` header.
