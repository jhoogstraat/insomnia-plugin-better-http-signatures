#  Better HTTP Signatures for Insomnia

This is a plugin for [Insomnia](https://insomnia.rest/) that allows the signing of HTTP Messages.
It is based on the [HTTP Signature Plugin](https://github.com/adnsio/insomnia-plugin-http-signature#readme).
To find out more about the http signature spec, look [here](https://tools.ietf.org/html/draft-cavage-http-signatures-10).

##  Installation

Install the `insomnia-plugin-better-http-signatures` plugin from Preferences -> Plugins.

##  How to use

Add the `HTTP Signature` template tag as auth token or header value and fill the necessary fields.

##  Q&A

RSA Private Keys are set without headers and newlines (`-----BEGIN RSA PRIVATE KEY-----` and `-----END RSA PRIVATE KEY-----`).

The Live Preview will show a template of the signing string. There are no values, because they are inserted when a request is fired.

-  The `Date` header is added if needed.
-  `Content-Type` and `Content-Length` headers are used when available (eg. in post requests).
