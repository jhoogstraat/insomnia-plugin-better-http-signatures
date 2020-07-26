const crypto = require('crypto')

module.exports.templateTags = [
  {
    name: 'httpsignature',
    displayName: 'HTTP Signature',
    description: 'sign http requests',

    args: [
      {
        displayName: 'Key ID',
        type: 'string',
      },
      {
        displayName: 'Key',
        type: 'string',
      },
      {
        displayName: 'Signing Algorithm',
        type: 'enum',
        defaultValue: 'HMAC-SHA256',
        options: [
          { displayName: 'HMAC-SHA256', value: 'hmac-sha256', description: '' },
          { displayName: 'HMAC-SHA512', value: 'hmac-sha512', description: '' },
          { displayName: 'RSA-SHA256', value: 'RSA-SHA256', description: '' },
          { displayName: 'RSA-SHA512', value: 'RSA-SHA512', description: '' },
        ],
      },
      {
        displayName: 'Key Encoding',
        type: 'enum',
        defaultValue: 'Hex',
        options: [
          { displayName: 'Hex', value: 'hex', description: '' },
          { displayName: 'Base 64', value: 'base64', description: '' },
        ],
      },
      {
        displayName: 'header presets',
        type: 'enum',
        defaultValue: 'host (request-target)',
        options: [
          { displayName: '(request-target) host', value: '(request-target) host', description: '' },
          { displayName: '(request-target) host date', value: '(request-target) host date', description: '' },
          { displayName: '(request-target) host date content-type content-length', value: '(request-target) host date content-type content-length', description: '' },
        ],
      },
    ],

    async run(context, keyId, base64PrivateKey, signAlgorithm, encoding, headers) {

      if (!keyId) throw new Error('missing keyId')
      if (!base64PrivateKey) throw new Error('missing privateKey')

      await Promise.all([
        context.store.setItem("bhh-headers", headers),
        context.store.setItem("bhh-keyId", keyId),
        context.store.setItem("bhh-privKey", base64PrivateKey),
        context.store.setItem("bhh-alg", signAlgorithm),
        context.store.setItem("bhh-enc", encoding)
      ])

      return "better-http-signatures: The Signature will be generated on send. These are just the headers used:\n" + headers.split(" ").map(header => {
        return `${header}:`
      }).join("\n")
    },
  },
]

module.exports.requestHooks = [async (context) => {
  const signatureHeaders = context.request.getHeaders().filter(header => header.value.startsWith("better-http-signatures:"))

  if (signatureHeaders.length == 0)
    return

  console.log("Inserting signature into http headers " + signatureHeaders.map(h => "'" + h.name + "'").join(", "))

  const signedHeaders = await context.store.getItem("bhh-headers")
  const keyId = await context.store.getItem("bhh-keyId")
  const alg = await context.store.getItem("bhh-alg")
  const privKey = await context.store.getItem("bhh-privKey")
  const encoding = await context.store.getItem("bhh-enc")

  signatureHeaders.forEach(header => {
    const signingString = composeSigningString(context, signedHeaders)
    const signature = generateSignature(signingString, alg, privKey, encoding)
    var signatureHeader = `keyId="${keyId}",algorithm="${alg.toLowerCase()}",headers="${signedHeaders}",signature="${signature}"`

    if (header.name != "Signature")
      signatureHeader = "Signature " + signatureHeader

    console.log("Signing String:\n" + signingString)
    console.log("Signature header:\n" + signatureHeader)

    context.request.setHeader(header.name, signatureHeader)
  })
}]

function composeSigningString(context, signedHeaders) {
  // Generate complete URL (with parameters)
  const requestUrl = new URL(context.request.getUrl())
  for (const parameter of context.request.getParameters()) {
    requestUrl.searchParams.append(parameter.name, parameter.value)
  }

  var signingComps = []

  signedHeaders.split(" ").forEach(header => {
    switch (header) {
      case "(request-target)":
        signingComps.push(`${header}: ${context.request.getMethod().toLowerCase()} ${requestUrl.pathname}${requestUrl.search}`)
        break
      case "host":
        signingComps.push(`${header}: ${requestUrl.host}`)
        break
      case "date":
        if (context.request.hasHeader("Date")) {
          var dateHeader = context.request.getHeader("Date")
        } else {
          var dateHeader = new Date().toGMTString()
          context.request.setHeader("Date", dateHeader)
        }
        signingComps.push(`${header}: ${dateHeader}`)
        break
      case "content-type":
        if (context.request.hasHeader("Content-Type")) {
          signingComps.push(`${header}: ${context.request.getHeader("Content-Type")}`)
        } else {
          throw new Error("Cannot generate signature using content-type and content-length, because no body was found!")
        }
        break
      case "content-length":
        if (context.request.hasHeader("Content-Type")) {
          signingComps.push(`${header}: ${context.request.getBody().text.length}`)
        } else {
          throw new Error("Cannot generate signature using content-type and content-length, because no body was found!")
        }
        break
    }
  })

  return signingComps.join('\n')
}

function generateSignature(string, signAlgorithm, base64encPrivKey, encoding) {
  const alg = signAlgorithm.split("-")
  const signAlg = alg[0]
  const digestAlg = alg[1]

  console.log("Signing Request with: " + signAlgorithm)

  switch (signAlg) {
    case 'RSA':
      return crypto.createSign(signAlgorithm)
        .update(string)
        .sign(`-----BEGIN RSA PRIVATE KEY-----\n${base64encPrivKey}\n-----END RSA PRIVATE KEY-----`, encoding)

    case 'hmac':
      return crypto.createHmac(digestAlg, Buffer.from(base64encPrivKey, 'base64'))
        .update(string)
        .digest(encoding)
  }

}

