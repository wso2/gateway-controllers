---
title: "Overview"
---
# Error Response Formatter

## Overview

The Error Response Formatter policy renders a gateway error in a shape you define — from a
built-in preset such as OpenAI, JSON-RPC or SOAP, or from your own template — and sets the
response status and headers that go with it. It replaces the gateway's default error body.

> **This is a fault policy only.** Attach it under `faultPolicies`. Declared under `policies` it
> deploys successfully and then never runs.

## Features

- **Presets** for the shapes that have to be exact — OpenAI, JSON-RPC, SOAP 1.1, SOAP 1.2, and a
  canonical WSO2 envelope
- **Structured templates** (`template`) rendered as JSON, where a leaf keeps its type
- **Text templates** (`stringTemplate`) for XML, SOAP and plain text, where element order matters
- **Header customisation** on the same error, so a client can branch without parsing the body
- **Status code change**, with the body rendered for the new status
- **Automatic escaping** for the output syntax, so untrusted text cannot break out of the document
- **Replaces the gateway's default error body**, with nothing else to configure
- **Validation** of placeholders and templates before any request is served

## Configuration

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `preset` | string | No | `canonical` | A built-in shape: `openai`, `canonical`, `jsonrpc`, `soap11`, `soap12`. Each sets its own Content-Type. Mutually exclusive with `template` and `stringTemplate`. |
| `template` | object | No | - | A structured shape rendered as JSON. String leaves may contain `${Field}` placeholders; numbers, booleans and nulls pass through as written. |
| `stringTemplate` | string | No | - | A raw-text shape, for output that is not an object — XML, SOAP, plain text. |
| `contentType` | string | No | `application/json` | Content-Type for the rendered body. A preset supplies its own. Also drives escaping unless `escape` overrides it. |
| `headersToSet` | array | No | `[]` | Response headers to overwrite on the error. Values may contain placeholders; names may not. |
| `headersToAppend` | array | No | `[]` | Response headers to add without replacing existing values. |
| `headersToRemove` | array | No | `[]` | Response headers to strip from the error. Naming a header here and in `headersToSet`/`headersToAppend` is refused. |
| `statusCode` | integer | No | - | Replaces the response status, `200`–`599`. Unset keeps the failure's own status. See [Changing the status](#changing-the-status). |
| `escape` | string | No | `auto` | How substituted values are made safe inside `stringTemplate`: `auto`, `xml`, `json`, `none`. Ignored for `template`. |

### Placeholders

Templates and header values can use these placeholders:

| Placeholder | What it carries |
|---|---|
| `${Code}` `${Type}` `${Direction}` | The failure's classification |
| `${Message}` | The client-facing message. Always has a value. |
| `${Description}` | Operator-facing detail. **Often empty** — for a guardrail rejection it is the blocked content, so it is never defaulted and **no preset renders it**. Naming it in your own template sends it to the client. |
| `${Policy}` `${PolicyPhase}` | Which policy failed, and in which phase |
| `${Source}` | Which actor produced the failure: `gateway`, `backend`, `router`, `noRoute`, `unknown` |
| `${Status}` `${RequestID}` | The HTTP status the client receives (the new one, when `statusCode` is set), and the correlation id |
| `${OpenAIType}` | OpenAI's vocabulary — `authentication_error`, `rate_limit_error`, … |
| `${JsonRpcCode}` | `-32600` for 4xx, `-32603` for 5xx. A number in a structured template. |
| `${JsonRpcID}` | The JSON-RPC request id, where one was read |
| `${Soap11Code}` `${Soap12Code}` | `soapenv:Client`/`soapenv:Server`, `env:Sender`/`env:Receiver` |

An invalid configuration, such as an unknown placeholder, is not applied: the API still deploys,
the gateway logs an `ERROR` naming the problem, and the error response goes out unformatted.
Check the gateway log after deploying a new configuration.

## Examples

### A preset

```yaml
faultPolicies:
  - name: error-response-formatter
    version: v1
    params:
      preset: openai
```

Produces `{"error":{"message":"…","type":"authentication_error","code":"900902"}}`.

### A house envelope

```yaml
faultPolicies:
  - name: error-response-formatter
    version: v1
    params:
      template:
        error:
          message: ${Message}
          type: ${OpenAIType}
          code: ${Code}
        requestId: ${RequestID}
        status: ${Status}        # a number, because the leaf is exactly the placeholder
      headersToSet:
        - name: x-error-code
          value: ${Code}
        - name: x-error-source
          value: ${Source}
```

A leaf whose placeholders all resolve empty is dropped, and an object whose every leaf dropped is
dropped too — so a sparse failure yields absence rather than `{"code":""}`.

### A SOAP 1.1 fault from a text template

```yaml
faultPolicies:
  - name: error-response-formatter
    version: v1
    params:
      contentType: text/xml
      stringTemplate: |
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
          <soapenv:Body>
            <soapenv:Fault>
              <faultcode>${Soap11Code}</faultcode>
              <faultstring>${Message}</faultstring>
            </soapenv:Fault>
          </soapenv:Body>
        </soapenv:Envelope>
```

Substituted values are XML-escaped, so a message containing `</fault>` cannot break out of its
element. Unlike `template`, empty values are not dropped here — a placeholder that resolves to
nothing leaves an empty element.

### Changing the status

`statusCode` replaces the status the client receives. `${Status}` and the values derived from it
(`${OpenAIType}`, `${JsonRpcCode}`, `${Soap11Code}`, `${Soap12Code}`) are rendered from the new
status, so the body never contradicts it. A JSON-RPC code the failing policy stated itself is kept.

To change the status for some failures only, give the entry an `executionCondition`. Entries run
in order and each sees what the one before did, so a later entry can override an earlier one:

```yaml
faultPolicies:
  # Every failure in the canonical shape.
  - name: error-response-formatter
    version: v1
    params:
      preset: canonical
  # A missing credential is reported as 400 rather than 401.
  - name: error-response-formatter
    version: v1
    executionCondition: 'fault.Code == "900902"'
    params:
      preset: canonical
      statusCode: 400
```

A `2xx` is allowed for protocols that carry an error inside a successful response, such as
JSON-RPC over HTTP. The status cannot change once a streamed response has started, because it has
already been sent.

## Notes

- Header names cannot contain placeholders.
- Line breaks and NUL characters are removed from substituted header values.
- Set `Content-Type` with `contentType`, not `headersToSet`.
