# Security policy

## Supported versions

QuantaSeek has not had a release yet. Fixes go to the `main` branch only.

## Reporting a vulnerability

Report privately through GitHub: open the repository's **Security** tab and
choose **Report a vulnerability**
(<https://github.com/Mehrn0ush/QuantaSeek/security/advisories/new>). Please
don't open a public issue.

Include the version or commit, the command line, and, if you can, a minimal
reproduction. A packet capture or the JSON report is often enough.

You can expect an acknowledgement within 7 days. There is no fixed fix date,
but you will be kept informed, and credited in the advisory unless you would
rather not be.

## Scope

In scope:
- memory-safety or denial-of-service bugs in parsing server responses
  (ServerHello, certificates, alerts, HTTP)
- crashes or hangs triggered by a malicious server
- QuantaSeek reporting a result it did not observe, in a way that could make
  a user believe an endpoint is post-quantum protected when it is not
- supply-chain problems in the build or CI configuration

Out of scope: weaknesses in the servers being scanned. QuantaSeek reports
those as findings.
