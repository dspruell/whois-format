# whois-format
Whois client wrapper producing a terse, single-line format.

## Why?
When dealing with security threats, an important aspect to analyze and
track is the attacker's infrastructure
(ref. [Diamond Model](https://www.threatintel.academy/diamond/)).
[WHOIS](https://en.wikipedia.org/wiki/WHOIS) provides a distributed database
containing registered domain information, and an associated protocol for
querying this information.

One issue with WHOIS data is that as a directory record format, it can
contain a lot of information - sometimes many dozens of lines of output,
with some being repeated, and in the modern day, much of this being
boilerplate redacted information due to WHOIS privacy. Additionally,
not every registry's record format is the same, so the lack of consistency
can be difficult to deal with. As an analyst, when looking up domain name
information, this can be tedious. In some cases, you may spend a good amount
of time copying, pasting and formatting data from WHOIS records.

## Features
This tool attempts to ease this by presenting WHOIS information in a brief
format:

- Domain information in a terse, consistent single-line layout.
- Suitable for grep(1) and for arranging on a page in a readable columnar
  format.
- Information output is only key fields useful for typical purposes: domain
  name, registration date, registrar, nameservers, registrant name (or
  organization), and registrant email.

The output format is optimized for plain text use, and fields are separated
using two spaces, with multiple value fields separated with a comma and
space. This format is intended for reading, not parsing.

A default sleep time of 15 seconds is implemented as a blunt pause so that
lookups don't trigger thresholds on WHOIS servers, which can result in
blocklisting or further data redaction. When looking up multiple domains,
this version of the tool pauses to collect information on all domains
before outputting any data (this needs to be improved). This threshold
can be adjusted using the `-s` option.

whois-format uses the [python-whois](https://pypi.org/project/python-whois/)
library to query WHOIS.

## Setup

It's recommended to use [pipx](https://pypa.github.io/pipx/) for easy setup and
isolation:

```
pipx install whois-format
```

## Examples

Looking up a single input domain. The same syntax supports passing additional
domains on the command line:

```
$ whois-format -d iana.org
IANA.ORG  1995-06-05  CSC Corporate Domains, Inc.  iana-servers.net, icann.org  REDACTED FOR PRIVACY  domainabuse@cscglobal.com
```

Querying for a list of domains from a newline-separated file:

```
$ whois-format -f tests/sample_domains.txt 
IANA.ORG       1995-06-05  CSC Corporate Domains, Inc.  icann.org, iana-servers.net   REDACTED FOR PRIVACY     domainabuse@cscglobal.com
ICANN.ORG      1998-09-14  GoDaddy.com, LLC             icann.org, icann-servers.net  REDACTED FOR PRIVACY     abuse@godaddy.com
SLACKWARE.COM  1995-12-26  Network Solutions, LLC       cwo.com                       Slackware Linux Project  abuse@web.com, volkerdi@gmail.com, domain.operations@web.com
```
