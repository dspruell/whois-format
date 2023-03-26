"""
Whois client wrapper producing terse, single-line format.

"""

import datetime
import logging
from argparse import ArgumentParser, FileType

import pkg_resources
from whois import whois

__application_name__ = "whois-format"
__version__ = pkg_resources.get_distribution(__application_name__).version
__full_version__ = f"{__application_name__} {__version__}"

logging.basicConfig(level=logging.DEBUG, format="[%(levelname)s] %(message)s")


DEFAULT_STR = "-"


def get_ns_domains(nameservers):
    "Return parent domain(s) for list of DNS server FQDNs"

    x = set()
    for fqdn in nameservers:
        dom = ".".join(fqdn.split(".")[1:]).lower()
        x.add(dom)
    return list(x)


def cli():
    description = "Whois client wrapper producing terse, single-line format."
    parser = ArgumentParser(description=description)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--domain", help="domain name to query")
    group.add_argument(
        "-f", "--in-file", type=FileType("r"), help="input file of domains"
    )
    group.add_argument(
        "-V",
        "--version",
        action="version",
        version=__full_version__,
        help="print package version",
    )
    args = parser.parse_args()

    # Output format
    output_tpl = (
        "{domain}  {creation_date}  {registrar}  {nameservers}  "
        "{registrant_name}  {email}"
    )

    fields = {}

    w = whois(args.domain.lower())
    fields["domain"] = w.domain.upper()
    dt = w.get("creation_date")[0]
    if isinstance(dt, datetime.datetime):
        fields["creation_date"] = dt.strftime("%Y-%m-%d")
    else:
        fields["creation_date"] = DEFAULT_STR
    fields["registrar"] = w.get("registrar", DEFAULT_STR)
    ns_list = get_ns_domains(w.get("name_servers", []))
    fields["nameservers"] = ", ".join(ns_list or ["-"])
    fields["registrant_name"] = w.get("name") or w.get("org", DEFAULT_STR)
    fields["email"] = ", ".join(w.get("emails", [DEFAULT_STR]))
    print(output_tpl.format(**fields))
