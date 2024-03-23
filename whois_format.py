"""Whois client wrapper producing a terse, single-line format."""

import datetime
import logging
from argparse import ArgumentParser, FileType
from importlib.metadata import version
from time import sleep

from tabulate import tabulate
from whois import whois  # type: ignore
from whois.parser import PywhoisError  # type: ignore

__application_name__ = "whois-format"
__version__ = version(__application_name__)
__full_version__ = f"{__application_name__} {__version__}"

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

DEFAULT_STR = "-"
NUM_SLEEP_SECONDS = 15


def get_ns_domains(nameservers: list) -> list:
    """Return parent domain(s) for list of DNS server FQDNs."""
    x = set()
    for fqdn in nameservers:
        dom: str = ".".join(fqdn.split(".")[1:]).lower()
        x.add(dom)
    return list(x)


def get_domain_whois(domains: list, pause: int = NUM_SLEEP_SECONDS) -> dict:
    """Return domain attributes for each input domain.

    Perform a WHOIS lookup for each input domain. Sleep for `pause` seconds
    between lookups to avoid rate limiting by servers queried for multiple
    domains.

    Due to the possibility that some domains may succeed and others fail,
    return a dictionary object with the following keys:

    - `responses`: a list of lists of domain information for each domain
      successfully queried in WHOIS.
    - `warnings`: a list of errors for each domain that failed to return a
      response from WHOIS.

    Arguments:
    domains -- list of domains for which to query WHOIS

    Keyword arguments:
    pause -- number of seconds to pause between WHOIS queries (default:
    constant)
    """
    val = 0
    resp_data: dict[str, list] = {
        "responses": [],
        "warnings": [],
    }
    for domain in domains:
        val += 1
        data = []
        domain = domain.strip().lower()
        logging.debug("about to query for domain: %s", domain)
        try:
            w = whois(domain)
        except PywhoisError as e:
            # Take the first line of output as the error to pass back to the
            # caller.
            err = str(e).partition("\n")[0]
            resp_data["warnings"].append([domain, err])
            logging.debug("encountered error for domain %s: %s", domain, err)
            continue
        logging.debug("completed query for domain: %s; result: %s", domain, w)
        if w.domain_name is None:
            logging.error(
                "%s: received null response to lookup "
                "(possible nonexistent domain or WHOIS library issue)",
                domain,
            )
            continue

        # Build return data as a list of fields from attributes of the
        # response.
        # Field ordering matters - keep to this format:
        # domain, creation_date, registrar, nameservers, registrant name or
        # organization, registrant email(s)
        data.append(w.domain.upper())
        creation = w.get("creation_date")
        if isinstance(creation, list):
            dt = creation[0]
        else:
            dt = creation
        if isinstance(dt, datetime.datetime):
            data.append(dt.strftime("%Y-%m-%d"))
        else:
            data.append(DEFAULT_STR)
        data.append(w.get("registrar", DEFAULT_STR))
        ns_list = get_ns_domains(w.get("name_servers", []))
        data.append(", ".join(ns_list or ["-"]))
        data.append(w.get("name") or w.get("org", DEFAULT_STR))
        # Multiple email addresses may be extracted from the WHOIS record, so
        # attempt to return all of them to maximize context.
        emails = w.get("emails", [DEFAULT_STR])
        logging.debug("emails: %s", emails)
        if emails is None:
            emails = [DEFAULT_STR]
            logging.debug("emails: %s", emails)
        if not isinstance(emails, list):
            emails = [emails]
            logging.debug("emails: %s", emails)
        data.append(", ".join(emails))

        resp_data["responses"].append(data)
        if val < len(domains):
            sleep(pause)

    return resp_data


def cli():
    """CLI entry point."""
    description = "Whois client wrapper producing a terse, single-line format."
    parser = ArgumentParser(description=description)
    parser.add_argument(
        "-s",
        "--sleep",
        type=int,
        default=NUM_SLEEP_SECONDS,
        help=(
            "number of seconds to sleep for a pause between lookups of "
            "multiple domains (default: %(default)s)"
        ),
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "domain", nargs="*", default=[], help="domain name(s) to query"
    )
    group.add_argument(
        "-f",
        "--in-file",
        type=FileType("r"),
        help="input file of domains (`-` for standard input)",
    )
    group.add_argument(
        "-V",
        "--version",
        action="version",
        version=__full_version__,
        help="print package version",
    )
    parser.add_argument(
        "-d", "--debug", action="store_true", help="enable debug output"
    )
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.in_file:
        lookup_domains = args.in_file.readlines()
    else:
        lookup_domains = args.domain

    resp_data = get_domain_whois(lookup_domains, args.sleep)

    if resp_data["responses"]:
        print(tabulate(resp_data["responses"], tablefmt="plain"))
    if resp_data["warnings"]:
        txt_warning = tabulate(resp_data["warnings"], tablefmt="plain")
        logging.warning("WHOIS errors:\n%s", txt_warning)
