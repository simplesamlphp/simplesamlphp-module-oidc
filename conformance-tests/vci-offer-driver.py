#!/usr/bin/env python3
"""Deliver credential offers to the OpenID4VCI issuer conformance plan.

In the issuer-initiated variants of oid4vci-1_0-issuer-test-plan each test waits for the issuer to
send it a credential offer, and with a pre-authorized code also for the transaction code (tx_code).
The suite's plan runner does neither, so this script stands in for the issuer's side: it watches the
suite for VCI issuer tests waiting at their credential offer or tx_code endpoint, asks the OP's
credential offer API for an offer of the grant the test runs, and hands it over. The OP mails a
transaction code to the user, and the driver reads it from the Mailpit container which catches the
OP's mail (docker/docker-compose.yml), the way the user would read it from their inbox.

Run it in the background for the length of the plan run, and stop it afterwards:

    python3 conformance-tests/vci-offer-driver.py &
    ./conformance-suite/scripts/run-test-plan.py ...
    kill %1

The defaults match the conformance OP of docker/docker-compose.yml and the suite's local URL.
"""

import argparse
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

GRANT_TYPES = {
    "authorization_code": "authorization_code",
    "pre_authorization_code": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
}

# The attributes of the "student" user of docker/ssp/authsources.php, so that a pre-authorized
# credential carries the same claims as one issued after that user logs in.
STUDENT_ATTRIBUTES = {
    "uid": ["student"],
    "eduPersonAffiliation": ["member", "student"],
    "eduPersonNickname": ["Sir_Nickname"],
    "displayName": ["Some User"],
    "givenName": ["Firsty"],
    "middle_name": ["Mid"],
    "sn": ["Lasty"],
    "labeledURI": ["https://example.com/student"],
    "jpegURL": ["https://example.com/student.jpg"],
    "mail": ["something@example.com"],
    "email_verified": ["yes"],
    "zoneinfo": ["Europe/Paris"],
    "updated_at": ["1621374126"],
    "preferredLanguage": ["fr-CA"],
    "website": ["https://example.com/student-blog"],
    "gender": ["female"],
    "birthdate": ["1945-03-21"],
    "eduPersonUniqueId": ["13579"],
    "phone_number_verified": ["yes"],
    "mobile": ["+1 (604) 555-1234;ext=5678"],
    "postalAddress": ["Place Charles de Gaulle, Paris"],
    "street_address": ["Place Charles de Gaulle"],
    "locality": ["Paris"],
    "region": ["Île-de-France"],
    "postal_code": ["75008"],
    "country": ["France"],
}

# Both servers run with development certificates.
TLS = ssl.create_default_context()
TLS.check_hostname = False
TLS.verify_mode = ssl.CERT_NONE


def log(message):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), "vci-offer-driver:", message, flush=True)


def request(url, data=None, headers=None, timeout=30):
    req = urllib.request.Request(url, data=data, headers=headers or {})
    with urllib.request.urlopen(req, context=TLS, timeout=timeout) as response:
        return response.read()


def get_json(url):
    return json.loads(request(url))


def delete(url):
    req = urllib.request.Request(url, method="DELETE")
    with urllib.request.urlopen(req, context=TLS, timeout=30) as response:
        return response.read()


def with_query(url, query):
    return url + ("&" if "?" in url else "?") + query


def may_have_reached(error):
    """Whether a failed call may have reached the server. urllib wraps in URLError only what fails while it
    connects or sends the request (refused, a name which does not resolve, a broken TLS handshake), which
    certainly did not; a failure while reading the answer is raised unwrapped, an HTTP error is the server's
    own answer, and a timeout may have come while the server was working on the request."""
    if isinstance(error, urllib.error.HTTPError):
        return True
    if isinstance(error, urllib.error.URLError):
        return isinstance(error.reason, TimeoutError)
    return True


class Driver:
    def __init__(self, args):
        self.suite = args.suite.rstrip("/") + "/"
        self.op_api = args.op_api
        self.token = args.token
        self.alias = args.alias
        self.credential_configuration_id = args.credential_configuration_id
        self.use_tx_code = args.use_tx_code
        self.mailpit = args.mailpit.rstrip("/") + "/"
        # Per test id: how many offers and tx_codes were delivered, and the tx_code of the last offer.
        self.delivered = {}

    def poll(self):
        for test_id in get_json(self.suite + "api/runner/running"):
            try:
                self.serve(test_id)
            except Exception as e:  # one test's trouble must not stop the others being served
                log("{}: {}".format(test_id, e))

    def serve(self, test_id):
        exposed = get_json(self.suite + "api/runner/" + test_id).get("exposed") or {}
        if "credential_offer_endpoint" not in exposed and "tx_code_endpoint" not in exposed:
            return
        info = get_json(self.suite + "api/info/" + test_id)
        if info.get("status") != "WAITING" or info.get("alias") != self.alias:
            return

        # A test announces every wait in its log. The exposed endpoints alone do not tell a wait for
        # an offer from the wait for the browser which follows one, as the offer endpoint stays
        # exposed, so a wait is served when the log holds more of them than were delivered.
        entries = get_json(self.suite + "api/log/" + test_id)
        offer_waits = sum(1 for e in entries if e.get("src") == "VCIWaitForCredentialOffer")
        tx_code_waits = sum(1 for e in entries if e.get("src") == "VCIWaitForTxCode")
        done = self.delivered.setdefault(test_id, {"offers": 0, "tx_codes": 0, "tx_code": None})

        if offer_waits > done["offers"] and "credential_offer_endpoint" in exposed:
            self.deliver_offer(test_id, info, exposed["credential_offer_endpoint"], done)
        elif tx_code_waits > done["tx_codes"] and "tx_code_endpoint" in exposed:
            self.deliver_tx_code(test_id, info, exposed["tx_code_endpoint"], done)

    def deliver_offer(self, test_id, info, endpoint, done):
        grant = (info.get("variant") or {}).get("vci_grant_type", "authorization_code")
        body = {
            "credential_configuration_id": self.credential_configuration_id,
            "grant_type": GRANT_TYPES[grant],
        }
        if grant == "pre_authorization_code":
            body["user_attributes"] = STUDENT_ATTRIBUTES
            body["use_tx_code"] = self.use_tx_code
            if self.use_tx_code:
                # Only the mail this offer sends is to be read back, so none is left from an earlier one.
                delete(self.mailpit + "api/v1/messages")

        answer = json.loads(request(
            self.op_api,
            data=json.dumps(body).encode(),
            headers={"Authorization": "Bearer " + self.token, "Content-Type": "application/json"},
        ))
        # The API answers the wallet invocation URI, openid-credential-offer://?credential_offer=...,
        # and the suite's offer endpoint takes the same query.
        query = urllib.parse.urlsplit(answer["credential_offer_uri"]).query
        offer = json.loads(urllib.parse.parse_qs(query)["credential_offer"][0])
        grant_object = offer.get("grants", {}).get(GRANT_TYPES[grant], {})
        # An offer without a tx_code object needs no code; the suite still asks for one, and gets none.
        tx_code = self.read_mailed_tx_code() if "tx_code" in grant_object else ""

        # Counted only now, just before the suite is called. A failure up to here (the OP's API, Mailpit) is
        # retried on the next poll with a fresh offer, while a call which reached the suite is never repeated:
        # the test would get an offer it is no longer waiting for.
        done["offers"] += 1
        done["tx_code"] = tx_code
        log("{} {} ({}): offer {} for {}".format(
            test_id, info.get("testName"), grant, done["offers"], json.dumps(offer.get("grants"))))
        # The suite runs the test on as far as its next wait before it answers.
        try:
            request(with_query(endpoint, query), timeout=120)
        except Exception as error:
            if not may_have_reached(error):
                done["offers"] -= 1  # never reached the suite: the next poll tries again, with a fresh offer
            raise

    def read_mailed_tx_code(self):
        """The transaction code the OP mailed with the offer just made: the API sends the mail before it
        answers, so it is the latest one Mailpit holds."""
        message = get_json(self.mailpit + "api/v1/message/latest")
        found = re.search(r"Transaction Code\D*?(\d+)", message.get("Text", ""))
        if found is None:
            raise RuntimeError("the latest mail carries no transaction code: {!r}".format(message.get("Subject")))
        return found.group(1)

    def deliver_tx_code(self, test_id, info, endpoint, done):
        tx_code = done["tx_code"]
        # Counted before the suite is called, which is all this delivery does, for the reason deliver_offer()
        # gives.
        done["tx_codes"] += 1
        log("{} {}: tx_code {} ({})".format(
            test_id, info.get("testName"), done["tx_codes"], "none offered" if tx_code == "" else "sent"))
        # The exposed endpoint carries a placeholder, ?code=your_tx_code, which the code replaces.
        parts = urllib.parse.urlsplit(endpoint)
        params = [(k, v) for k, v in urllib.parse.parse_qsl(parts.query, keep_blank_values=True) if k != "code"]
        query = urllib.parse.urlencode(params + [("code", tx_code)])
        try:
            request(urllib.parse.urlunsplit(parts._replace(query=query)), timeout=120)
        except Exception as error:
            if not may_have_reached(error):
                done["tx_codes"] -= 1  # never reached the suite: the next poll tries again
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--suite", default=os.environ.get("CONFORMANCE_SERVER", "https://localhost.emobix.co.uk:8443/"))
    parser.add_argument(
        "--op-api",
        default="https://op.local.stack-dev.cirrusidentity.com/simplesaml/module.php/oidc/api/vci/credential-offer")
    parser.add_argument("--token", default=os.environ.get("VCI_OFFER_API_TOKEN", "strong-random-token-string"))
    parser.add_argument("--alias", default="simplesamlphp-module-oidc-vci")
    parser.add_argument("--credential-configuration-id", default="ResearchAndScholarshipCredentialDcSdJwt")
    parser.add_argument("--use-tx-code", action="store_true", help="offer pre-authorized codes with a tx_code")
    parser.add_argument("--mailpit", default="http://127.0.0.1:8025/", help="where the OP's mail is read")
    parser.add_argument("--timeout", type=int, default=3600, help="seconds to run before giving up")
    args = parser.parse_args()

    driver = Driver(args)
    deadline = time.time() + args.timeout
    log("watching {} for tests of alias {}".format(driver.suite, driver.alias))
    while time.time() < deadline:
        try:
            driver.poll()
        except Exception as e:  # the suite may be busy or restarting; keep watching
            log("poll: {}".format(e))
        time.sleep(0.5)
    log("timed out after {} seconds".format(args.timeout))
    return 1


if __name__ == "__main__":
    sys.exit(main())
