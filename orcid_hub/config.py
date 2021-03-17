# -*- coding: utf-8 -*-
"""Application configuration."""

from os import environ, getenv, path, getcwd

ENV = getenv("ENV", "dev")
SHIBBOLETH_DISABLED = getenv("SHIBBOLETH_DISABLED")

ORCID_API_HOST_URL = "https://api.sandbox.orcid.org/" if ENV != "prod" else "https://api.orcid.org/"
ORCID_API_VERSION = "v2.0"
ORCID_API_BASE = ORCID_API_HOST_URL + ORCID_API_VERSION + '/'
ORCID_BASE_URL = "https://sandbox.orcid.org/" if ENV != "prod" else "https://orcid.org/"

# NB! Set up the key. See: http://flask.pocoo.org/docs/latest/quickstart/#sessions
SECRET_KEY = getenv("SECRET_KEY", b'\xf4\xf7\x03D\xd5\xe9i\xf8\x190\xef\x81\x05\xdcI\x01r\x8f\x10\xe1\xbfU93')
SENTRY_DSN = getenv("SENTRY_DSN")

# TODO: Soon to be depricated:
SALT = getenv("TOKEN_PASSWORD_SALT")

# NZ ORCIDHUB API client ID and secret
ORCID_CLIENT_ID = getenv("ORCID_CLIENT_ID")
ORCID_CLIENT_SECRET = getenv("ORCID_CLIENT_SECRET")

# Change the URL as per the enviornment
AUTHORIZATION_BASE_URL = 'https://sandbox.orcid.org/oauth/authorize' \
    if ENV != "prod" else "https://orcid.org/oauth/authorize"
TOKEN_URL = 'https://sandbox.orcid.org/oauth/token' if ENV != "prod" else "https://orcid.org/oauth/token"

# Database connection url
DATABASE_URL = getenv("DATABASE_URL", "sqlite:///data.db")
BACKUP_DATABASE_URL = getenv("BACKUP_DATABASE_URL")
LOAD_TEST = getenv("LOAD_TEST")

# NB! Disable in production
if ENV in ("dev0", ):
    DEBUG = '1'
    MAIL_DEBUG = '1'
    TESTING = True
    DEBUG_TB_INTERCEPT_REDIRECTS = False
    DEBUG_TB_PROFILER_ENABLED = True
    OAUTHLIB_INSECURE_TRANSPORT = '1'
    environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    TEMPLATES_AUTO_RELOAD = True
    # EXPLAIN_TEMPLATE_LOADING = True

if "DEBUG" not in dir():
    PREFERRED_URL_SCHEME = "https"

OAUTH2_PROVIDER_TOKEN_EXPIRES_IN = 86400  # Default Bearer token expires time, default is 3600.

# add mail server config
MAIL_PORT = int(getenv("MAIL_PORT", 25))
MAIL_SUPPRESS_SEND = False
MAIL_DEFAULT_SENDER = getenv("MAIL_DEFAULT_SENDER", "no-reply@intembeko.orcid.ac.za")
MAIL_SERVER = getenv("MAIL_SERVER", "monitor.tenet.ac.za")
MAIL_DKIM_DOMAIN = getenv("MAIL_DKIM_DOMAIN", "orcid.ac.za")
MAIL_DKIM_SELECTOR = getenv("MAIL_DKIM_SELECTOR", "intembeko2021")

MEMBER_API_FORM_BASE_URL = "https://orcid.org/content/register-client-application-sandbox" \
    if ENV != "prod" else "https://orcid.org/content/register-client-application-production-trusted-party"

NOTE_ORCID = 'An Intembeko ORCID Hub integration for'
CRED_TYPE_PREMIUM = 2
APP_NAME = 'Intembeko ORCID HUB'
APP_DESCRIPTION = 'This is an ORCID integration through the Intembeko ORCID HUB connecting'
APP_URL = "https://" + (ENV + ".intembeko.orcid.ac.za" if ENV != "prod" else "intembeko.orcid.ac.za")
SEED_HUB_ADMIN = getenv("SEED_HUB_ADMIN", "orcid@tenet.ac.za")

# External Shibboleth SP login URL (e.g., https://intembeko.orcid.ac.za/saml/login)
EXTERNAL_SP = getenv("EXTERNAL_SP") if ENV != "prod" else None
# Attribute map for external SP
EXTERNAL_SP_ATTR_EPPN = getenv("EXTERNAL_SP_ATTR_EPPN", "eppn")
EXTERNAL_SP_ATTR_SN = getenv("EXTERNAL_SP_ATTR_SN", "sn")
EXTERNAL_SP_ATTR_GIVENNAME = getenv("EXTERNAL_SP_ATTR_GIVENNAME", "givenName")
EXTERNAL_SP_ATTR_MAIL = getenv("EXTERNAL_SP_ATTR_MAIL", "mail")
EXTERNAL_SP_ATTR_DISPLAYNAME = getenv("EXTERNAL_SP_ATTR_DISPLAYNAME", "displayName")
EXTERNAL_SP_ATTR_ORG = getenv("EXTERNAL_SP_ATTR_ORG", "schacHomeOrganization")
EXTERNAL_SP_ATTR_AFFILIATION = getenv("EXTERNAL_SP_ATTR_AFFILIATION", "unscoped-affiliation")
EXTERNAL_SP_ATTR_ORCID = getenv("EXTERNAL_SP_ATTR_ORCID", "eduPersonOrcid")

DEFAULT_COUNTRY = "ZA"

if ENV == "dev":
    GA_TRACKING_ID = "265937145"
else:
    GA_TRACKING_ID = "265977402"

DEFAULT_EMAIL_TEMPLATE = """<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>{SUBJECT}</title>
    <meta name="keywords" content="ORCID HUB,Intembeko,ZA,orcid"/>
  </head>
  <body>
    <div style="font-family: Arial, Verdana, Georgia, and Times New Roman; background-color: white; color: black;">
      <table style="vertical-align: middle; background-color: black; color: white; width: 100%;">
        <tr>
          <td>&nbsp;</td>
          <td align="right">
            <img src="{LOGO}" title="Intembeko ORCID Hub" alt="Intembeko ORCID Hub" style="display:block;" />
          </td>
        </tr>
      </table>
      {MESSAGE}
      <p>If you received this email in error, or you have questions about the responsibilities
      involved, please contact: <a href="mailto:orcid@tenet.ac.za">
      orcid@tenet.ac.za</a></p>
      <p>For information about ORCID go to the
      <a href="https://www.tenet.ac.za/services/orcid/">What is ORCID?</a>
       page of our website.</p>
      <hr>
      <p>This email was sent to <a href="mailto:{EMAIL}">{EMAIL}</a></p>
      <!--  Footer Details -->
      <table style="vertical-align: top; background-color: black; color: white; width: 100%; margin-top: 25px;">
        <tr>
          <td>
            <p style="vertical-align: top; padding-left: 15px;">
            Contact details for the Intembeko ORCID Hub<br>
            Phone: +27.21.763.7147<br>
            <b><a style="text-decoration: none; color: white;"
                  href="mailto:orcid@tenet.ac.za">orcid@tenet.ac.za</a></b>
            </p>
          </td>
          <td style="vertical-align: top;">
            <p class="copyright"><a href="https://creativecommons.org/licenses/by/4.0/"
            target="_blank"><img
            src="{BASE_URL}/static/images/CC-BY-icon-80x15.png" alt="CC-BY" /></a></p>
          </td>
        </tr>
      </table>
    </div>
  </body>
</html>
"""

DKIM_KEY_PATH = path.join(getcwd(), ".keys", "dkim.key")

# RQ:
RQ_REDIS_URL = getenv("RQ_REDIS_URL")
RQ_QUEUE_CLASS = "orcid_hub.queuing.ThrottledQueue"
RQ_CONNECTION_CLASS = getenv("RQ_CONNECTION_CLASS", "redis.StrictRedis")
RQ_ASYNC = getenv("RQ_ASYNC", True)
if isinstance(RQ_ASYNC, str):
    RQ_ASYNC = RQ_ASYNC.lower() in ["true", "1", "yes", "on"]

# rq-dashboard config:
RQ_POLL_INTERVAL = 5000  #: Web interface poll period for updates in ms
WEB_BACKGROUND = "gray"

# Other flask settings
JSONIFY_PRETTYPRINT_REGULAR = True

# Caching
CACHE_TYPE = "simple"
# CACHE_DEFAULT_TIMEOUT = 600
