"""OAuth support for provider."""

from datetime import datetime, timedelta

from flask import render_template, request
from flask_login import current_user, login_required

from . import app, oauth
from .models import Client, Grant, Token


@oauth.clientgetter
def load_client(client_id):  # noqa: D103
    try:
        return Client.get(client_id=client_id)
    except Client.DoesNotExist:
        return None


@oauth.grantgetter
def load_grant(client_id, code):  # noqa: D103 pragma: no cover
    try:
        return Grant.get(client_id=client_id, code=code)
    except Grant.DoesNotExist:
        return None


@oauth.grantsetter
def save_grant(client_id, code, request, *args, **kwargs):  # noqa: D103 pragma: no cover
    expires = datetime.utcnow() + timedelta(seconds=100)
    return Grant.create(
        client=Client.get(client_id=client_id),
        code=code["code"],
        redirect_uri=request.redirect_uri,
        _scopes=' '.join(request.scopes),
        user=current_user,
        expires=expires)


@oauth.tokengetter
def load_token(access_token=None, refresh_token=None):  # noqa: D103
    return Token.select().where(
        Token.expires >= datetime.now(),
        (Token.access_token == access_token) if access_token is not None else
        (Token.refresh_token == refresh_token)).first()


@oauth.tokensetter
def save_token(token, request, *args, **kwargs):  # noqa: D103

    Token.delete().where(Token.expires < datetime.now()).execute()

    expires_in = token.get("expires_in")
    expires = datetime.utcnow() + timedelta(seconds=expires_in)

    return Token.create(
        access_token=token["access_token"],
        refresh_token=token.get("refresh_token"),
        token_type=token["token_type"],
        _scopes=token["scope"],
        expires_in=expires_in,
        expires=expires,
        client=request.client,
        user=request.user)


@app.route("/oauth/authorize", methods=["GET", "POST"])
@login_required
@oauth.authorize_handler
def authorize(*args, **kwargs):  # noqa: D103 pragma: no cover
    if request.method == "GET":
        client_id = kwargs.get("client_id")
        client = Client.query.filter_by(client_id=client_id).first()
        kwargs["client"] = client
        return render_template("oauthorize.html", **kwargs)

    confirm = request.form.get("confirm", "no")
    return confirm == "yes"


@app.route("/oauth/token", methods=["POST"])
@oauth.token_handler
def access_token():  # noqa: D103
    return None
