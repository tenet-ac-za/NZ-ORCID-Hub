from flask import jsonify, request, _request_ctx_stack
from flask_login import current_user, login_required
from werkzeug.local import LocalProxy

from application import app
from models import User, ApiToken
from functools import wraps
import jwt
from datetime import datetime, timedelta
import base64
import random

JWT_EXPIRATION_DELTA = timedelta(days=365)
JWT_NOT_BEFORE_DELTA = timedelta(seconds=0)


current_identity = LocalProxy(lambda: getattr(_request_ctx_stack.top, 'current_identity', None))

class JWTError(Exception):
    def __init__(self, error, description, status_code=401, headers=None):
        self.error = error
        self.description = description
        self.status_code = status_code
        self.headers = headers

    def __repr__(self):
        return 'JWTError: %s' % self.error

    def __str__(self):
        return '%s. %s' % (self.error, self.description)


def jwt_required(realm=None):

    if realm is None:
        realm = app.name

    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):

            auth_header_value = request.headers.get("Authorization", None)

            if auth_header_value:
                parts = auth_header_value.split()

                if parts[0].lower() != "jwt".lower():
                    raise JWTError("Invalid JWT header", "Unsupported authorization type")
                elif len(parts) == 1:
                    raise JWTError("Invalid JWT header", "Token missing")
                elif len(parts) > 2:
                    raise JWTError("Invalid JWT header", "Token contains spaces")
                token = parts[1]

                try:
                    payload = jwt.decode(token, app.secret_key)
                except jwt.InvalidTokenError as e:
                    raise JWTError("Invalid token", str(e))
            else:
                raise JWTError(
                    "Authorization Required",
                    "Request does not contain an access token",
                    headers={"WWW-Authenticate": 'JWT realm="%s"' % realm})

            user_id = payload['identity']
            try:
                user = User.get(id=user_id)
            except User.DoesNotExist:
                raise JWTError("Invalid JWT", "User does not exist")

            _request_ctx_stack.top.current_identity = user

            return fn(*args, **kwargs)

        return decorated_view

    return wrapper


def auth_required(realm=None):

    if realm is None:
        realm = app.name

    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):

            auth_header_value = request.headers.get("Authorization", None)

            if auth_header_value:
                parts = auth_header_value.split()

                if parts[0].lower() != "api".lower():
                    raise JWTError("Invalid API header", "Unsupported authorization type")
                elif len(parts) == 1:
                    raise JWTError("Invalid API header", "Token missing")
                elif len(parts) > 2:
                    raise JWTError("Invalid API header", "Token contains spaces")
                token = parts[1]

                try:
                    payload = ApiToken.get(token=token)
                except ApiToken.DoesNotExist:
                    raise JWTError("Invalid token", str(e))
            else:
                raise JWTError(
                    "Authorization Required",
                    "Request does not contain an access token",
                    headers={"WWW-Authenticate": 'JWT realm="%s"' % realm})

            _request_ctx_stack.top.current_identity = token.user

            return fn(*args, **kwargs)

        return decorated_view

    return wrapper


@app.route("/get_api_token")
@login_required
def get_api_token():
    # iat = datetime.utcnow()  # issued at
    # exp = iat + JWT_EXPIRATION_DELTA  # expires in one year
    # nbf = iat + JWT_NOT_BEFORE_DELTA
    # identity = current_user.id
    # payload = dict(iat=iat, exp=exp, nbf=nbf, identity=identity)
    token = base64.b64encode(("%i" % random.randint(1,100000000000)).encode("ascii")).decode("ascii")
    ##jwt.encode(payload, app.secret_key)
    ApiToken.create(token=token, org=current_user.organisation, user_id=current_user.id)
    return token


@app.route("/api/me")
@jwt_required()
def me():
    user = current_identity
    return jsonify(dict(name=user.name))

@app.route("/api/my_org")
@auth_required()
def test_auth():
    user = current_identity
    return jsonify(dict(name=user.name))

