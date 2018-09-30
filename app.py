from flask import Flask, jsonify, request, redirect
from flask_jwt_extended import (
    JWTManager, jwt_required, jwt_refresh_token_required,
    create_access_token, create_refresh_token,
    get_jwt_identity, get_jwt_claims,
    set_access_cookies, set_refresh_cookies, unset_jwt_cookies
)
from datetime import timedelta
from urllib.parse import urlparse, urljoin, urlencode, quote
from os import environ

# https://github.com/cyverse/caslib.py
from caslib import CASClient

# NOTE: This is just a basic example of how to enable cookies. This is
#       vulnerable to CSRF attacks, and should not be used as is. See
#       csrf_protection_with_cookies.py for a more complete example!

app = Flask(__name__)


##These settings will be used often
# https://login.org/path/login?service=https%3A%2F%2Fhostname.example%2Freports%2Ffoo%2Fpw_protected%2test.php
CAS_SERVER_URL = "https://login.org/path"
CAS_SERVICE_URL = "https://login.org/CAS_serviceValidater?sendback=" # + "?sendback="

# Configuration Options for flask_jwt_extended:
# https://flask-jwt-extended.readthedocs.io/en/latest/options.html
#

# Configure application to store JWTs in cookies. Whenever you make
# a request to a protected endpoint, you will need to send in the
# access or refresh JWT via a cookie.
app.config['JWT_TOKEN_LOCATION'] = ['cookies']

# How long an access token should live before it expires.
# This takes a datetime.timedelta, and defaults to 15 minutes.
# Can be set to False to disable expiration.
app.config['JWT_SESSION_COOKIE'] = False
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=10)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(minutes=10)

# Set the cookie paths, so that you are only sending your access token
# cookie to the access endpoints, and only sending your refresh token
# to the refresh endpoint. Technically this is optional, but it is in
# your best interest to not send additional cookies in the request if
# they aren't needed.
app.config['JWT_ACCESS_COOKIE_PATH'] = '/'
app.config['JWT_REFRESH_COOKIE_PATH'] = '/token/refresh'

app.config['JWT_ACCESS_COOKIE_NAME'] = 'myapp_jwt'
app.config['JWT_REFRESH_COOKIE_NAME'] = 'myapp_jwt_refresh'

# Disable CSRF protection for this example. In almost every case,
# this is a bad idea. See examples/csrf_protection_with_cookies.py
# for how safely store JWTs in cookies
app.config['JWT_COOKIE_CSRF_PROTECT'] = False

# Only allow JWT cookies to be sent over https. In production, this
# should likely be True
app.config['JWT_COOKIE_SECURE'] = False

# Setup the Flask-JWT-Extended extension
SECRET_KEY = environ.get('SECRET_KEY', 'super-secret')
app.config['JWT_SECRET_KEY'] = environ.get('JWT_SECRET_KEY', SECRET_KEY)  # FIXME : Change this! to configuration

jwt = JWTManager(app)


# Provide a method to create access tokens. The create_access_token()
# function is used to actually generate the token, and you can return
# it to the caller however you choose.
@app.route('/token/auth', methods=['GET'])
def login():
#    if not request.is_json:
#        return jsonify({"msg": "Missing JSON in request"}), 400

#    cas_client = CASClient(CAS_SERVER_URL,
#                           quote(SERVICE_URL, safe='/', encoding=None, errors=None) # + "/hmm where to go"
#
#                           )
#    ticket_from_cas = request.GET['ticket']
#    cas_response = cas_client.cas_serviceValidate(ticket_from_cas)
    #cas_response object
#    (truth, user) = (cas_response.success, cas_response.user)
    # if (truth) redirect(user,sendback) else redirect(CASLoginURL)

    username = "testUserName"
    # username        = cas.username,
    # display_name    = cas.attributes['cas:displayName']
    # cas_token       = cas.token

    # Using the user_claims_loader, we can specify a method that will be
    # called when creating access tokens, and add these claims to the said
    # token. This method is passed the identity of who the token is being
    # created for, and must return data that is json serializable
    @jwt.user_claims_loader
    def add_claims_to_access_token(identity):
        return {
            'user': identity,
            'roles': ['bar', 'baz'],
            'rights': ['foo', 'nix', 'all']
        }

    # expires = timedelta(minutes=11)

    # Create the tokens we will be sending back to the user
    # Identity can be any data that is json serializable
    access_token  = create_access_token(identity=username, fresh=True) # , expires_delta=expires
    refresh_token = create_refresh_token(identity=username) # , expires_delta=expires


    resp = redirect("/token/protected?sendback=/test/location", code=302)

    # Set the JWT cookies in the response
    # resp = jsonify({'login': True})
    set_access_cookies(resp, access_token)
    set_refresh_cookies(resp, refresh_token)

    return resp

    #return redirect("/protected?sendback=/test/location", code=302)
    # return resp, 201, {'location': '/protected?sendback=/test/location'}
    #response = jsonify()
#    resp.status_code = 201
#    resp.headers['location'] = '/protected?sendback=/test/location'
#    resp.autocorrect_location_header = False
#    return resp

# Same thing as login here, except we are only setting a new cookie
# for the access token.
@app.route('/token/refresh', methods=['GET'])
@jwt_refresh_token_required
def refresh():
    # Create the new access token
    current_user = get_jwt_identity()

    @jwt.user_claims_loader
    def add_claims_to_access_token(identity):
        return get_jwt_claims()

    access_token = create_access_token(identity=current_user, fresh=False)

    # Set the JWT access cookie in the response
    resp = jsonify({'refresh': True})
    set_access_cookies(resp, access_token)
    return resp, 200

# Because the JWTs are stored in an httponly cookie now, we cannot
# log the user out by simply deleting the cookie in the frontend.
# We need the backend to send us a response to delete the cookies
# in order to logout. unset_jwt_cookies is a helper function to
# do just that.
@app.route('/token/remove', methods=['GET'])
def logout():
    resp = jsonify({'logout': True})
    unset_jwt_cookies(resp)
    return resp, 200


# Protect a view with jwt_required, which requires a valid access token
# in the request to access.
@app.route('/token/protected', methods=['GET'])
@jwt_required
def protected():
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()

    claims = get_jwt_claims()

    referrer = request.referrer
    redir_target = get_redirect_target()

    return jsonify(logged_in_as=current_user, referrer=referrer, redir_target=redir_target, claims=claims), 200


@app.route('/token/redirect')
def redirect_request():
    return redirect("/token/auth?sendback=/token/protected", code=302)


def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc


def get_redirect_target():
    for target in request.args.get('sendback'), request.referrer:
        if not target:
            continue
        if is_safe_url(target):
            return target

if __name__ == '__main__':
    app.run()
