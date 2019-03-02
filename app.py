# -*- encoding: utf-8 -*-
from flask import Flask
from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask import abort
from flask import jsonify
from flask import send_from_directory

import requests
from requests.auth import HTTPBasicAuth

# set the project root directory as the static folder, you can set others.
app = Flask(__name__, static_url_path='')

@app.route('/static/<path:file>', defaults={'file': 'index.html'})
def serve_results(file):
    # Haven't used the secure way to send files yet
    return send_from_directory(app.config['RESULT_STATIC_PATH'], file)

import esi

import config
import hashlib
import hmac
import logging
from logging.handlers import RotatingFileHandler
import random
import base64
import json
import time
import os

# logger stuff
logger = logging.getLogger(__name__)
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
console = logging.StreamHandler()
console.setLevel(logging.DEBUG)
console.setFormatter(formatter)
logger.addHandler(console)

# init app and load conf
app = Flask(__name__)
app.config.from_object(config)

scopes = [
    'esi-skills.read_skills.v1',
    'esi-fittings.read_fittings.v1',
    'esi-fittings.write_fittings.v1'
]

cache = {}

releases_cache = {
    'data': None,
    'time': None
}

def generate_token():
    """Generates a non-guessable OAuth token"""
    chars = ('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
    rand = random.SystemRandom()
    random_string = ''.join(rand.choice(chars) for _ in range(40))
    return hmac.new(
        config.SECRET_KEY,
        random_string.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()


@app.route('/oauth/authorize')
def login():
    """ This is the first step in oauth flow. When a user logs into EVE from pyfa, pyfa directs them to this URL along
    with where to redirect the user to after logging in (pyfa's server) and pyfa state token to prevent malicious requests
    """

    session['pyfa-state'] = request.args.get('state')
    session['pyfa-redirect'] = request.args.get('redirect')
    session['pyfa-login-method'] = int(request.args.get('login_method'))

    myCache = {
        'pyfa-state': request.args.get('state'),
        'pyfa-redirect': request.args.get('redirect'),
        'pyfa-login-method': int(request.args.get('login_method'))
    }

    token = generate_token()
    session['token'] = token
    uri = esi.get_auth_uri(
        scopes=scopes,
        state=token,
    )

    cache[token] = myCache

    # app.logger.info("Sending {} to EVE SSO, current cache contents: {}".format(token, cache))

    return redirect(uri)

@app.route('/oauth/token', methods=['POST'])
def token():
    """ This route does the refresh token
    """
    if request.values.get('grant_type') != 'refresh_token':
        return abort(400)

    try:
        json_resp = esi.refresh(request.values.get('refresh_token'))
    except Exception as ex:
        return jsonify(ex.args[2]), ex.args[1]

    return jsonify(json_resp)

@app.route('/sso/callback')
def callback():
    """ This is where the user comes after he logged in SSO """
    # get the code from the login process
    code = request.args.get('code')
    token = request.args.get('state')

    # app.logger.info("Got {}, current cache contents: {}".format(token, cache))

    pop = cache.pop(token, None)

    # app.logger.info("---- Popping cache: {}, new contents: {}".format(pop, cache))

    pyfa_state = session['pyfa-state']
    pyfa_redirect = session['pyfa-redirect']

    # compare the state with the saved token for CSRF check
    sess_token = session.pop('token', None)
    if sess_token is None or token is None or token != sess_token:
        return 'Login EVE Online SSO failed: Session Token Mismatch', 403

    # now we try to get tokens
    try:
        auth_response = esi.auth(code)
    except Exception as e:
        return 'Login EVE Online SSO failed: %s' % e, 403

    print("redirecting to ",pyfa_redirect)

    ssoInfo = base64.b64encode(json.dumps(auth_response).encode('utf-8'))

    if session['pyfa-login-method'] == 0:
        # server
        return redirect(pyfa_redirect + '/?state=' + session['pyfa-state'] + '&SSOInfo=' + ssoInfo.decode('utf-8'))
    else:
        # manual
        return render_template('ssoInfo.html', ssoInfo=ssoInfo)


@app.route('/update_check')
def update_check():

    if releases_cache['data'] is None or (time.time() - releases_cache.get('time', time.time()-(60 * 5 * 100))) >= (60 * 5):  # 5 min cache
        resp = requests.get("https://api.github.com/repos/pyfa-org/Pyfa/releases", auth=HTTPBasicAuth(os.environ['GITHUB_USER'], os.environ['GITHUB_PASS']))
        releases_cache['data'] = resp.json()
        releases_cache['time'] = time.time()

    return jsonify(releases_cache['data'])


@app.route('/ping')
def thing():
    return 'pong', 200



@app.route('/cookie_check')
def cookie_check():
    return render_template('cookie_check.html')


@app.route('/log_test')
def log_test():
    # app.logger.warning('A warning occurred (%d apples)', 42)
    # app.logger.error('An error occurred')
    # app.logger.info('Info')
    return "foo"

# -----------------------------------------------------------------------
# Index Routes
# -----------------------------------------------------------------------
@app.route('/')
def index():
    return "pyfa auth"

handler = RotatingFileHandler('foo.log', maxBytes=10000, backupCount=1)
handler.setLevel(logging.INFO)
# app.logger.addHandler(handler)


if __name__ == '__main__':
    app.run(port=config.PORT, host=config.HOST, threaded=True)

