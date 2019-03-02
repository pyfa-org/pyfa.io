'''
This code is directly from EsiPy <https://github.com/Kyria/EsiPy>.

EsiPY had a bit too much overhead for the context of a proxy server that only handles token fetching / refreshing on
behalf of another application. Additionally, the ESISecurity object kept data around between requests (as I understand
it), causing a possible security issues in a multi-user environment (would not want to accidently send someone else's
refresh token). Thus, we do the very basics here, and don't store any tokens.
'''

from urllib.parse import quote
from requests import Session
import config
import base64

sso_url = "https://login.eveonline.com"
oauth_authorize = '%s/oauth/authorize' % sso_url
oauth_token = '%s/oauth/token' % sso_url

_session = Session()
_session.headers.update({
    'Accept': 'application/json',
    'User-Agent': (
        'EsiPy/Security/ - '
        'https://github.com/Kyria/EsiPy'
    )
})

def get_auth_uri(scopes=None, state=None, implicit=False):
    s = [] if not scopes else scopes

    response_type = 'code' if not implicit else 'token'

    return '%s?response_type=%s&redirect_uri=%s&client_id=%s%s%s' % (
        oauth_authorize,
        'code',
        quote(config.ESI_CALLBACK, safe=''),
        config.ESI_CLIENT_ID,
        '&scope=%s' % '+'.join(s) if scopes else '',
        '&state=%s' % state if state else ''
    )

def __get_token_auth_header():
    """ Return the Basic Authorization header required to get the tokens

    :return: a dict with the headers
    """
    # encode/decode for py2/py3 compatibility
    auth_b64 = "%s:%s" % (config.ESI_CLIENT_ID, config.ESI_SECRET_KEY)
    auth_b64 = base64.b64encode(auth_b64.encode('latin-1'))
    auth_b64 = auth_b64.decode('latin-1')

    return {'Authorization': 'Basic %s' % auth_b64}

def __make_token_request_parameters(params):
    request_params = {
        'headers': __get_token_auth_header(),
        'data': params,
        'url': oauth_token,
    }

    return request_params


def get_access_token_request_params(code):
    return __make_token_request_parameters(
        {
            'grant_type': 'authorization_code',
            'code': code,
        }
    )

def auth(code):
    request_data = get_access_token_request_params(code)
    res = _session.post(**request_data)
    if res.status_code != 200:
        raise Exception(
            request_data['url'],
            res.status_code,
            res.json()
        )
    json_res = res.json()
    return json_res


def refresh(refresh_token):
    request_data = __make_token_request_parameters(
            {
                'grant_type': 'refresh_token',
                'refresh_token': refresh_token,
            }
        )
    res = _session.post(**request_data)
    if res.status_code != 200:
        raise Exception(
            request_data['url'],
            res.status_code,
            res.json()
        )
    json_res = res.json()
    return json_res
