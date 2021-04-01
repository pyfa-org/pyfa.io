# pyfa.io

pyfa.io is the proxy server that sits between pyfa and EVE SSO, assisting with logging users into their EVE characters securely.

## tl;dr

OAuth Basics
1) Characters within pyfa are linked to their characters in the game via EVE SSO, allowing pyfa to pull live character data (for things like skill syncing)
2) EVE SSO is based on OAuth, an industry standard mechanism for linking third-party applications (pyfa) with a server resource (EVE) on behalf of a resource owner (user). 
3) EVE SSO provides "access tokens" and "refresh tokens". Access tokens allow pyfa to access character data, and is short-lived. Refresh tokens allow pyfa to refresh the access token when the previous one expires
4) In order to get a refresh token, the authorization flow requires the pyfa client secret to be known and sent. This client secret is supposed to only be known to pyfa developers to prevent abuse of the system, and thus cannot ship with the pyfa package. This is where pyfa.io comes in.

pyfa.io
1) Because EVE SSO uses OAuth, pyfa.io never collects or intercepts your account login details (username, password, 2FA code, etc).
2) pyfa.io sits in between pyfa and the EVE SSO, allowing pyfa to request access/refresh tokens for it's own use, without exposing the pyfa client secret to anyone.
3) pyfa.io is only used for initial sign on and when retreiving a refresh token. All other calls to fetch data from the EVE API happen soley on the client (pyfa) side, using the access token.
4) While pyfa.io is the default method of signing in, it is optional. If you wish to set up your own application, please see https://github.com/pyfa-org/Pyfa/wiki/EVE-SSO. This will eliminate any third-party enity between pyfa and EVE SSO.

## Setup

todo

## Flow

Mostly taken from https://github.com/pyfa-org/Pyfa/wiki/pyfa.io-Authentication-Workflow

There are two methods of reporting the token data back to pyfa
- Server: pyfa starts a small local server on a randomized port, and sends the details to pyfa.io. When pyfa.io gets token data, it's reports this data to that server, and the local server shuts down.
- Manual: pyfa opens a window with a text box. When pyfa.io get the token data, it displays a webpage with the encoded token data. The user then copies and pastes it into pyfa.

1. When the user initiates a login, pyfa opens a web browser and directs user to `https://pyfa.io/oauth/authorize`. 

2. The web server then redirects the user to EVE's SSO

3. After logging in, EVE SSO redirects back to pyfa's web app with an authentication code.

4. The webserver then uses it's client ID and secret, bundled with the authentication code, to fetch an access token and refresh token from the EVE SSO system. This ensures that we can keep pyfa's client secret a secret.

6a. (if using Server Method) The web application then sends the information needed back to the pyfa client

6b. (if using Manual Method) The web application then displays information for the user to copy and paste into pyfa to save character login information.

7. pyfa encrypts the refresh token with a key unique to that client and saves it in the database, along with the limited-time access token 

Refreshing access token:

1. pyfa decrypts the refresh token using it's client key

2. pyfa HTTP POST's refresh token to pyfa's web server, which makes the call to EVE SSO to get a new access token

3. Web server responds to pyfa's request with a new access token and expiration time.

## Deploying

pyfa.io automatically updates whenever a merge into main branch happens. Deploying is done via a simple web hook, that POSTs to pyfa.io and instructs it to pull the latest commit and restart the server. Eventually, we would like GitHub actions to be the one to do it (via ssh) so that it's not reliant on the server being online and accepting requests, but it is what it is for now.
