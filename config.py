# -*- encoding: utf-8 -*-
import datetime
import os

# -----------------------------------------------------
# Application
# ------------------------------------------------------
DEBUG = True
SECRET_KEY = os.environ['SECRET_KEY'].encode()
PORT = 5015
HOST = 'localhost'

# -----------------------------------------------------
# ESI Configs
# -----------------------------------------------------
ESI_DATASOURCE = 'tranquility'  # Change it to 'singularity' to use the test server
ESI_SWAGGER_JSON = 'https://esi.tech.ccp.is/latest/swagger.json?datasource=%s' % ESI_DATASOURCE
ESI_SECRET_KEY = os.environ['ESI_SECRET_KEY']  # your secret key
ESI_CLIENT_ID = '0b3d8699bab149a18838d5183507b5ab'  # your client ID
ESI_CALLBACK = 'https://www.pyfa.io/sso/callback' # the callback URI you gave CCP
ESI_USER_AGENT = 'pyfa-esipy'

# ------------------------------------------------------
# Session settings for flask login
# ------------------------------------------------------
PERMANENT_SESSION_LIFETIME = datetime.timedelta(days=30)

# ------------------------------------------------------
# CI/CD auto update 
# ------------------------------------------------------
TRIGGER_REF = 'refs/heads/main'
