""" Copyright start
  Copyright (C) 2008 - 2021 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from requests import request
from time import time, ctime
from os import path
from adal import AuthenticationContext
from datetime import datetime
from configparser import RawConfigParser
from base64 import b64encode, b64decode
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('azure-active-directory')

CONFIG_SUPPORTS_TOKEN = True
try:
    from connectors.core.utils import update_connnector_config
except:
    CONFIG_SUPPORTS_TOKEN = False
    configfile = path.join(path.dirname(path.abspath(__file__)), 'config.conf')

REFRESH_TOKEN_FLAG = False

# authorization types
AUTH_BEHALF_OF_USER = "On behalf of User - Delegate Permission"
AUTH_USING_APP = "Without a User - Application Permission"

# redirect url
DEFAULT_REDIRECT_URL = 'https://localhost/myapp'

# grant types
CLIENT_CREDENTIALS = 'client_credentials'
AUTHORIZATION_CODE = 'authorization_code'
REFRESH_TOKEN = 'refresh_token'


class MicrosoftAuth:

    def __init__(self, config):
        self.client_id = config.get("client_id")
        self.client_secret = config.get("client_secret")
        self.verify_ssl = config.get('verify_ssl')
        self.host = config.get("resource")
        if self.host[:7] == "http://":
            self.host = "https://{0}".format(self.host)
        elif self.host[:8] == "https://":
            self.host = "{0}".format(self.host)
        else:
            self.host = "https://{0}".format(self.host)
        tenant_id = config.get('tenant_id')
        self.auth_url = 'https://login.microsoftonline.com/{0}'.format(tenant_id)
        # depend on the auth type we add the class members.
        self.auth_type = config.get("auth_type")
        if self.auth_type == AUTH_BEHALF_OF_USER:
            self.refresh_token = ""
            self.code = config.get("code")
            self.scope = 'https://graph.microsoft.com/.default'
            self.token_url = "https://login.microsoftonline.com/{0}/oauth2/v2.0/token".format(tenant_id)
            if not config.get("redirect_url"):
                self.redirect_url = DEFAULT_REDIRECT_URL
            else:
                self.redirect_url = config.get("redirect_url")

    def convert_ts_epoch(self, ts):
        datetime_object = datetime.strptime(ctime(ts), "%a %b %d %H:%M:%S %Y")
        return datetime_object.timestamp()

    def encode_token(self, token):
        try:
            token = token.encode('UTF-8')
            return b64encode(token)
        except Exception as err:
            logger.error(err)

    def generate_token(self, REFRESH_TOKEN_FLAG):
        try:
            if not self.auth_type == AUTH_BEHALF_OF_USER:
                ac = AuthenticationContext(self.auth_url)
                token_resp = ac.acquire_token_with_client_credentials(self.host, self.client_id, self.client_secret)
                ts = token_resp.get('expiresOn')
                datetime_object = datetime.strptime(ts, '%Y-%m-%d %H:%M:%S.%f')
                token_resp['expiresOn'] = datetime_object.timestamp()
                return token_resp
            else:
                resp = self.acquire_token_on_behalf_of_user(REFRESH_TOKEN_FLAG)
                ts_now = time()
                resp['expiresOn'] = (ts_now + resp['expires_in']) if resp.get("expires_in") else None
                resp['accessToken'] = resp.get("access_token")
                resp.pop("access_token")
                return resp

        except Exception as err:
            try:
                logger.error("{0}".format(err.error_response['error_description']))
                raise ConnectorError("{0}".format(err.error_response['error_description']))
            except:
                logger.error("{0}".format(err))
                raise ConnectorError("{0}".format(err))

    def write_config(self, token_resp, config, section_header):
        time_key = ['expiresOn']
        token_key = ['accessToken']

        config.add_section(section_header)
        for key, val in token_resp.items():
            if key not in time_key and key not in token_key:
                config.set(section_header, str(key), str(val))
        for key in time_key:
            config.set(section_header, str(key), self.convert_ts_epoch(token_resp['expiresOn']))
        for key in token_key:
            config.set(section_header, str(key), self.encode_token(token_resp[key]).decode('utf-8'))

        try:
            with open(configfile, 'w') as fobj:
                config.write(fobj)
                fobj.close()
            return config
        except Exception as err:
            logger.error("{0}".format(str(err)))
            raise ConnectorError("{0}".format(str(err)))

    def handle_config(self, section_header, flag=False):
        # Lets setup the config parser.
        config = RawConfigParser()
        try:
            if path.exists(configfile) is False:
                token_resp = self.generate_token(REFRESH_TOKEN_FLAG)
                return self.write_config(token_resp, config, section_header)
            else:
                # Read existing config
                config.read(configfile)
                # Check for user
                if not config.has_section(section_header) and not flag:
                    # Write new config
                    token_resp = self.generate_token(REFRESH_TOKEN_FLAG)
                    return self.write_config(token_resp, config, section_header)
                else:
                    if flag:
                        config.remove_section(section_header)
                        with open(configfile, "w") as f:
                            config.write(f)
                    else:
                        config.read(config)
                return config

        except Exception as err:
            logger.error("Handle_config:Failure {0}".format(str(err)))
            raise ConnectorError(str(err))

    def validate_token(self, connector_config, connector_info):
        if CONFIG_SUPPORTS_TOKEN:
            ts_now = time()
            if not connector_config.get('accessToken'):
                logger.error('Error occurred while connecting server: Unauthorized')
                raise ConnectorError('Error occurred while connecting server: Unauthorized')
            expires = connector_config['expiresOn']
            expires_ts = self.convert_ts_epoch(expires)
            if ts_now > float(expires_ts):
                REFRESH_TOKEN_FLAG = True
                logger.info("Token expired at {0}".format(expires))
                self.refresh_token = connector_config["refresh_token"]
                token_resp = self.generate_token(REFRESH_TOKEN_FLAG)
                connector_config['accessToken'] = token_resp['accessToken']
                connector_config['expiresOn'] = token_resp['expiresOn']
                connector_config['refresh_token'] = token_resp.get('refresh_token')
                update_connnector_config(connector_info['connector_name'], connector_info['connector_version'],
                                         connector_config,
                                         connector_config['config_id'])

                return "Bearer {0}".format(connector_config.get('accessToken'))
            else:
                logger.info("Token is valid till {0}".format(expires))
                return "Bearer {0}".format(connector_config.get('accessToken'))
        else:
            client_id = connector_config.get('client_id')
            section_header = 'Microsoft-API-Auth-{0}'.format(client_id)
            time_key = ['expiresOn']
            token_key = ['accessToken']
            try:
                config = self.handle_config(section_header)
                ts_now = time()
                expires = config.get(section_header, 'expiresOn')
                if ts_now > float(expires):
                    REFRESH_TOKEN_FLAG = True
                    self.refresh_token = config.get(section_header, 'refresh_token')
                    logger.info("Token expired at {0}".format(str(expires)))
                    new_token = self.generate_token(REFRESH_TOKEN_FLAG)
                    for key, val in new_token.items():
                        if key in time_key:
                            config.set(section_header, str(key), self.convert_ts_epoch(new_token.get(key)))
                        if key in token_key:
                            config.set(section_header, str(key), self.encode_token(new_token[key]).decode('utf-8'))

                    with open(configfile, 'w') as fobj:
                        config.write(fobj)
                else:
                    logger.info("Token is valid till {0}".format(str(expires)))

                encoded_token = config.get(section_header, 'accessToken')
                decoded_token = b64decode(encoded_token.encode('utf-8'))
                token = "Bearer {0}".format(decoded_token.decode('utf-8'))
                return token
            except Exception as err:
                logger.error("{0}".format(str(err)))
                raise ConnectorError("{0}".format(str(err)))

    def remove_config(self):
        try:
            section_header = 'Microsoft-API-Auth-{0}'.format(self.client_id)
            self.handle_config(section_header, flag=True)
        except Exception as err:
            logger.error("{0}".format(str(err)))
            raise ConnectorError("{0}".format(str(err)))

    def acquire_token_on_behalf_of_user(self, REFRESH_TOKEN_FLAG):
        try:
            post_data = {
                "client_id": self.client_id,
                "scope": self.scope,
                "client_secret": self.client_secret,
                "redirect_uri": self.redirect_url
            }

            if not REFRESH_TOKEN_FLAG:
                post_data["grant_type"] = AUTHORIZATION_CODE,
                post_data["code"] = self.code
            else:
                post_data['grant_type'] = REFRESH_TOKEN,
                post_data['refresh_token'] = self.refresh_token

            response = request("POST", self.token_url, data=post_data, verify=self.verify_ssl)
            if response.status_code in [200, 204, 201]:
                return response.json()

            else:
                if response.text != "":
                    error_msg = ''
                    err_resp = response.json()
                    if err_resp and 'error' in err_resp:
                        failure_msg = err_resp.get('error_description')
                        error_msg = 'Response {0}: {1} \n Error Message: {2}'.format(response.status_code,
                                                                                     response.reason,
                                                                                     failure_msg if failure_msg else '')
                    else:
                        err_resp = response.text
                else:
                    error_msg = '{0}:{1}'.format(response.status_code, response.reason)
                raise ConnectorError(error_msg)

        except Exception as err:
            logger.error("{0}".format(str(err)))
            raise ConnectorError(error_msg)


def check(config, connector_info):
    try:
        ms = MicrosoftAuth(config)
        if CONFIG_SUPPORTS_TOKEN:
            if not 'accessToken' in config:
                token_resp = ms.generate_token(REFRESH_TOKEN_FLAG)
                config['accessToken'] = token_resp.get('accessToken')
                config['expiresOn'] = token_resp.get('expiresOn')
                config['refresh_token'] = token_resp.get('refresh_token')
                update_connnector_config(connector_info['connector_name'], connector_info['connector_version'], config,
                                         config['config_id'])
                return True
            else:
                token_resp = ms.validate_token(config, connector_info)
                return True
        else:
            ms.remove_config()
            client_id = config.get('client_id')
            section_header = 'Microsoft-API-Auth-{0}'.format(client_id)
            ms.handle_config(section_header)
            return True
    except Exception as err:
        raise ConnectorError(str(err))
