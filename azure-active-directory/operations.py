""" Copyright start
  Copyright (C) 2008 - 2021 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from requests import request, exceptions as req_exceptions
from .microsoft_api_auth import *

logger = get_logger('azure-active-directory')

API_VERSION = "v1.0"


def api_request(method, endpoint, connector_info, config, params=None, data=None, headers={}):
    try:
        ms = MicrosoftAuth(config)
        endpoint = ms.host + "/" + API_VERSION + endpoint
        token = ms.validate_token(config, connector_info)

        headers['Authorization'] = token
        headers['Content-Type'] = 'application/json'
        headers['consistencylevel'] = 'eventual'
        try:
            response = request(method, endpoint, headers=headers, params=params, json=data, verify=ms.verify_ssl)
            if response.status_code in [200, 201, 204]:
                if response.text != "":
                    return response.json()
                else:
                    return True
            else:
                if response.text != "":
                    err_resp = response.json()
                    failure_msg = err_resp['error']['message']
                    error_msg = 'Response [{0}:{1} Details: {2}]'.format(response.status_code, response.reason,
                                                                         failure_msg if failure_msg else '')
                else:
                    error_msg = 'Response [{0}:{1}]'.format(response.status_code, response.reason)
                logger.error(error_msg)
                raise ConnectorError(error_msg)
        except req_exceptions.SSLError:
            logger.error('An SSL error occurred')
            raise ConnectorError('An SSL error occurred')
        except req_exceptions.ConnectionError:
            logger.error('A connection error occurred')
            raise ConnectorError('A connection error occurred')
        except req_exceptions.Timeout:
            logger.error('The request timed out')
            raise ConnectorError('The request timed out')
        except req_exceptions.RequestException:
            logger.error('There was an error while handling the request')
            raise ConnectorError('There was an error while handling the request')
        except Exception as err:
            raise ConnectorError(str(err))
    except Exception as err:
        raise ConnectorError(str(err))


def list_users(config, params, connector_info):
    try:
        search = params.get('$search')
        if search:
            search = '\"{0}\"'.format(search)
        payload = {
            '$filter': params.get('$filter'),
            '$search': search,
            '$select': params.get('$select')
        }
        payload = {k: v for k, v in payload.items() if v is not None and v != ''}
        response = api_request("GET", "/users", connector_info, config, params=payload)
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def get_user_details(config, params, connector_info):
    try:
        response = api_request("GET", "/users/{0}".format(params.get('id')), connector_info, config)
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def enable_user(config, params, connector_info):
    try:
        payload = {
            'accountEnabled': True
        }
        response = api_request("PATCH", "/users/{0}".format(params.get('id')), connector_info, config, data=payload)
        if response:
            return {'status': 'success', 'result': 'User account enable successfully'}
    except Exception as err:
        raise ConnectorError(str(err))


def disable_user(config, params, connector_info):
    try:
        payload = {
            'accountEnabled': False
        }
        response = api_request("PATCH", "/users/{0}".format(params.get('id')), connector_info, config, data=payload)
        if response:
            return {'status': 'success', 'result': 'User account disable successfully'}
    except Exception as err:
        raise ConnectorError(str(err))


def reset_password(config, params, connector_info):
    try:
        force_change = params.pop('force_change', False)
        payload = {'passwordProfile': {'forceChangePasswordNextSignIn': force_change}}
        password = params.get('password')
        if password:
            payload['passwordProfile']['password'] = password
        response = api_request("PATCH", "/users/{0}".format(params.get('id')), connector_info, config, data=payload)
        if response:
            return {'status': 'success', 'result': 'Password successfully reset'}
    except Exception as err:
        raise ConnectorError(str(err))


def add_user(config, params, connector_info):
    try:
        force_change = params.pop('force_change', False)
        password = params.pop('password')
        payload = {'passwordProfile': {'forceChangePasswordNextSignIn': force_change, 'password': password}}
        params.update(payload)
        additional_fields = params.pop('additional_fields', {})
        if additional_fields:
            params.update(additional_fields)
        response = api_request("POST", "/users", connector_info, config, data=params)
        if response:
            return response
    except Exception as err:
        raise ConnectorError(str(err))


def delete_user(config, params, connector_info):
    try:
        response = api_request("DELETE", "/users/{0}".format(params.get('id')), connector_info, config)
        if response:
            return {'status': 'success', 'result': 'User successfully Deleted'}
    except Exception as err:
        raise ConnectorError(str(err))


def _check_health(config, connector_info):
    try:
        return check(config, connector_info)
    except Exception as err:
        raise ConnectorError(str(err))


operations = {
    'list_users': list_users,
    'get_user_details': get_user_details,
    'enable_user': enable_user,
    'disable_user': disable_user,
    'reset_password': reset_password,
    'add_user': add_user,
    'delete_user': delete_user
}
