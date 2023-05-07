""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
import json

from requests import request, exceptions as req_exceptions
from connectors.core.connector import get_logger, ConnectorError
from .microsoft_api_auth import *
from urllib import parse
from requests_toolbelt.utils import dump
import logging
import copy

logger = get_logger('azure-active-directory')
#logger.setLevel(logging.DEBUG) # Uncomment for connector specific debug

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
            logger.debug('\n{}\n'.format(dump.dump_all(response).decode('utf-8')))
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


def _fetch_remaining_pages(response, url_params, connector_info, config, endpoint):
    results = copy.deepcopy(response)
    while '@odata.nextLink' in response:
        skiptoken = parse.parse_qs(parse.urlparse(response['@odata.nextLink']).query)['$skiptoken'][0]
        url_params.update({"$skiptoken": skiptoken})
        response = api_request("GET", endpoint, connector_info, config, params=url_params)
        results['value'] += response['value']
        logger.debug('Append {} more records'.format(str(len(response['value']))))
    return results


def _list_records(config, params, connector_info, endpoint):
    try:
        url_params = {}
        endpoint = endpoint
        get_all_pages = params.get("get_all_pages")
        if params.get('$filter'):
            url_params.update({"$filter": params.get('$filter')})
        if params.get("$top"):
            url_params.update({"$top": params.get('$top')})
        if not any([path in endpoint for path in ['/auditLogs', 'people']]):
            url_params.update({"$count": 'true'})
        if params.get("$select"):
            url_params.update({"$select": params.get('$select')})
        if params.get("$skipToken"):
            url_params.update({"$skiptoken": params.get('$skipToken')})

        response = api_request("GET", endpoint, connector_info, config, params=url_params)
        if '@odata.nextLink' in response and get_all_pages:
            return _fetch_remaining_pages(response, url_params, connector_info, config, endpoint)
        else:
            return response
    except Exception as err:
        raise ConnectorError(str(err))


def list_users(config, params, connector_info):
    return _list_records(config, params, connector_info, "/users")


def list_groups(config, params, connector_info):
    return _list_records(config, params, connector_info, "/groups")


def list_sign_ins(config, params, connector_info):
    return _list_records(config, params, connector_info, "/auditLogs/signIns")


def list_group_members(config, params, connector_info):
    return _list_records(config, params, connector_info, "/groups/{0}/members".format(params.get('id')))


def get_group_details(config, params, connector_info):
    try:
        response = api_request("GET", "/groups/{0}".format(params.get('id')), connector_info, config)
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def remove_member(config, params, connector_info):
    try:
        response = api_request("DELETE",
                               "/groups/{0}/members/{1}/$ref".format(params.get('id'), params.get("dir_object_id")),
                               connector_info, config)
        if response:
            return {'status': 'success', 'result': 'Member successfully removed'}
    except Exception as err:
        raise ConnectorError(str(err))


def add_member(config, params, connector_info):
    try:
        payload = {
            "@odata.id": "https://graph.microsoft.com/v1.0/directoryObjects/{0}".format(params.get("dir_object_id"))
        }
        response = api_request("POST", "/groups/{0}/members/$ref".format(params.get('id')), connector_info, config,
                               data=payload)
        if response:
            return {'status': 'success', 'result': 'Member successfully added'}
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

def get_user_membership(config, params, connector_info):
    membership_type_map = {
        "Direct": "/users/{0}/memberOf",
        "Transitive": "/users/{0}/transitiveMemberOf"
    }
    user_id = params.get('user_id')
    membership_type = params.get('membership_type')
    endpoint = membership_type_map[membership_type].format(user_id)
    return _list_records(config, params, connector_info, endpoint)


def get_people(config, params, connector_info):
    return _list_records(config, params, connector_info, '/users/{0}/people'.format(params.get('user_id')))


def get_managers(config, params, connector_info):
    return api_request("GET", "/users/{0}/".format(params.get('user_id')),
                       connector_info, config, params={"$expand": "manager($levels=max)"})


def list_direct_reports(config, params, connector_info):
    return api_request("GET", "/users/{0}/directReports".format(params.get('user_id')), connector_info, config)


def list_devices(config, params, connector_info):
    return _list_records(config, params, connector_info, '/devices')


def get_registered_owners(config, params, connector_info):
    return api_request("GET", "/devices/{0}/registeredOwners".format(params.get('device_id')), connector_info, config)


def get_registered_users(config, params, connector_info):
    return api_request("GET", "/devices/{0}/registeredUsers".format(params.get('device_id')), connector_info, config)


def _check_health(config, connector_info):
    if check(config, connector_info) and list_users(config, params={}, connector_info=connector_info):
        return True


operations = {
    'list_users': list_users,
    'get_user_details': get_user_details,
    'enable_user': enable_user,
    'disable_user': disable_user,
    'reset_password': reset_password,
    'add_user': add_user,
    'delete_user': delete_user,
    'list_sign_ins': list_sign_ins,
    'list_groups': list_groups,
    'get_group_details': get_group_details,
    'remove_member': remove_member,
    'add_member': add_member,
    'list_group_members': list_group_members,
    'get_user_membership': get_user_membership,
    'get_people': get_people,
    'get_managers': get_managers,
    'list_direct_reports': list_direct_reports,
    'list_devices': list_devices,
    'get_registered_owners': get_registered_owners,
    'get_registered_users': get_registered_users
}
