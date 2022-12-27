""" Copyright start
  Copyright (C) 2008 - 2021 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from connectors.core.connector import Connector, get_logger, ConnectorError
from .operations import operations, _check_health
AUTH_BEHALF_OF_USER = "On behalf of User - Delegated Permission"
CONFIG_SUPPORTS_TOKEN = True
try:
    from connectors.core.utils import update_connnector_config
except:
    CONFIG_SUPPORTS_TOKEN = False

logger = get_logger('azure-active-directory')


class AzureAcivedirectory(Connector):
    
    def execute(self, config, operation, params, **kwargs):
        try:
            connector_info = {"connector_name": self._info_json.get('name'),
                              "connector_version": self._info_json.get('version')}
            operation = operations.get(operation)
        except Exception as err:
            logger.exception(err)
            raise ConnectorError(err)
        return operation(config, params, connector_info)

    def check_health(self, config):
        logger.info('starting health check')
        connector_info = {"connector_name": self._info_json.get('name'),
                          "connector_version": self._info_json.get('version')}
        _check_health(config, connector_info)
        logger.info('completed health check no errors')

    def on_update_config(self, old_config, new_config, active):
        connector_info = {"connector_name": self._info_json.get('name'),
                          "connector_version": self._info_json.get('version')}

        if new_config.get('auth_type', '') == AUTH_BEHALF_OF_USER and CONFIG_SUPPORTS_TOKEN:
            old_auth_code = old_config.get('code')
            new_auth_code = new_config.get('code')
            if old_auth_code != new_auth_code:
                new_config.pop('access_token', '')
            else:
                new_config['access_token'] = old_config.get('access_token')
                new_config['refresh_token'] = old_config.get('refresh_token ')
                new_config['expires_in'] = old_config.get('expires_in')
        update_connnector_config(connector_info['connector_name'], connector_info['connector_version'], new_config,
                                 new_config['config_id'])        


