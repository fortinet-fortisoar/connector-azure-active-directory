""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from connectors.core.connector import Connector, get_logger, ConnectorError
from .operations import operations, _check_health
from django.conf import settings
from integrations.crudhub import make_request

logger = get_logger('azure-active-directory')

MACRO_LIST = ["User_Enrichment_Playbooks_IRIs"]


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

    def del_micro(self, config):
        if not settings.LW_AGENT:
            for macro in MACRO_LIST:
                try:
                    resp = make_request(f'/api/wf/api/dynamic-variable/?name={macro}', 'GET')
                    if resp['hydra:member']:
                        logger.info("resetting global variable '%s'" % macro)
                        macro_id = resp['hydra:member'][0]['id']
                        resp = make_request(f'/api/wf/api/dynamic-variable/{macro_id}/?format=json', 'DELETE')
                except Exception as e:
                    logger.error(e)

    def on_deactivate(self, config):
        self.del_micro(config)

    def on_activate(self, config):
        self.del_micro(config)

    def on_add_config(self, config, active):
        self.del_micro(config)

    def on_delete_config(self, config):
        self.del_micro(config)
