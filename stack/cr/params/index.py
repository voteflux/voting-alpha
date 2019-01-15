# Source: https://github.com/stelligent/cloudformation-custom-resources/blob/master/lambda/python/customresource.py

import json
import logging
import signal
import time
import traceback
from urllib.request import build_opener, HTTPHandler, Request
from enum import Enum

import os, sys

# os.environ['PYTHONPATH'] = os.environ['PYTHONPATH'] + (':' if os.environ['PYTHONPATH'] else '') + os.path.dirname(
#     os.path.realpath(__file__)) + '/deps'
# sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + '/deps')
# print("PYTHONPATH:", os.environ['PYTHONPATH'])

import bootstrap

from lib import *

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)


class CfnStatus(Enum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"


class CrResponse:
    def __init__(self, status: CfnStatus, data: dict, physical_id: str) -> None:
        '''The pysical_id should only ever change if the last version of the CR should be deleted.'''
        self.status = status
        self.data = data
        self.physical_id = physical_id


def wrap_handler(_handler):
    """Handle Lambda event from AWS"""

    def inner(event, context):
        # Setup alarm for remaining runtime minus a second
        signal.alarm((context.get_remaining_time_in_millis() // 1000) - 1)
        try:
            LOGGER.info('REQUEST RECEIVED:\n %s', event)
            LOGGER.info('REQUEST RECEIVED:\n %s', context)
            LOGGER.info(event['RequestType'])
            resp: CrResponse = _handler(event, context, **event['ResourceProperties'])
            if type(resp) != CrResponse:
                raise Exception("Handler {} did not return a CrResponse!".format(_handler.__name__))
            send_cfn_resp(event, context, resp)
        except Exception as e:
            traceback.print_exc()
            tb_str = traceback.format_exc()
            LOGGER.info('FAILED!')
            LOGGER.info("Exception: %s", repr(e))
            resource_id = event.get('PhysicalResourceId',
                                    "Unknown-PhysicalResourceId-{}".format(event['LogicalResourceId'])
                                    )
            send_cfn_resp(event, context,
                          CrResponse(CfnStatus.FAILED, {
                              "Message": "Error: %s" % (repr(e),), "Traceback": tb_str
                          }, resource_id))

    return inner


def gen_nonce(**params):
    return {'Nonce': int(time.time())}

def do_create(props: dict):
    data = {}
    data.update(generate_ec2_key(**props))
    data.update(gen_eth_stats_secret(**props))
    data.update(gen_network_id(**props))
    data.update(upload_chain_config(**data, **props))
    data.update(gen_nonce(**data, **props))
    data.update(
        {"Message": "Success: EthStats Secret, NetworkID, ChainConfig, (Optional) EC2 Key Generation"})
    return data


@wrap_handler
def handler_bucket_cleanup(event, ctx, **props):
    NamePrefix = props['NamePrefix']
    physical_id = 'sv-{}-eth-private-keys-and-addrs'.format(NamePrefix)

    if event['RequestType'] == "Delete":
        return CrResponse(CfnStatus.SUCCESS, remove_s3_bucket_objs(**props), physical_id)
    elif event['RequestType'] in ["Create", "Update"]:
        return CrResponse(CfnStatus.SUCCESS, {}, physical_id)
    else:
        raise Exception("Unknown RequestType: {}".format(event['RequestType']))


@wrap_handler
def handler_priv_keys(event: dict, context, **props):
    """Create consensus+service privkeys, record PoA Addrs, record Service Addrs"""
    NamePrefix = props['NamePrefix']
    NConsensusNodes = props['NConsensusNodes']
    physical_id = 'sv-{}-eth-private-keys-and-addrs'.format(NamePrefix)

    if event['RequestType'] == 'Create':
        _keys = create_node_keys(**props)
        data = {'PoAAddresses': _keys['poa_pks']}
        data.update(save_node_keys(_keys['ssm_keys'], **props))
        data.update(save_poa_pks(_keys['poa_pks'], **props))
        data.update(save_service_pks(_keys['service_pks'], **props))
        data.update(save_enode_pks(_keys['enode_pks'], **props))
        return CrResponse(CfnStatus.SUCCESS, data, physical_id)

    elif event['RequestType'] == 'Update':
        # check if we need to update any key stuff (i.e. did nNodes change?)
        ssm = boto3.client('ssm')
        old_n = ssm.get_parameter(Name="sv-{}-param-nconsensus-nodes".format(NamePrefix))['Parameter']['Value']
        if old_n != NConsensusNodes:
            raise Exception("You cannot update NConsensusNodes currently. Sorry about that.")
        return CrResponse(CfnStatus.SUCCESS, {"UpdatedPrivKeys": False}, physical_id)

    elif event['RequestType'] == 'Delete':
        return CrResponse(CfnStatus.SUCCESS, delete_all_node_keys(**props), physical_id)
    else:
        return CrResponse(CfnStatus.FAILED, {"Message": "Unexpected RequestType from CFN"}, physical_id)


@wrap_handler
def handler_prevent_nameprefix_change(event, ctx, NamePrefix, **props):
    physical_id = "sv-{}-nameprefix-prevent-change".format(NamePrefix)
    return ({
        'Create': CrResponse(CfnStatus.SUCCESS, {"NamePrefixConfirmed": True}, physical_id),
        'Update': CrResponse(CfnStatus.FAILED,
                             {"Message": "You cannot update NamePrefix after it's been set!"},
                             physical_id),
        'Delete': CrResponse(CfnStatus.SUCCESS, {}, physical_id)
    })[event['RequestType']]


@wrap_handler
def handler_params(event: dict, context, **props):
    physical_id = "sv-{}-big-old-custom-resource-todo-refactor-out".format(props['NamePrefix'])
    if event['RequestType'] == 'Create':
        data = do_create(props)
        return CrResponse(CfnStatus.SUCCESS, data, physical_id)
    elif event['RequestType'] == 'Update':
        LOGGER.info('UPDATE! (NULL)')
        return CrResponse(CfnStatus.SUCCESS, {}, physical_id)
    elif event['RequestType'] == 'Delete':
        LOGGER.info('DELETE!')
        data = del_ssm_networkid_ethstats(**props)
        return CrResponse(CfnStatus.SUCCESS, data, physical_id)
    else:
        return CrResponse(CfnStatus.FAILED, {"Message": "Unexpected event received from CloudFormation"}, physical_id)


def send_cfn_resp(evt, ctx, cfn_resp: CrResponse):
    return send_response(evt, ctx, cfn_resp)


def send_response(event, context, cfn_resp: CrResponse):
    response_status: CfnStatus = cfn_resp.status
    response_data = cfn_resp.data
    '''Send a resource manipulation status response to CloudFormation'''
    reason_prefix = response_data.get('Message', '')
    logs_url = "https://{region}.console.aws.amazon.com/cloudwatch/home?region={region}#logEventViewer:group={log_group};stream={log_stream}".format(
        region=context.invoked_function_arn.split(":")[3],
        log_group=context.log_group_name,
        log_stream=context.log_stream_name
    )
    resp_dict = {
        "Status": response_status.value,
        "Reason": reason_prefix + "\nLogs URL: {}".format(logs_url),
        "PhysicalResourceId": cfn_resp.physical_id,
        "StackId": event['StackId'],
        "RequestId": event['RequestId'],
        "LogicalResourceId": event['LogicalResourceId'],
        "Data": response_data
    }
    if 'Traceback' in response_data:
        resp_dict['Reason'] += "\n\nTraceback:\n" + response_data['Traceback']
    response_body = json.dumps(resp_dict).encode()

    LOGGER.info('ResponseURL: %s', event['ResponseURL'])
    LOGGER.info('ResponseBody: %s', response_body.decode())

    opener = build_opener(HTTPHandler)
    request = Request(event['ResponseURL'], data=response_body)
    request.add_header('Content-Type', '')
    request.add_header('Content-Length', len(response_body))
    request.get_method = lambda: 'PUT'
    response = opener.open(request)
    LOGGER.info("Status code: %s", response.getcode())
    LOGGER.info("Status message: %s", response.msg)


def timeout_handler(_signal, _frame):
    '''Handle SIGALRM'''
    raise Exception('Time exceeded')


signal.signal(signal.SIGALRM, timeout_handler)
