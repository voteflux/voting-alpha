# Source: https://github.com/stelligent/cloudformation-custom-resources/blob/master/lambda/python/customresource.py

import json
import logging
import signal
import traceback
from urllib.request import build_opener, HTTPHandler, Request

import os, sys
os.environ['PYTHONPATH'] = os.environ['PYTHONPATH'] + (':' if os.environ['PYTHONPATH'] else '') + os.path.dirname(os.path.realpath(__file__)) + '/deps'
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + '/deps')
print("PYTHONPATH:", os.environ['PYTHONPATH'])

from lib import *

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)


def do_create(props: dict):
    data = {}
    data.update(generate_ec2_key(**props))

    ssm_keys, poa_pks = generate_node_keys(**props)
    data.update(save_node_keys(ssm_keys, **props))

    data.update(gen_eth_stats_secret(**props))

    data.update(gen_network_id(**props))

    data.update(upload_chain_config(**data, **props))

    data.update({"Message": "Success: Node Keys, EthStats Secret, NetworkID, ChainConfig, (Optional) EC2 Key Generation"})

    return data


def handler(event: dict, context):
    '''Handle Lambda event from AWS'''
    # Setup alarm for remaining runtime minus a second
    signal.alarm((context.get_remaining_time_in_millis() // 1000) - 1)
    try:
        LOGGER.info('REQUEST RECEIVED:\n %s', event)
        LOGGER.info('REQUEST RECEIVED:\n %s', context)
        if event['RequestType'] == 'Create':
            LOGGER.info('CREATE!')
            data = do_create(event['ResourceProperties'])
            send_response(event, context, "SUCCESS", data)
        elif event['RequestType'] == 'Update':
            LOGGER.info('UPDATE! (Rerun create...)')
            data = do_create(event['ResourceProperties'])
            send_response(event, context, "SUCCESS", data)
        elif event['RequestType'] == 'Delete':
            LOGGER.info('DELETE!')
            send_response(event, context, "SUCCESS",
                          {"Message": "Resource deletion successful!"})
        else:
            LOGGER.info('FAILED!')
            send_response(event, context, "FAILED",
                          {"Message": "Unexpected event received from CloudFormation"})
    except Exception as e:
        traceback.print_exc()
        tb_str = traceback.format_exc()
        LOGGER.info('FAILED!')
        LOGGER.info("Exception: %s", repr(e))
        send_response(event, context, "FAILED", {"Message": "Error: %s" % (repr(e),), "Traceback": tb_str})


def send_response(event, context, response_status, response_data):
    '''Send a resource manipulation status response to CloudFormation'''
    reason_prefix = response_data.get('Message', '')
    logs_url = "https://{region}.console.aws.amazon.com/cloudwatch/home?region={region}#logEventViewer:group={log_group};stream={log_stream}".format(
        region=context.invoked_function_arn.split(":")[3],
        log_group=context.log_group_name,
        log_stream=context.log_stream_name
    )
    resp_dict = {
        "Status": response_status,
        "Reason": reason_prefix + "\nLogs URL: {}".format(logs_url),
        "PhysicalResourceId": context.log_stream_name,
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