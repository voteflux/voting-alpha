# Source: https://github.com/stelligent/cloudformation-custom-resources/blob/master/lambda/python/customresource.py

import json
import logging
import signal
from urllib.request import build_opener, HTTPHandler, Request

from lib import *

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)


def handler(event, context):
    '''Handle Lambda event from AWS'''
    # Setup alarm for remaining runtime minus a second
    signal.alarm((context.get_remaining_time_in_millis() // 1000) - 1)
    try:
        LOGGER.info('REQUEST RECEIVED:\n %s', event)
        LOGGER.info('REQUEST RECEIVED:\n %s', context)
        if event['RequestType'] == 'Create':
            LOGGER.info('CREATE!')

            props = event['Properties']
            data = {}
            data.update(generate_ec2_key(**props))
            data.update(generate_node_keys(**props))
            data.update(gen_eth_stats_secret(**props))
            data.update(gen_network_id(**props))
            data.update(upload_chain_config(**props))

            send_response(event, context, "SUCCESS",
                          {"Message": "Resource creation successful!"})
        elif event['RequestType'] == 'Update':
            LOGGER.info('UPDATE!')
            send_response(event, context, "SUCCESS",
                          {"Message": "Resource update successful!"})
        elif event['RequestType'] == 'Delete':
            LOGGER.info('DELETE!')
            send_response(event, context, "SUCCESS",
                          {"Message": "Resource deletion successful!"})
        else:
            LOGGER.info('FAILED!')
            send_response(event, context, "FAILED",
                          {"Message": "Unexpected event received from CloudFormation"})
    except Exception as e:
        LOGGER.info('FAILED!')
        LOGGER.info("Exception: %s", e)
        send_response(event, context, "FAILED", {"Message": "Exception during processing"})


def send_response(event, context, response_status, response_data):
    '''Send a resource manipulation status response to CloudFormation'''
    response_body = json.dumps({
        "Status": response_status,
        "Reason": "See the details in CloudWatch Log Stream: " + context.log_stream_name,
        "PhysicalResourceId": context.log_stream_name,
        "StackId": event['StackId'],
        "RequestId": event['RequestId'],
        "LogicalResourceId": event['LogicalResourceId'],
        "Data": response_data
    })

    LOGGER.info('ResponseURL: %s', event['ResponseURL'])
    LOGGER.info('ResponseBody: %s', response_body)

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