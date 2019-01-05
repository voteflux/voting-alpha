# Source: https://github.com/stelligent/cloudformation-custom-resources/blob/master/lambda/python/customresource.py

import json
import logging
import signal
import traceback
from urllib.request import build_opener, HTTPHandler, Request
from enum import Enum

import os, sys

# os.environ['PYTHONPATH'] = os.environ.get('PYTHONPATH', '') + (':' if 'PYTHONPATH' in os.environ else '') + os.path.dirname(
#     os.path.realpath(__file__)) + '/deps'
# sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + '/deps')
# print("PYTHONPATH:", os.environ['PYTHONPATH'])

main_dir = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, main_dir)
sys.path.insert(0, os.path.join(main_dir, 'deps'))

LOGGER = logging.getLogger("CfnWrap")
LOGGER.setLevel(logging.INFO)

LOGGER.info(f"Path: {sys.path}")

class CfnStatus(Enum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"


class CrResponse:
    def __init__(self, status: CfnStatus, data=None, physical_id=None, fragment=None) -> None:
        '''The pysical_id should only ever change if the last version of the CR should be deleted.'''
        self.is_macro = fragment is not None
        self.is_cr = data is not None and physical_id is not None

        if (self.is_cr and self.is_macro) or not (self.is_cr or self.is_macro):
            raise Exception("must define either fragement or (data and physical_id)")

        self.fragment = fragment
        self.status = status
        self.data = data
        self.physical_id = physical_id


def wrap_macro(_handler):
    """wrap a macro handler (lambda)"""
    def inner(event, context):
        # Setup alarm for remaining runtime minus a second
        ms_remaining = context.get_remaining_time_in_millis()
        timeout_in_s = max((ms_remaining // 1000) - 1, 15)
        LOGGER.debug(f'ms remaining: {ms_remaining}')
        LOGGER.debug(f'timing out in seconds: {timeout_in_s} (min 15s)')
        signal.alarm(timeout_in_s)
        def run():
            try:
                LOGGER.info('REQUEST RECEIVED:\n %s', event)
                LOGGER.info('REQUEST RECEIVED:\n %s', context)
                resp: CrResponse = _handler(event, context, **event['templateParameterValues'])
                if type(resp) != CrResponse:
                    raise Exception("Handler {} did not return a CrResponse!".format(_handler.__name__))
                if not resp.is_macro:
                    raise Exception("macro handlers must return a CrResponse with fragment!")
                return {
                    "requestId": event['requestId'],
                    "status": resp.status.value,
                    "fragment": resp.fragment
                }
            except Exception as e:
                traceback.print_exc()
                tb_str = traceback.format_exc()
                LOGGER.info('FAILED!')
                LOGGER.info("Exception: %s", repr(e))
                LOGGER.error(tb_str)
                return {
                    "requestId": event['requestId'],
                    "status": CfnStatus.FAILED.value,
                    "errorMessage": "Exception: {}\n\nTraceback:\n{}".format(repr(e), tb_str)
                }
        resp = run()
        logging.info(f"RESPONSE: {resp}")
        signal.alarm(0)
        return resp
    return inner


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


def send_cfn_resp(evt, ctx, cfn_resp: CrResponse):
    return send_response(evt, ctx, cfn_resp)


def send_response(event, context, cfn_resp: CrResponse):
    if not cfn_resp.is_cr:
        raise Exception("send_response can only be used with CFN custom resource responses")
    response_status: CfnStatus = cfn_resp.status.value
    response_data = cfn_resp.data
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
        "PhysicalResourceId": cfn_resp.physical_id,
        "StackId": event['StackId'],
        "RequestId": event['RequestId'],
        "LogicalResourceId": event['LogicalResourceId'],
        "Data": response_data
    }
    if 'Traceback' in response_data:
        tb_lines = response_data['Traceback'].split('\n')
        nl = '\n'
        resp_dict['Reason'] += f"\nTB:\n{nl.join(tb_lines[1:3])}\n...\n{nl.join(tb_lines[-2:])}"
        del response_data['Traceback']
    resp_dict['Reason'] = resp_dict['Reason'][:600]
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
