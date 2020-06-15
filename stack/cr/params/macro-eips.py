import json
import logging
from collections import defaultdict

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

import bootstrap

from common import *


@wrap_macro
def macro(event, context, **kwargs):
    event_txt = json.dumps(event, indent=4, separators=(',', ': '), sort_keys=True)
    logger.debug(f"event: {event_txt}")
    logger.debug("params: {}".format(json.dumps(kwargs)))

    # Add general Outputs
    frag = event['fragment']
    rs = frag['Resources']
    outs = frag.get('Outputs', {})
    params = event['templateParameterValues']
    n_nodes = int(params['pNPublicNodes'])

    if 'AWSTemplateFormatVersion' not in frag or 'Resources' not in frag:
        raise Exception(
            "Must run from root of template! (Ensure both AWSTemplateFormatVersion and Resources fields are present")

    for i in range(n_nodes):
        rs[f"rEip{i}"] = {
            'Type': "AWS::EC2::EIP"
        }
        # rs[f"rDomainName{i}"] = {
        #     'Type': "AWS::Route53::RecordSet",
        #     'Properties': {
        #         'HostedZoneName': {"Ref": "pDomain"},
        #         'Name': {"Fn::Sub": f"pnode-{i}.${{pSubdomain}}.${{pDomain}}"},
        #         "TTL": "60",
        #         "Type": "A",
        #         "ResourceRecords": [{"Ref": f"rEip{i}"}]
        #     }
        # }

    outs['oPublicIps'] = {
        'Value': {'Fn::Join': [',', [{'Ref': f'rEip{i}'} for i in range(n_nodes)]]}
    }

    outs['oEipAllocationIds'] = {
        'Value': {'Fn::Join': [',', [{'Fn::GetAtt': f'rEip{i}.AllocationId'} for i in range(n_nodes)]]}
    }

    # outs['oDomainNames'] = {
    #     'Value': {'Fn::Join': [',', [{'Ref': f'rDomainName{i}'} for i in range(n_nodes)]]}
    # }

    frag['Outputs'] = outs
    fragment_txt = json.dumps(event['fragment'], indent=4, separators=(',', ': '), sort_keys=True)
    logger.debug(f"fragment {fragment_txt}")

    return CrResponse(CfnStatus.SUCCESS, fragment=frag)
