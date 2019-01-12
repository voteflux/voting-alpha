import sys, os, json, datetime, traceback, time, hashlib
from datetime import date, datetime
import logging

from botocore.vendored import requests
import boto3

LOG = logging.getLogger("ACM+DNS CR")
LOG.setLevel(logging.INFO)


# source: https://www.reddit.com/r/aws/comments/8g1vhq/cloudformation_create_and_verify_acm_certificate/dy8vdz9/
# note: some modifications made for python3.6


class Timer:
    def __init__(self, name=''):
        self.name = name

    def __enter__(self):
        self.start = time.time()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end = time.time()
        self.interval = self.end - self.start
        if self.name:
            LOG.info(f'Timed {self.name} to take {self.interval} seconds.')

    @property
    def curr_interval(self):
        return time.time() - self.start


def json_serial(obj):
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    raise TypeError("Type %s not serializable" % type(obj))


def cfn_response(url, body):
    LOG.info(f"Returning to CFN: {body}")
    headers = {'content-type': '', 'content-length': str(len(body))}
    response = requests.put(url, data=body, headers=headers)
    return response


def acm_certificate(event, context):
    LOG.info(f"Request Event: {event}")
    if event['RequestType'] in ['Create', 'Update']:
        cfn_response(event['ResponseURL'], _create_acm_certificate(event, context))
    else:
        cfn_response(event['ResponseURL'], _delete_acm_certificate(event))


def _create_acm_certificate(event, ctx):
    acm = boto3.client('acm')
    ret = dict()
    ret['StackId'] = event['StackId']
    ret['RequestId'] = event['RequestId']
    ret['LogicalResourceId'] = event['LogicalResourceId']
    rp = event['ResourceProperties']
    try:
        cs = rp['pDomain'].rstrip('.')
        dn = "%s.%s" % (rp['pSubdomain'].rstrip('.'), cs)
        wc = rp.get("pWildcard", "false") == 'true'
        additional_dn = ["*.%s" % dn] if wc else []
        san = dn
        if len(dn) > 62:
            hashlen = 62 - len(cs)
            ch = hashlib.sha256(dn).hexdigest()[-hashlen:]
            dn = "%s.%s" % (ch, cs)
        response = acm.list_certificates(
            CertificateStatuses=['PENDING_VALIDATION', 'ISSUED']
        )

        def request_cert():
            response = acm.request_certificate(
                DomainName=dn,
                ValidationMethod='DNS',
                IdempotencyToken=event['LogicalResourceId'],
                SubjectAlternativeNames=[san] + additional_dn,
            )
            return response['CertificateArn']

        cert_arn = None
        for cert in response['CertificateSummaryList']:
            LOG.info("existing cert: %s" % cert['DomainName'])
            if cert['DomainName'] == dn:
                if wc:
                    cert_deets = acm.describe_certificate(CertificateArn=cert['CertificateArn'])['Certificate']
                    try:
                        _san = cert_deets['SubjectAlternativeNames']
                        if _san[0] != additional_dn[0] or len(_san) > 2:  # if it's >2 it wasn't created by this CR
                            continue
                    except:
                        continue
                cert_arn = cert['CertificateArn']
                LOG.info("Matching cert: %s" % cert_arn)

        FRESH_CERT = False
        if not cert_arn:
            cert_arn = request_cert()['CertificateArn']
            FRESH_CERT = True

        with Timer("ACM cert creation") as t:
            while t.curr_interval < 10:
                response = acm.describe_certificate(
                    CertificateArn=cert_arn
                )
                try:
                    dvo = response['Certificate']['DomainValidationOptions']
                    if len(dvo) > 0 and 'ResourceRecord' in dvo[0]:
                        break
                except:
                    time.sleep(0.5)
        r53_c = []
        LOG.info(f"describe_cert response for {cert_arn}: {response}")
        for vo in dvo:
            LOG.info(f"domain validation option: {vo}")
            if vo['DomainName'][0] == "*":
                continue
            rr = vo['ResourceRecord']
            r53_c.append({'Action': 'UPSERT', 'ResourceRecordSet': {'Name': rr['Name'], 'Type': rr['Type'], 'TTL': 3600,
                                                                    'ResourceRecords': [{'Value': rr['Value']}]}})

        r53 = boto3.client('route53')
        lhzbn_resp = r53.list_hosted_zones_by_name(DNSName=cs)
        LOG.info("lhzbn_resp: %s" % lhzbn_resp)
        zone_id = lhzbn_resp['HostedZones'][0]['Id']
        LOG.warning("r53 changes: %s" % r53_c)
        response = r53.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={'Comment': 'Auth', 'Changes': r53_c}
        )
        LOG.info("r53 response: %s" % response)

        if FRESH_CERT:
            LOG.info(f"Fresh cert delete: {acm.delete_certificate(CertificateArn=cert_arn)})")
            cert_arn = request_cert()['CertificateArn']

        cert_done = False
        cert_status = "PENDING_VALIDATION"
        seconds_remaining = (ctx.get_remaining_time_in_millis() // 1000) - 10
        LOG.info(f"monitoring cert validation up to {seconds_remaining}s")
        with Timer("certificate DNS validation period") as t:
            while t.curr_interval < seconds_remaining and not cert_done:  # seconds
                try:
                    cert = acm.describe_certificate(CertificateArn=cert_arn)['Certificate']
                    cert_status = cert['DomainValidationOptions'][0]['ValidationStatus']
                    cert_done = cert_status in ["SUCCESS", "FAILED"]
                except Exception as e:
                    LOG.info(f"Exception while checking cert validation status: {repr(e)}")
                finally:
                    time.sleep(5 if not cert_done else 0)

        ret['PhysicalResourceId'] = cert_arn
        ret['Data'] = {}
        ret['Data']['CertificateArn'] = cert_arn
        ret['Status'] = 'SUCCESS' if cert_status == "SUCCESS" else "FAILED"
    except Exception as e:
        LOG.error(f"Traceback during create:\n{traceback.format_exc()}")
        ret['Status'] = 'FAILED'
        ret['Reason'] = repr(e)
        ret['PhysicalResourceId'] = 'no-cert-created'
    finally:
        return json.dumps(ret)


def _delete_acm_certificate(event):
    acm = boto3.client('acm')
    ret = dict()
    ret['StackId'] = event['StackId']
    ret['RequestId'] = event['RequestId']
    ret['LogicalResourceId'] = event['LogicalResourceId']
    ret['PhysicalResourceId'] = "certificate-deleted"
    try:
        cert_arn = event['PhysicalResourceId']
        LOG.info(f"Previous PhysicalResourceId: {cert_arn}")
        if cert_arn[:11] == "arn:aws:acm":
            response = acm.delete_certificate(
                CertificateArn=cert_arn
            )
            LOG.info(f"got delete response {response}")
        ret['Status'] = 'SUCCESS'
    except Exception as e:
        LOG.error(f"Traceback during delete:\n{traceback.format_exc()}")
        ret['Status'] = 'SUCCESS'
        ret['Reason'] = repr(e)
    finally:
        return json.dumps(ret)
