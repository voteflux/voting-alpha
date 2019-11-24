import os
import sys
import csv
from collections import OrderedDict

from api.models import VoterEnrolmentModel
from pymonad import Nothing

members_file = os.path.expanduser("~/sv-test-members.csv")

reader = csv.DictReader(open(members_file, 'r'))


def mk_weightings(line: OrderedDict):
    groups = [k for k in line.keys() if k not in ['first name', 'last name', 'email']]
    return {k: int(line[k] or '0') for k in groups}


for rowN, line in enumerate(reader):
    # VoterEnrolmentModel(
    # )
    if VoterEnrolmentModel.get_maybe(line['email']) == Nothing:
        r = dict(
            email_addr=line['email'],
            first_name=line['first name'],
            weightingMap=mk_weightings(line),
            claimed=False,
        )
        VoterEnrolmentModel(**r).save()
        print('saved', r['email_addr'])
    else:
        print('skipped', line['email'])
