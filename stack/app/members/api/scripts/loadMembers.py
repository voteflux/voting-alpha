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

count = 0
seen = set()
dup = []
for rowN, line in enumerate(reader):
    # VoterEnrolmentModel(
    # )
    email = line['email'].strip()
    count += 1
    if VoterEnrolmentModel.get_maybe(line['email']) == Nothing:
        r = dict(
            email_addr=line['email'].strip(),
            first_name=line['first name'].strip(),
            weightingMap=mk_weightings(line),
            claimed=False,
        )
        VoterEnrolmentModel(**r).save()
        print('saved', r['email_addr'])
    else:
        print('skipped', line['email'])
    if email in seen:
        dup.append(email)
    seen.add(email)
print({
    'count': count,
    'seen': len(seen),
    'dup': dup
})
