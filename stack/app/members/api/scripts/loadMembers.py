import os
import sys
import csv
from collections import OrderedDict
from pathlib import Path

import click

from api.models import VoterEnrolmentModel
from pymonad import Nothing


@click.command()
@click.option('--in-file', help='CSV to load.')
def load_members(in_file):
    _load_members(in_file)


def _load_members(in_file, force_overwrite=False):
    '''
    File should be a csv with at least headings: 'first name', 'last name', 'email'
    Other headings are treated as jurisdictions/classes of electors, and the attributes in those columns as weightings
    :param in_file:
    :return:
    '''
    to_load = Path(in_file if in_file else os.path.expanduser("~/sv-test-members.csv"))
    members_file = os.path.expanduser(to_load)
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
        email = line['email'].strip().lower()
        fname = line['first name'].strip()
        count += 1
        if VoterEnrolmentModel.get_maybe(email) == Nothing or force_overwrite:
            r = dict(
                email_addr=email,
                first_name=fname,
                weightingMap=mk_weightings(line),
                claimed=False,
            )
            VoterEnrolmentModel(**r).save()
            print('saved', email)
        else:
            print('skipped', email)
        if email in seen:
            dup.append(email)
        seen.add(email)
    print({
        'count': count,
        'seen': len(seen),
        'dup': dup
    })


if __name__ == '__main__':
    load_members()
