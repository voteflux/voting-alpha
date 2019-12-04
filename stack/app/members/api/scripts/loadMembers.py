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
@click.option('--force-overwrite', is_flag=True, default=False)
@click.option('--really-save', is_flag=True, default=False)
def load_members(in_file, force_overwrite, really_save):
    _load_members(in_file=in_file, force_overwrite=force_overwrite, really_save=really_save)


def _load_members(in_file, force_overwrite=False, really_save=False):
    '''
    File should be a csv with at least headings: 'first_name', 'last_name', 'email'
    Other headings are treated as jurisdictions/classes of electors, and the attributes in those columns as weightings
    :param in_file:
    :return:
    '''
    if not in_file or in_file == "" or in_file is None:
        raise Exception('must provide a filename to consume')
    to_load = Path(in_file)
    members_file = os.path.expanduser(to_load)
    reader = csv.DictReader(open(members_file, 'r'))

    def mk_weightings(line: OrderedDict):
        groups = [k for k in line.keys() if k not in ['first_name', 'last_name', 'email']]
        return {k: int(line[k] or '0') for k in groups}

    count = 0
    seen = set()
    dup = []
    for rowN, line in enumerate(reader):
        email = line['email'].strip().lower()
        fname = line['first_name'].strip()
        count += 1
        enrolment_m = VoterEnrolmentModel.get_maybe(email)
        if enrolment_m == Nothing:  # or force_overwrite:  # commented force_overwrite for safety
            r = dict(
                email_addr=email,
                first_name=fname,
                weightingMap=mk_weightings(line),
                claimed=False,
                have_sent_otp=False,
            )
            if really_save:
                VoterEnrolmentModel(**r).save()
                print('WARNING: saved', email, r)
            else:
                print(f'WARNING: would save but flag not provided: {r}')
        else:
            print(f'EXISTS:{email}')
            enrolment = enrolment_m.getValue()
            predicted_weightings = mk_weightings(line)
            weightings = enrolment.weightingMap.as_dict()
            if len(predicted_weightings) != len(weightings):
                raise Exception(f'lens different: {enrolment.to_python()}, {predicted_weightings}')
            for (k,v) in predicted_weightings.items():
                if k not in weightings or weightings[k] != v:
                    print(f'WARNING: values different ({k}): {enrolment.to_python()}, {predicted_weightings}')
            print(f'CONFIRMED:{email}')
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
