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


def _load_members():
    '''
    File should be a csv with at least headings: 'first name', 'last name', 'email'
    Other headings are treated as jurisdictions/classes of electors, and the attributes in those columns as weightings
    :param in_file:
    :return:
    '''
    VoterEnrolmentModel.count()

if __name__ == '__main__':
    load_members()
