import os
import click


@click.command()
@click.option('--list-emails', default=False, is_flag=True)
def member_rego_stats(list_emails):
    print(f"Getting member rego stats for NAME_PREFIX={os.getenv('NAME_PREFIX')}")
    ret = _member_rego_stats()
    if list_emails:
        ret.update(dict(registered=list(m.email_addr for m in ret.registered),
                        not_registered=list(m.email_addr for m in ret.not_registered)))
    else:
        ret.update(dict(registered=len(ret.registered), not_registered=len(ret.not_registered)))
    print(ret)
    return ret


def _member_rego_stats():
    '''
    Return a doc of the current state of member rego.
    :returns { 'total': int, 'registered': str[], 'not_registered': str[] }
    '''

    from functools import reduce
    from attrdict import AttrDict

    from api.models import VoterEnrolmentModel

    total = VoterEnrolmentModel.count()
    all_members = VoterEnrolmentModel.scan()

    def acc_members(acc, m):
        _r, _not_r = acc
        return (_r + [m], _not_r) if m.claimed else (_r, _not_r + [m])

    registered, not_registered = reduce(acc_members, all_members, ([], []))
    return AttrDict(total=total, registered=registered, not_registered=not_registered)

