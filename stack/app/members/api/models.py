import json
import datetime
import os
from enum import Enum
from typing import TypeVar

import toolz
from api.lib import now
from attrdict import AttrDict
from pymonad import Nothing, Maybe, Just
from pynamodb.indexes import GlobalSecondaryIndex, AllProjection
from pynamodb.models import Model
from pynamodb.attributes import UnicodeAttribute, BooleanAttribute, UTCDateTimeAttribute, ListAttribute, MapAttribute, \
    Attribute, BinaryAttribute, NumberAttribute
from pynamodb.constants import STRING
import pynamodb.exceptions as pddb_ex
from .env import get_env


T = TypeVar('T')
os.environ['AWS_REGION'] = "ap-southeast-2"


def gen_table_name(name):
    return f"{get_env('pNamePrefix')}-{name}"


class EnumAttribute(Attribute):
    attr_type = STRING

    def __init__(self, enum_cls, *args, **kwargs):
        self.enum = enum_cls
        self.enum_values = list([e.value for e in enum_cls])
        super().__init__(*args, **kwargs)

    def serialize(self, value):
        if value not in self.enum:
            raise pddb_ex.PutError(f"Invalid value in EnumAttribute: {value}. Allowed values: {self.enum_values}")
        return str(value.value)

    def deserialize(self, value):
        if value not in self.enum_values:
            raise AttributeError(f"Invalid value for enum: {value}. Expected: {self.enum_values}")
        return self.enum(value)


class ModelEncoder(json.JSONEncoder):
    def default(self, obj):
        if hasattr(obj, 'attribute_values'):
            return obj.attribute_values
        elif isinstance(obj, datetime.datetime):
            return obj.isoformat()
        elif isinstance(obj, bytes):
            return obj.decode()
        elif isinstance(obj, SessionState):
            return obj.value
        return json.JSONEncoder.default(self, obj)


class BaseModel(Model):
    @classmethod
    def get_or(cls, *args, default=None):
        if default is None:
            raise Exception('must provide a default')
        try:
            return super().get(*args)
        except super().DoesNotExist as e:
            return default

    @classmethod
    def get_maybe(cls, *args):
        try:
            return Just(super().get(*args))
        except super().DoesNotExist as e:
            return Nothing

    def to_json(self):
        return json.dumps(self, cls=ModelEncoder)

    def to_python(self):
        return AttrDict(json.loads(self.to_json()))

    def strip_private(self):
        return self.to_python()


class UidPrivate(BaseModel):
    def strip_private(self) -> dict:
        return {k: v for k, v in super().strip_private() if k != 'uid'}


class Ix(GlobalSecondaryIndex):
    class Meta:
        projection = AllProjection()


'''
establish session
-> GET lambda/session (JWT encoded)

client
- sends {msg:<json stringified>,sig:ethAccountSig}

server
- auths by doing sig reverse, tracks session by address (todo: future: session token too)

JWT has a token that lets the user de-anon themselves in logs
Can we store users public key and use to encrypt? yes
Encrypt logs with users voting key

-> POST address + email
** send email to user with OTP
<- JWT
-> POST jwt + OTP
** mark email as "in-progress"
-> POST jwt + address + encrypted_payload
** send email backup, mark awaiting_confirmation
-> POST jwt + address + confirm(hash(encrypted_payload))
** publish address to smart contract
<- txid, maybe local proof? client should validate tx

-> POST proxy vote payload + JWT
** validates payload and submits
'''


class RequestTypes(Enum):
    ESTABLISH_SESSION = "ESTABLISH_SESSION"
    PROVIDE_OTP = "PROVIDE_OTP"
    RESEND_OTP = "RESEND_OTP"
    PROVIDE_BACKUP = "PROVIDE_BACKUP"
    FINAL_CONFIRM = "FINAL_CONFIRM"


class SessionState(Enum):
    s000_NEWLY_CREATED = "s000_NEWLY_CREATED"
    s010_SENT_OTP_EMAIL = "s010_SENT_OTP_EMAIL"
    s020_CONFIRMED_OTP = "s020_CONFIRMED_OTP"
    s030_SENT_BACKUP_EMAIL = "s030_SENT_BACKUP_EMAIL"
    s040_MADE_ID_CONF_TX = "s040_MADE_ID_CONF_TX"


class TimestampMap(MapAttribute):
    ts = UTCDateTimeAttribute(default=datetime.datetime.now())


class OtpState(MapAttribute):
    not_valid_after = UTCDateTimeAttribute()
    not_valid_before = UTCDateTimeAttribute()
    otp_hash = BinaryAttribute()
    succeeded = BooleanAttribute()
    emails_sent_at = ListAttribute(of=TimestampMap, default=list)
    incorrect_attempts = NumberAttribute(default=0)


class SessionModel(BaseModel):
    class Meta:
        table_name = gen_table_name('session-db')
        region = get_env('AWS_REGION')
    session_anon_id = UnicodeAttribute(hash_key=True)
    state = EnumAttribute(SessionState)
    not_valid_before = UTCDateTimeAttribute(default=lambda: now() - datetime.timedelta(minutes=1))
    not_valid_after = UTCDateTimeAttribute()
    otp = OtpState(null=True)
    backup_hash = BinaryAttribute(null=True)
    tx_proof = BinaryAttribute(null=True)


class QuestionModel(UidPrivate):
    class Meta:
        table_name = gen_table_name("qanda-questions-ddb")
        region = get_env('AWS_REGION')

    qid = UnicodeAttribute(hash_key=True)
    uid = UnicodeAttribute()
    display_name = UnicodeAttribute()
    is_anon = BooleanAttribute()
    question = UnicodeAttribute()
    title = UnicodeAttribute()
    prev_q = UnicodeAttribute(null=True)
    next_q = UnicodeAttribute(null=True)
    ts = UTCDateTimeAttribute()


class UserQuestionLogEntry(MapAttribute):
    ts = UTCDateTimeAttribute()
    qid = UnicodeAttribute()


class UserQuestionsModel(BaseModel):
    class Meta:
        table_name = gen_table_name("qanda-user-qs-ddb")
        region = get_env('AWS_REGION')

    uid = UnicodeAttribute(hash_key=True)
    qs = ListAttribute(of=UserQuestionLogEntry, default=list)


class GenericPointer(MapAttribute):
    ts = UTCDateTimeAttribute()
    id = UnicodeAttribute()


class ReplyIdsByQid(BaseModel):
    class Meta:
        table_name = gen_table_name("qanda-reply-ids-ddb")
        region = get_env('AWS_REGION')

    qid = UnicodeAttribute(hash_key=True)
    rids = ListAttribute(of=GenericPointer, default=list)


class ReplyIdsByUid(BaseModel):
    class Meta:
        table_name = gen_table_name("qanda-reply-ids-by-uid-ddb")
        region = get_env('AWS_REGION')

    uid = UnicodeAttribute(hash_key=True)
    rids = ListAttribute(of=GenericPointer, default=list)


class Reply(UidPrivate):
    class Meta:
        table_name = gen_table_name("qanda-replies-ddb")
        region = get_env('AWS_REGION')

    rid = UnicodeAttribute(hash_key=True)
    qid = UnicodeAttribute()
    uid = UnicodeAttribute()
    body = UnicodeAttribute()
    ts = UTCDateTimeAttribute()
    parent_rid = UnicodeAttribute(null=True)
    child_rids = ListAttribute(of=GenericPointer, default=list)
    is_staff = BooleanAttribute()
    display_name = UnicodeAttribute()
