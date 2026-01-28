#!/usr/bin/env python
# -*- coding: utf-8 -*-

from typing import Any
import inspect
import abc
import json
import datetime
import logging
import hashlib
import uuid
from argparse import ArgumentParser
from http.server import BaseHTTPRequestHandler, HTTPServer

import scoring

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}


class AbsentRequiredFieldException(Exception):
    pass

class WrongFieldContent(Exception):
    pass


class BaseClass(object):

    def __init__(self, required=False, nullable=True):
        self.required = required
        self.nullable = nullable

    def _attr_name_of_protected(self, protected_name: str):
        return protected_name[1:]

    def validate(self, value) -> (bool, str):
        return True, ""

    def __set_name__(self, owner, attr_name: str) -> None:
        self._protected_attr_name = f"_{attr_name}"

    def __get__(self, instance, owner=None) -> Any:
        return getattr(instance, self._protected_attr_name)

    def __set__(self, instance, value: Any) -> None:
        # if (self.required or not self.nullable) and not value:
        attr_name = self._attr_name_of_protected(self._protected_attr_name)
        if (self.required or not self.nullable) and value is None:
            raise AbsentRequiredFieldException(f"{instance.__class__.__name__}: absent required field '{attr_name}'")
        if value is not None:
            b, msg = self.validate(value)
            if not b:
                raise WrongFieldContent(f"{instance.__class__.__name__}: wrong field content '{attr_name}': {msg}")
        setattr(instance, self._protected_attr_name, value)


class CharField(BaseClass):

    def validate(self, value) -> (bool, str):
        if not isinstance(value, str):
            return False, "should be str"
        return True, ""


class ArgumentsField(BaseClass):
    pass


class EmailField(CharField):

    def validate(self, value) -> (bool, str):
        if "@" not in value:
            return False, "@ should be in email"
        return True, ""


class PhoneField(BaseClass):
    pass


class DateField(BaseClass):

    def validate(self, value) -> (bool, str):
        try:
            d0 = datetime.datetime.strptime(value, "%d.%m.%Y")
        except Exception as e:
            return False, "should be string in format %d.%m.%Y"
        return True, ""


class BirthDayField(BaseClass):

    def validate(self, value) -> (bool, str):
        try:
            d0 = datetime.datetime.strptime(value, "%d.%m.%Y")
        except Exception as e:
            return False, "should be string in format %d.%m.%Y"
        if (datetime.datetime.now() - d0).days / 365 > 70:
            return False, "should be < 70 years"
        return True, ""


class GenderField(BaseClass):

    def validate(self, value) -> (bool, str):
        if not isinstance(value, int) or value not in [0, 1, 2]:
            return False, "should be str"
        return True, ""


class ClientIDsField(BaseClass):

    def validate(self, value) -> (bool, str):
        if not isinstance(value, list):
            return False, "should be list"
        if len(value) == 0:
            return False, "should be non empty list"
        for x in value:
            if not isinstance(x, int):
                return False, "should be list of ints"
        return True, ""


class BaseClass2(object):

    @classmethod
    def of_dict(cls, js: dict):
        obj = cls.__new__(cls)
        properties = [a[0] for a in inspect.getmembers(cls, lambda x: isinstance(x, property))]
        for k, v in cls.__dict__.items():
            if k[:2] != "__" and k not in properties:
                _v = js[k] if k in js.keys() else None
                setattr(obj, k, _v)
        return obj

    @classmethod
    def of_request(cls, req: dict):
        d = {}
        if "body" in req.keys():
            for k, v in req["body"].items():
                d[k] = v
                if isinstance(v, dict):
                    for k2, v2 in v.items():
                            d[k2] = v2
        return cls.of_dict(d)

    @classmethod
    def of_request_arguments(cls, arg: dict):
        d = {}
        for k, v in arg.items():
            d[k] = v
            if isinstance(v, dict):
                for k2, v2 in v.items():
                        d[k2] = v2
        return cls.of_dict(d)

    def get_list_of_nonempty_fields(self) -> list[str]:
        cls = self.__class__
        properties = [a[0] for a in inspect.getmembers(cls, lambda x: isinstance(x, property))]
        li = []
        for k, v in cls.__dict__.items():
            if k[:2] != "__" and k not in properties:
                if getattr(self, k) is not None:
                    li.append(k)
        return li


class ClientsInterestsRequest(BaseClass2):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)


class OnlineScoreRequest(BaseClass2):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)


class MethodRequest(BaseClass2):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


def check_auth(request):
    if request.is_admin:
        digest = hashlib.sha512((datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).encode('utf-8')).hexdigest()
    else:
        digest = hashlib.sha512((request.account + request.login + SALT).encode('utf-8')).hexdigest()
    return digest == request.token


def method_handler(request, ctx, store):
    if not request:
        return None, FORBIDDEN

    if "body" not in request.keys() or not request["body"]:
        return None, INVALID_REQUEST

    try:
        data_method = MethodRequest.of_request(request)
    except AbsentRequiredFieldException as e:
        logging.info(e)
        return {"msg": str(e)}, INVALID_REQUEST #FORBIDDEN

    if not check_auth(data_method):
        return None, FORBIDDEN


    if data_method.method == "online_score":
        try:
            data = OnlineScoreRequest.of_request_arguments(request["body"]["arguments"])
        except AbsentRequiredFieldException as e:
            logging.info(e)
            return {"msg": str(e)}, INVALID_REQUEST
        except WrongFieldContent as e:
            logging.info(e)
            return {"msg": str(e)}, INVALID_REQUEST

        if data_method.is_admin:
            score = 42
        else:
            score = scoring.get_score(
                store=None,
                phone=data.phone,
                email=data.email,
                birthday=data.birthday,
                gender=data.gender,
                first_name=data.first_name,
                last_name=data.last_name,
            )
        ctx["has"] = data.get_list_of_nonempty_fields()
        return {"score": score}, OK
    elif data_method.method == "clients_interests":
        try:
            data = ClientsInterestsRequest.of_request_arguments(request["body"]["arguments"])
            ctx["nclients"] = len(data.client_ids)
            response = {}
            for client_id in data.client_ids:
                response[str(client_id)] = scoring.get_interests(store, client_id)
            return response, OK
        except AbsentRequiredFieldException as e:
            logging.info(e)
            return {"msg": str(e)}, INVALID_REQUEST
        except WrongFieldContent as e:
            logging.info(e)
            return {"msg": str(e)}, INVALID_REQUEST
    response, code = None, OK
    return response, code


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = None

    def get_request_id(self, headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            request = json.loads(data_string)
        except:
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    response, code = self.router[path]({"body": request, "headers": self.headers}, context, self.store)
                except Exception as e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
        context.update(r)
        logging.info(context)
        self.wfile.write(json.dumps(r).encode('utf-8'))
        return


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("-p", "--port", action="store", type=int, default=8080)
    parser.add_argument("-l", "--log", action="store", default=None)
    args = parser.parse_args()
    logging.basicConfig(filename=args.log, level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    server = HTTPServer(("localhost", args.port), MainHTTPHandler)
    logging.info("Starting server at %s" % args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
