# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from typing import Optional
import json
from connexion.lifecycle import ConnexionRequest, ConnexionResponse
from connexion import exceptions

from api import configuration
from api.middlewares import ip_block, ip_stats
from wazuh.core.utils import get_utc_now


def prevent_bruteforce_attack(request: ConnexionRequest, attempts: int = 5):
    """Checks that the IPs that are requesting an API token do not do so repeatedly.

    Parameters
    ----------
    request : ConnexionRequest
        HTTP request.
    attempts : int
        Number of attempts until an IP is blocked.
    """

    if request.scope['path'] in {'/security/user/authenticate',
                                 '/security/user/authenticate/run_as'} and \
            request.method in {'GET', 'POST'}:
        if request.client.host not in ip_stats:
            ip_stats[request.client.host] = dict()
            ip_stats[request.client.host]['attempts'] = 1
            ip_stats[request.client.host]['timestamp'] = get_utc_now().timestamp()
        else:
            ip_stats[request.client.host]['attempts'] += 1

        if ip_stats[request.client.host]['attempts'] >= attempts:
            ip_block.add(request.client.host)


def _cleanup_detail_field(detail: str) -> str:
    """Replace double endlines with '. ' and simple endlines with ''.

    Parameters
    ----------
    detail : str
        String to be modified.

    Returns
    -------
    str
        New value for the detail field.
    """
    return ' '.join(str(detail).replace("\n\n", ". ").replace("\n", "").split())


async def unauthorized_error_handler(request: ConnexionRequest, 
                                     exc: Exception) -> ConnexionResponse:
    """Unauthorized Exception Error handler.
    
    Parameters
    ----------
    request : ConnexionRequest
        Incomming request.
    exc: Exception
        Raised exception.

    Returns
    -------
    Response
        HTTP Response returned to the client.
    """
    problem = {
        "title": "Unauthorized",
        "type": "about:blank",
    }

    if request.scope['path'] in {'/security/user/authenticate',
                        '/security/user/authenticate/run_as'} and \
        request.method in {'GET', 'POST'}:
        problem["detail"] = "Invalid credentials"

        prevent_bruteforce_attack(
            request=request,
            attempts=configuration.api_conf['access']['max_login_attempts']
        )
    return ConnexionResponse(status_code=exc.status_code,
                             body=json.dumps(problem),
                             content_type="application/problem+json")


async def bad_request_error_handler(_: Optional[ConnexionRequest], 
                                    exc: exceptions.BadRequestProblem) -> ConnexionResponse:
    """Bad Request Exception Error handler.
    
    Parameters
    ----------
    _: ConnexionRequest
        Incomming request.
        Parameter not used.
    exc: Exception
        Raised exception.

    Returns
    -------
    Response
        HTTP Response returned to the client.
    """

    problem = {
        "title": 'Bad Request',
        "type": "about:blank",
    }
    if exc.detail:
        problem['detail'] = exc.detail
    return ConnexionResponse(status_code=exc.status_code,
                             body=json.dumps(problem),
                             content_type="application/problem+json")


async def http_error_handler(_: Optional[ConnexionRequest],
                             exc: exceptions.HTTPException) -> ConnexionResponse:
    """HTTPError Exception Error handler.
    
    Parameters
    ----------
    _ : ConnexionRequest
        Incomming request.
        Unnamed parameter not used.
    exc: Exception
        Raised exception.

    Returns
    -------
    Response
        HTTP Response returned to the client.
    """

    problem = {
        "title": 'HTTPException',
        "type": "about:blank",
    }
    if exc.detail:
        problem['detail'] = exc.detail
    return ConnexionResponse(status_code=exc.status_code,
                             body=json.dumps(problem),
                             content_type="application/problem+json")


async def jwt_error_handler(_: Optional[ConnexionRequest] = None,
                            __: Optional[Exception] = None) -> ConnexionResponse:
    """JWTException Error handler.
    
    Parameters
    ----------
    _ : ConnexionRequest
        Incomming request.
        Unnamed parameter not used.
    __: Exception
        Raised exception.
        Unnamed parameter not used.

    Returns
    -------
    Response
        HTTP Response returned to the client.
    """
    problem = {
        "title": "Unauthorized",
        "type": "about:blank",
        "detail": "Invalid token"
    }

    return ConnexionResponse(status_code=401,
                             body=json.dumps(problem),
                             content_type="application/problem+json")


async def problem_error_handler(_: Optional[ConnexionRequest], 
                                exc: exceptions.ProblemException) -> ConnexionResponse:
    """ProblemException Error handler.
    
    Parameters
    ----------
    request: ConnexionRequest
        Incomming request.
    exc: Exception
        Raised exception.

    Returns
    -------
    Response
        HTTP Response returned to the client.
    """
    problem = {
        "title": exc.title if exc.title else 'Bad Request',
        "type": exc.type if exc.type else 'about:blank',
        "detail": exc.detail if isinstance(exc.detail, dict) \
                    else _cleanup_detail_field(exc.detail)
    }

    problem.update(exc.ext if exc.ext else {})
    if isinstance(problem['detail'], dict):
        for field in ['status', 'type']:
            if field in problem['detail']:
                problem['detail'].pop(field)
    if 'code' in problem:
        problem['error'] = problem.pop('code')
    if not problem['detail']:
        del problem['detail']

    return  ConnexionResponse(body=json.dumps(problem),
                              status_code=exc.__dict__['status'],
                              content_type="application/problem+json")
