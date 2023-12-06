# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
from unittest.mock import patch, MagicMock
import pytest
from copy import copy

from connexion.exceptions import HTTPException, ProblemException, BadRequestProblem, Unauthorized
from api.error_handler import _cleanup_detail_field, prevent_bruteforce_attack, jwt_error_handler, \
    http_error_handler, problem_error_handler, bad_request_error_handler, unauthorized_error_handler


@pytest.fixture
def request_info(request):
    """Return the dictionary of the parametrize"""
    return request.param if 'prevent_bruteforce_attack' in request.node.name else None


@pytest.fixture
def mock_request(request, request_info):
    """fixture to wrap functions with request"""
    req = MagicMock()
    req.client.host = 'ip'
    if 'prevent_bruteforce_attack' in request.node.name:
        for clave, valor in request_info.items():
            setattr(req, clave, valor)

    return req


def test_cleanup_detail_field():
    """Test `_cleanup_detail_field` function."""
    detail = """Testing

    Details field.
    """

    assert _cleanup_detail_field(detail) == "Testing. Details field."


@pytest.mark.parametrize('stats', [
    {},
    {'ip': {'attempts': 4}},
])
@pytest.mark.parametrize('request_info', [
    {'path': '/security/user/authenticate', 'method': 'GET'},
    {'path': '/security/user/authenticate', 'method': 'POST'},
    {'path': '/security/user/authenticate/run_as', 'method': 'POST'},
], indirect=True)
def test_middlewares_prevent_bruteforce_attack(stats, request_info, mock_request):
    """Test `prevent_bruteforce_attack` blocks IPs when reaching max number of attempts."""
    mock_request.configure_mock(scope={'path': request_info['path']})
    mock_request.method = request_info['method']
    with patch("api.error_handler.ip_stats", new=copy(stats)) as ip_stats, \
        patch("api.error_handler.ip_block", new=set()) as ip_block:
        previous_attempts = ip_stats['ip']['attempts'] if 'ip' in ip_stats else 0
        prevent_bruteforce_attack(mock_request, attempts=5)
        if stats:
            # There were previous attempts. This one reached the limit
            assert ip_stats['ip']['attempts'] == previous_attempts + 1
            assert 'ip' in ip_block
        else:
            # There were not previous attempts
            assert ip_stats['ip']['attempts'] == 1
            assert 'ip' not in ip_block


@pytest.mark.asyncio
@pytest.mark.parametrize('path, method', [
    ('/security/user/authenticate', 'GET'),
    ('/security/user/authenticate', 'POST'),
    ('/user/authenticate/run_as', 'POST'),
    ('/agents', 'POST'),
])
async def test_unauthorized_error_handler(path, method, mock_request):
    """Test unauthorized error handler."""
    problem = {
        "title": "Unauthorized",
        "type": "about:blank",
    }
    mock_request.configure_mock(scope={'path': path})
    mock_request.method = method
    if path in {'/security/user/authenticate', '/security/user/authenticate/run_as'} \
        and method in {'GET', 'POST'}:
        problem['detail'] = "Invalid credentials"
    exc = Unauthorized()
    with patch('api.error_handler.prevent_bruteforce_attack') as mock_pbfa, \
        patch('api.configuration.api_conf', new={'access': {'max_login_attempts': 1000}}):
        response = await unauthorized_error_handler(mock_request, exc)
        if path in {'/security/user/authenticate', '/security/user/authenticate/run_as'} \
            and method in {'GET', 'POST'}:
            mock_pbfa.assert_called_once_with(
                request=mock_request,
                attempts=1000,
            )
    body = json.loads(response.body)
    assert body == problem
    assert response.status_code == exc.status_code
    assert response.content_type == "application/problem+json"


@pytest.mark.asyncio
async def test_jwt_error_handler():
    """Test jwt error handler."""
    response = await jwt_error_handler()
    problem = {
        "title": "Unauthorized",
        "type": "about:blank",
        "detail": "Invalid token"
    }
    body = json.loads(response.body)
    assert body == problem
    assert response.status_code == 401
    assert response.content_type == "application/problem+json"


@pytest.mark.asyncio
@pytest.mark.parametrize('detail', [None, 'detail'])
async def test_http_error_handler(detail):
    """Test http error handler."""
    exc = HTTPException(status_code=401, detail=detail)
    response = await http_error_handler(None, exc)
    problem = {
        "title": 'HTTPException',
        "type": "about:blank",
    }
    problem.update({'detail': detail} if detail else {'detail': 'Unauthorized'})
    body = json.loads(response.body)
    assert body == problem
    assert response.status_code == 401
    assert response.content_type == "application/problem+json"


@pytest.mark.asyncio
@pytest.mark.parametrize('title, detail, ext, error_type', [
                          ('title', 'detail \n detail\n', {}, None),
                          ('', 'detail', {}, None),
                          ('', '', {}, None),
                          ('', 'detail', {'status': 'status'}, None),
                          ('', 'detail', {'type': 'type'}, None),
                          ('', 'detail', {'code': 3005}, None),
                          ('', 'detail', {'code': 3005}, None),
                          ('', 'detail', {'code': 3005}, 'type'),
                          ('', {'detail_1':'detail_1'}, {'code': 3005}, 'type'),
                          ('', {}, {'code': 3005}, 'type'),
                          ('', {}, {'status': 'status'}, 'type'),
                          ('', {}, {'type': 'type'}, 'type'),
                          ('', {}, {'type': 'type', 'more': 'more'}, 'type'),
])
async def test_problem_error_handler(title, detail, ext, error_type):
    """Test problem error handler."""
    exc = ProblemException(status=400, title=title, detail=detail, ext=ext, type=error_type)
    response = await problem_error_handler(None, exc)
    body = json.loads(response.body)

    if isinstance(detail, dict):
        if 'type' in detail:
            detail.pop('type')
        if 'status' in detail:
            detail.pop('status')
    elif isinstance(detail, str):
        detail = _cleanup_detail_field(detail)
    problem = {}
    problem.update({'title': title} if title else {'title': 'Bad Request'})
    problem.update({'type': error_type} if error_type else {'type': 'about:blank'})
    problem.update({'detail': detail} if detail else {})
    problem.update(ext if ext else {})
    problem.update({'error': problem.pop('code')} if 'code' in problem else {})

    assert response.status_code == 400
    assert response.content_type == "application/problem+json"
    assert body == problem


@pytest.mark.asyncio
@pytest.mark.parametrize('detail', [None, 'detail'])
async def test_bad_request_error_handler(detail):
    """Test bad request error handler."""
    problem = {
        "title": 'Bad Request',
        "type": "about:blank",
    }
    problem.update({'detail': detail} if detail else {})

    exc = BadRequestProblem(detail=detail)
    response = await bad_request_error_handler(None, exc)
    body = json.loads(response.body)
    assert body == problem
    assert response.status_code == exc.status_code
    assert response.content_type == "application/problem+json"
