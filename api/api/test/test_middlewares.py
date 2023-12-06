# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from datetime import datetime
from unittest.mock import patch, MagicMock, AsyncMock
import pytest

from connexion import AsyncApp
from connexion.testing import TestContext

from freezegun import freeze_time
from wazuh.core.exception import WazuhPermissionError, WazuhTooManyRequests

from api.middlewares import check_rate_limit, unlock_ip, \
    CheckRateLimitsMiddleware, WazuhAccessLoggerMiddleware, SecureHeadersMiddleware, secure_headers

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


@freeze_time(datetime(1970, 1, 1, 0, 0, 10))
async def test_middlewares_unlock_ip(mock_request):
    """Test unlock_ip function."""
    # Assert they are not empty
    with patch("api.middlewares.ip_stats", new={'ip': {'timestamp': 5}}) as mock_ip_stats, \
        patch("api.middlewares.ip_block", new={"ip"}) as mock_ip_block:
        unlock_ip(mock_request, 5)
        # Assert that under these conditions, they have been emptied
        assert not mock_ip_stats and not mock_ip_block


@patch("api.middlewares.ip_stats", new={"ip": {'timestamp': 5}})
@patch("api.middlewares.ip_block", new={"ip"})
@freeze_time(datetime(1970, 1, 1))
@pytest.mark.asyncio
async def test_middlewares_unlock_ip_ko(mock_request):
    """Test if `unlock_ip` raises an exception if the IP is still blocked."""
    with patch("api.middlewares.raise_if_exc") as raise_mock:
        unlock_ip(mock_request, 5)
        raise_mock.assert_called_once_with(WazuhPermissionError(6000))


@freeze_time(datetime(1970, 1, 1))
@pytest.mark.parametrize("current_time,max_requests,current_time_key, current_counter_key,expected_error_args", [
    (-80, 300, 'events_current_time', 'events_request_counter', {}),
    (-80, 300, 'general_current_time', 'general_request_counter', {}),
    (0, 0, 'events_current_time', 'events_request_counter', {
        'code': 6005,
        'extra_message': 'For POST /events endpoint the limit is set to 0 requests.'
    }),
    (0, 0, 'general_current_time', 'general_request_counter', {'code': 6001}),
])
def test_middlewares_check_rate_limit(
    current_time, max_requests, current_time_key, current_counter_key,
    expected_error_args, mock_request
):
    """Test if the rate limit mechanism triggers when the `max_requests` are reached."""

    with patch(f"api.middlewares.{current_time_key}", new=current_time), \
        patch("api.middlewares.raise_if_exc") as raise_mock:
        check_rate_limit(
            mock_request,
            current_time_key=current_time_key,
            request_counter_key=current_counter_key,
            max_requests=max_requests)
        if max_requests == 0:
            raise_mock.assert_called_once_with(WazuhTooManyRequests(**expected_error_args))


@pytest.mark.asyncio
async def test_check_rate_limits_middleware(mock_request):
    """Test limits middleware."""
    response = MagicMock()
    dispatch_mock = AsyncMock(return_value=response)

    middleware = CheckRateLimitsMiddleware(AsyncApp(__name__))
    operation = MagicMock(name="operation")
    operation.method = "post"
    with TestContext(operation=operation):
        middleware.dispatch(request=mock_request, call_next=dispatch_mock)


@pytest.mark.asyncio
async def test_wazuh_access_logger_middleware(mock_request):
    """Test access logging."""
    response = MagicMock()
    dispatch_mock = AsyncMock(return_value=response)

    middleware = WazuhAccessLoggerMiddleware(AsyncApp(__name__), dispatch=dispatch_mock)
    operation = MagicMock(name="operation")
    operation.method = "post"
    with TestContext(operation=operation):
        middleware.dispatch(request=mock_request, call_next=dispatch_mock)


@pytest.mark.asyncio
async def test_secure_headers_middleware(mock_request):
    """Test access logging."""
    response = MagicMock()
    dispatch_mock = AsyncMock(return_value=response)

    middleware = SecureHeadersMiddleware(AsyncApp(__name__))
    operation = MagicMock(name="operation")
    operation.method = "post"

    with TestContext(operation=operation), patch('api.middlewares.secure_headers') as mock_secure:
        secure_headers.framework.starlette = MagicMock()
        ret_response = await middleware.dispatch(request=mock_request, call_next=dispatch_mock)
        mock_secure.framework.starlette.assert_called_once_with(response)
        dispatch_mock.assert_awaited_once_with(mock_request)
        assert ret_response == response
