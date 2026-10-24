"""Explicitly opt-in; default execution records live stages as skipped."""
import os

import pytest

from integration.validate import Config, live, new_client, preflight, relay_once


@pytest.fixture
async def live_config():
    if os.getenv('TG_RUN_LIVE') != '1':
        pytest.skip('Live Telegram is unverified; TG_RUN_LIVE=1 was not set')
    required = ['TG_API_ID', 'TG_API_HASH', 'TG_SESSION', 'TG_TEST_CHAT']
    if any(not os.getenv(name) for name in required):
        pytest.skip('Live credentials/session/test chat are missing')
    config = Config.from_env()
    try:
        await preflight()
    except OSError:
        pytest.skip('Direct Telegram MTProto TCP is unavailable')
    return config


async def test_live_account(live_config):
    await live(live_config, [1, 2, 4])


async def test_live_authorized_workflow(live_config):
    if not os.getenv('TG_SOURCE_MESSAGE_ID') or not os.getenv('TG_EXPECTED_SHA256'):
        pytest.skip('Approved source message and known SHA-256 are missing')
    config = Config.from_env(workflow=True)
    client = new_client()
    try:
        await client.connect()
        for workers in [1, 2, 4]:
            await relay_once(client, config, workers)
    finally:
        await client.close()
