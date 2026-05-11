import os

import pytest

from twscrape.accounts_pool import NoAccountError
import twscrape.api as api_module
from twscrape.api import API, OP_SearchTimeline
from twscrape.utils import gather, get_env_bool


class MockedError(Exception):
    pass


GQL_GEN = [
    "search",
    "tweet_replies",
    "retweeters",
    "followers",
    "following",
    "user_tweets",
    "user_tweets_and_replies",
    "list_timeline",
    "trends",
]


async def test_gql_params(api_mock: API, monkeypatch):
    for func in GQL_GEN:
        args = []

        def mock_gql_items(*a, **kw):
            args.append((a, kw))
            raise MockedError()

        try:
            monkeypatch.setattr(api_mock, "_gql_items", mock_gql_items)
            await gather(getattr(api_mock, func)("user1", limit=100, kv={"count": 100}))
        except MockedError:
            pass

        assert len(args) == 1, f"{func} not called once"
        assert args[0][1]["limit"] == 100, f"limit not changed in {func}"
        assert args[0][0][1]["count"] == 100, f"count not changed in {func}"


async def test_raise_when_no_account(api_mock: API):
    await api_mock.pool.delete_accounts(["user1"])
    assert len(await api_mock.pool.get_all()) == 0

    assert get_env_bool("TWS_RAISE_WHEN_NO_ACCOUNT") is False
    os.environ["TWS_RAISE_WHEN_NO_ACCOUNT"] = "1"
    assert get_env_bool("TWS_RAISE_WHEN_NO_ACCOUNT") is True

    with pytest.raises(NoAccountError):
        await gather(api_mock.search("foo", limit=10))

    with pytest.raises(NoAccountError):
        await api_mock.user_by_id(123)

    del os.environ["TWS_RAISE_WHEN_NO_ACCOUNT"]
    assert get_env_bool("TWS_RAISE_WHEN_NO_ACCOUNT") is False


async def test_gql_items_empty_entries_returns_no_results(api_mock: API, monkeypatch):
    class DummyResponse:
        def __init__(self, obj):
            self._obj = obj

        def json(self):
            return self._obj

    class DummyQueueClient:
        def __init__(self, pool, queue, debug=False, proxy=None):
            self.pool = pool

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def get(self, url, params=None):
            return DummyResponse({"entries": []})

    monkeypatch.setattr(api_module, "QueueClient", DummyQueueClient)

    items = []
    async for rep in api_mock._gql_items(OP_SearchTimeline, {"rawQuery": "foo"}):
        items.append(rep)

    assert items == []


async def test_gql_items_malformed_entries_returns_no_results(api_mock: API, monkeypatch):
    class DummyResponse:
        def __init__(self, obj):
            self._obj = obj

        def json(self):
            return self._obj

    class DummyQueueClient:
        def __init__(self, pool, queue, debug=False, proxy=None):
            self.pool = pool

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def get(self, url, params=None):
            return DummyResponse({"entries": [{"noEntryId": "123"}]})

    monkeypatch.setattr(api_module, "QueueClient", DummyQueueClient)

    items = []
    async for rep in api_mock._gql_items(OP_SearchTimeline, {"rawQuery": "foo"}):
        items.append(rep)

    assert items == []
