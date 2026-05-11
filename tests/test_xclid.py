import pytest

from twscrape.xclid import XClIdGenError, get_scripts_list


def test_get_scripts_list_raises_xclid_error_on_missing_markers():
    with pytest.raises(XClIdGenError):
        list(get_scripts_list("<html>No xclid markers here</html>"))
