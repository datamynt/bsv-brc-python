"""Tests for BRC-87 overlay name validation."""

from __future__ import annotations

import pytest

from bsv_brc.brc87 import (
    MAX_NAME_LENGTH,
    InvalidNameError,
    is_valid_service_name,
    is_valid_topic_name,
    validate_overlay_name,
    validate_service_name,
    validate_topic_name,
)


# --- valid names ---------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    ["tm_uhrp_files", "tm_tempo_songs", "tm_a", "tm_kvstore", "tm_posts"],
)
def test_valid_topic_names(name):
    assert validate_topic_name(name) == name
    assert is_valid_topic_name(name)


@pytest.mark.parametrize(
    "name",
    ["ls_uhrp_files", "ls_tempo_songs_search", "ls_a", "ls_kvstore", "ls_posts"],
)
def test_valid_service_names(name):
    assert validate_service_name(name) == name
    assert is_valid_service_name(name)


def test_validate_overlay_name_accepts_either_prefix():
    assert validate_overlay_name("tm_x") == "tm_x"
    assert validate_overlay_name("ls_x") == "ls_x"


# --- master-rule violations ----------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "tm_",            # empty descriptor / ends with underscore
        "tm_a_",          # trailing underscore
        "tm__a",          # consecutive underscores
        "tm_a__b",        # consecutive underscores mid-name
        "tm_Files",       # upper-case
        "tm_files1",      # digit
        "tm_file-name",   # hyphen (not lower-case/underscore)
        "TM_files",       # upper-case prefix
        "topic_files",    # wrong prefix
        "tm_uhrp files",  # space
        "_tm_files",      # leading underscore
    ],
)
def test_invalid_names_rejected(name):
    with pytest.raises(InvalidNameError):
        validate_overlay_name(name)


def test_length_limit():
    too_long = "tm_" + "a" * (MAX_NAME_LENGTH - 2)  # 51 chars total
    assert len(too_long) == MAX_NAME_LENGTH + 1
    with pytest.raises(InvalidNameError, match="maximum"):
        validate_overlay_name(too_long)
    # Exactly at the limit is fine.
    at_limit = "tm_" + "a" * (MAX_NAME_LENGTH - 3)
    assert len(at_limit) == MAX_NAME_LENGTH
    assert validate_overlay_name(at_limit) == at_limit


# --- prefix/kind enforcement ---------------------------------------------


def test_topic_kind_rejects_service_prefix():
    with pytest.raises(InvalidNameError, match="must start with 'tm_'"):
        validate_topic_name("ls_files")


def test_service_kind_rejects_topic_prefix():
    with pytest.raises(InvalidNameError, match="must start with 'ls_'"):
        validate_service_name("tm_files")


def test_non_string_rejected():
    with pytest.raises(InvalidNameError, match="must be a string"):
        validate_overlay_name(123)  # type: ignore[arg-type]


def test_is_valid_helpers_never_raise():
    assert is_valid_topic_name("tm_ok") is True
    assert is_valid_topic_name("nope") is False
    assert is_valid_service_name("ls_ok") is True
    assert is_valid_service_name("tm_ok") is False  # wrong prefix for service
