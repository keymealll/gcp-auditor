"""Abstract base class for cloud providers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from cloud_audit.models import Category

# A check is a callable that returns a CheckResult
CheckFn = Any  # Callable[[], CheckResult] - simplified for Python 3.10 compat


def make_check(
    check_fn: Any,
    provider: Any,
    check_id: str,
    category: Category,
) -> CheckFn:
    """Create a check function wrapper.

    Args:
        check_fn: The check function to wrap
        provider: The provider instance to pass to the check
        check_id: The check identifier
        category: The category of the check

    Returns:
        Wrapped check function
    """
    # Store metadata on the function
    check_fn._check_id = check_id
    check_fn._category = category
    return check_fn


class BaseProvider(ABC):
    """Base class that all cloud providers must implement."""

    @abstractmethod
    def get_account_id(self) -> str:
        """Return the account/subscription identifier."""

    @abstractmethod
    def get_checks(self, categories: list[str] | None = None) -> list[CheckFn]:
        """Return list of check functions to execute.

        Args:
            categories: Optional filter - only return checks for these categories.
        """

    @abstractmethod
    def get_provider_name(self) -> str:
        """Return provider name (e.g. 'aws', 'azure')."""
