import pytest

from audit import AuditLog
from transaction_engine import BankAccount

PIN = "4826"  # fictional demo PIN


@pytest.fixture
def account():
    return BankAccount()


@pytest.fixture
def audit():
    return AuditLog()
