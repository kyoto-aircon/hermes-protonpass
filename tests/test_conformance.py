import pytest

from tests._conformance import SecretSourceConformance
from tests._plugin import ProtonPassSource


class TestProtonPassConformance(SecretSourceConformance):
    @pytest.fixture
    def source(self):
        return ProtonPassSource()
