from __future__ import annotations

import abc
from pathlib import Path
from typing import Generator, Union
from dns_detector.models.query import DNSQuery


class BaseParser(abc.ABC):
    """Abstract base class for DNS log parsers."""

    def __init__(self, filepath: Union[str, Path]) -> None:
        self.filepath = Path(filepath)

    @abc.abstractmethod
    def parse(self) -> Generator[DNSQuery, None, None]:
        """Yields parsed DNSQuery objects from the source file."""
        raise NotImplementedError
