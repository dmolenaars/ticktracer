from abc import abstractmethod
import json
from typing import Any


class BaseParser:
    def __init__(self):
        pass

    @abstractmethod
    def parse_timestamp(payload: Any) -> float:
        pass


class BinanceParser(BaseParser):
    def __init__(self):
        self.port = "9443"

    def parse_timestamp(self, payload: Any) -> float:
        payload = json.loads(payload)
        if "E" in payload:
            return float(payload.get("E"))


class BybitParser(BaseParser):
    def __init__(self):
        self.port = "443"

    def parse_timestamp(self, payload: Any) -> float:
        payload = json.loads(payload)
        if "ts" in payload:
            return float(payload.get("ts"))


class OKXParser(BaseParser):
    def __init__(self):
        self.port = "8443"

    def parse_timestamp(self, payload: Any) -> float:
        payload = json.loads(payload)
        if "data" in payload:
            return float(payload.get("data")[0].get("ts"))


def get_parser(exchange_id) -> BaseParser:
    supported_parsers = {
        "binance": BinanceParser,
        "bybit": BybitParser,
        "okx": OKXParser,
    }
    return supported_parsers[exchange_id]
