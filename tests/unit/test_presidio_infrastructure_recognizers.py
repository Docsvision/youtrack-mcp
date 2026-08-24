"""Isolated tests for Presidio recognizers without loading Stanza models."""

import presidio_analyzer
from presidio_analyzer.nlp_engine import StanzaNlpEngine

from sanitizer_service.service import PresidioAndSecretsSanitizer


class RecordingRegistry:
    def __init__(self):
        self.recognizers = []

    def add_recognizer(self, recognizer):
        self.recognizers.append(recognizer)


class RecordingAnalyzer:
    def __init__(self, **_):
        self.registry = RecordingRegistry()


def test_infrastructure_recognizers_cover_diagnostic_identifiers(monkeypatch):
    monkeypatch.setattr(presidio_analyzer, "AnalyzerEngine", RecordingAnalyzer)
    monkeypatch.setattr(StanzaNlpEngine, "load", lambda _: None)

    sanitizer = PresidioAndSecretsSanitizer()
    recognizers = sanitizer._analyzer.registry.recognizers
    text = (
        r"DB DVS_MOPB_DB_61 host APP1 id "
        r"101be719-14a2-0c65-3d41-4e628a632db8 path \\server01\share\file.txt"
    )

    matched_entities = set()
    for recognizer in recognizers:
        matched_entities.update(
            result.entity_type
            for result in recognizer.analyze(
                text=text,
                entities=recognizer.supported_entities,
            )
        )

    assert matched_entities == {
        "DATABASE",
        "INTERNAL_HOST",
        "INTERNAL_ID",
        "INTERNAL_PATH",
    }
