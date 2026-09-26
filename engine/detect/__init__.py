from engine.detect.base import Context, Detector, Reference, flow_features
from engine.detect.beaconing import BeaconDetector
from engine.detect.ddos import DdosDetector
from engine.detect.dga import DgaDetector
from engine.detect.encrypted import EncryptedDetector
from engine.detect.exfil import ExfilDetector
from engine.detect.scan import ScanDetector

DETECTOR_CLASSES = [
    DdosDetector,
    BeaconDetector,
    DgaDetector,
    EncryptedDetector,
    ScanDetector,
    ExfilDetector,
]

__all__ = [
    "Context",
    "Detector",
    "Reference",
    "flow_features",
    "DETECTOR_CLASSES",
    "BeaconDetector",
    "DdosDetector",
    "DgaDetector",
    "EncryptedDetector",
    "ExfilDetector",
    "ScanDetector",
    "build_detectors",
]


def build_detectors(config: dict | None = None) -> list[Detector]:
    per_detector = dict(config or {})
    return [cls(per_detector.get(cls.name)) for cls in DETECTOR_CLASSES]
