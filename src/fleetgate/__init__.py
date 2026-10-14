"""fleetgate: policy-gated multi-agent incident response for a simulated bare-metal fleet."""
from .audit import AuditLog
from .detect import EWMADetector, SeasonalDetector, ThresholdDetector
from .fleet import FAULTS, Fleet, LoadPattern
from .orchestrator import Orchestrator
from .policy import Decision, Policy, PolicyConfig, Reason
from .runbooks import CATALOG, Tier
from .scenarios import Scenario, load_scenarios
from .topology import Topology

__all__ = ["AuditLog", "CATALOG", "Decision", "EWMADetector", "FAULTS", "Fleet", "LoadPattern", "Orchestrator",
           "Policy", "PolicyConfig", "Reason", "Scenario", "SeasonalDetector", "ThresholdDetector", "Tier",
           "Topology", "load_scenarios"]
__version__ = "0.2.0"
