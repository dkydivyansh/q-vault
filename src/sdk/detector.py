"""
detector.py — Q-Vault Sentinel Deterministic Watchdog & Detection Engine

Implements deterministic, rule-and-graph-based threat detection (zero AI/ML):
  1. Clock-skew reorder buffer (+/- 5s configurable tolerance)
  2. Context-aware privilege escalation rules (admin role + maintenance window)
  3. Directed service-access graph for lateral movement detection
  4. Evaluation metrics: F1, median time-to-alert, false positives per 1,000 events
  5. Automated revocation callback integration
"""

import collections
import hashlib
import statistics
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional, Set, Tuple


class Severity(Enum):
    """Alert severity levels ordered from LOW to CRITICAL."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertType(Enum):
    """Canonical rule-code identifiers."""

    PRIVILEGE_ESCALATION = "PRIV_ESC_001"
    LATERAL_MOVEMENT = "LAT_MOVE_001"
    REPLAY_ATTACK = "REPLAY_001"
    CLOCK_SKEW_EXCEEDED = "CLOCK_001"
    REVOKED_ACCESS_ATTEMPT = "REVOKED_001"
    RAPID_SERVICE_HOP = "HOP_001"


@dataclass
class LogEvent:
    """Audit event ingested by the detection pipeline."""

    event_id: str
    timestamp: float
    received_at: float
    actor: str
    action: str
    source_service: str
    target_service: str
    key_epoch: int
    details: dict = field(default_factory=dict)
    ordering_uncertain: bool = False


@dataclass
class Alert:
    """Detection alert emitted by rule or service-graph evaluation."""

    alert_id: str
    alert_type: AlertType
    severity: Severity
    actor: str
    description: str
    event_ids: List[str]
    violated_rule: str
    services_involved: List[str]
    detected_at: float
    ordering_uncertain: bool = False
    auto_revoke_triggered: bool = False
    violated_path: Optional[str] = None


@dataclass
class DetectionMetrics:
    """Evaluation statistics computed over labeled event batches."""

    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    true_negatives: int = 0
    time_to_alert_seconds: List[float] = field(default_factory=list)
    total_benign_events: int = 0

    def f1_score(self) -> float:
        """Return harmonic mean of precision and recall."""
        # Epsilon prevents division by zero on empty batches.
        precision = self.true_positives / (self.true_positives + self.false_positives + 1e-9)
        recall = self.true_positives / (self.true_positives + self.false_negatives + 1e-9)
        return 2 * precision * recall / (precision + recall + 1e-9)

    def median_tta(self) -> float:
        """Return median time-to-alert in seconds."""
        if not self.time_to_alert_seconds:
            return 0.0
        return statistics.median(self.time_to_alert_seconds)

    def fp_per_1000(self) -> float:
        """Return false positives normalized per 1,000 benign events."""
        if self.total_benign_events == 0:
            return 0.0
        return (self.false_positives / self.total_benign_events) * 1000


class ClockSkewBuffer:
    """Sliding reorder buffer compensating for distributed clock skew."""

    def __init__(self, tolerance_seconds: float = 5.0, max_buffer_size: int = 10_000):
        self._tolerance = tolerance_seconds
        self._max_buffer_size = max_buffer_size
        self._buffer: List[LogEvent] = []
        self._last_settled_ts: Optional[float] = None
        self._lock = threading.Lock()

    def _mark_uncertain(self, events: List[LogEvent]) -> None:
        if events and self._last_settled_ts is not None:
            if abs(events[0].timestamp - self._last_settled_ts) < self._tolerance:
                events[0].ordering_uncertain = True
        for idx in range(len(events) - 1):
            t_a = events[idx].timestamp
            t_b = events[idx + 1].timestamp
            if abs(t_a - t_b) < self._tolerance:
                events[idx].ordering_uncertain = True
                events[idx + 1].ordering_uncertain = True
        if events:
            self._last_settled_ts = events[-1].timestamp

    def ingest(self, event: LogEvent) -> List[LogEvent]:
        """Buffer event and release settled events sorted by timestamp."""
        with self._lock:
            self._buffer.append(event)
            self._buffer.sort(key=lambda e: e.timestamp)

            cutoff = time.time() - self._tolerance
            settled_indices = [i for i, e in enumerate(self._buffer) if e.timestamp <= cutoff]

            if not settled_indices:
                return []

            settled_events: List[LogEvent] = [self._buffer[i] for i in settled_indices]
            self._mark_uncertain(settled_events)

            # Delete in reverse order so earlier list indices remain valid.
            for i in reversed(settled_indices):
                del self._buffer[i]

            if len(self._buffer) > self._max_buffer_size:
                self._buffer = self._buffer[-self._max_buffer_size:]

            return settled_events

    def flush(self) -> List[LogEvent]:
        """Drain and return all buffered events in timestamp order."""
        with self._lock:
            if not self._buffer:
                return []
            self._buffer.sort(key=lambda e: e.timestamp)
            drained = list(self._buffer)
            self._mark_uncertain(drained)
            self._buffer.clear()
            return drained


class ServiceAccessGraph:
    """Directed policy graph tracking allowed service paths and per-actor hops."""

    def __init__(self, allowed_paths: List[List[str]]):
        self._allowed: Set[Tuple[str, str]] = set()
        for path in allowed_paths:
            if len(path) >= 2:
                self._allowed.add((path[0], path[1]))

        self._actor_history: Dict[str, List[Tuple[float, str, str, str]]] = collections.defaultdict(list)

    def is_path_allowed(self, source: str, target: str) -> bool:
        """Return True when (source -> target) is permitted or intra-service."""
        if source == target:
            return True
        return (source, target) in self._allowed

    def record_access(
        self, actor: str, source: str, target: str, timestamp: float, event_id: str = ""
    ) -> None:
        """Record a service-to-service transition for `actor`."""
        self._actor_history[actor].append((timestamp, source, target, event_id))

    def check_lateral_movement(
        self,
        actor: str,
        window_seconds: float = 60.0,
        max_hops: int = 3,
        reference_time: Optional[float] = None,
    ) -> Optional[dict]:
        """Return violation details when recent hops meet `max_hops` and break policy."""
        ref = reference_time if reference_time is not None else time.time()
        cutoff = ref - window_seconds
        history = self._actor_history.get(actor, [])
        recent = [(src, dst, eid) for ts, src, dst, eid in history if ts >= cutoff]
        recent_hops = [(src, dst) for src, dst, _ in recent]

        if len(recent_hops) < max_hops:
            return None

        violated = [(src, dst) for src, dst in recent_hops if not self.is_path_allowed(src, dst)]
        if not violated:
            return None

        event_ids = [eid for _, _, eid in recent if eid]
        return {
            "actor": actor,
            "hops": recent_hops,
            "violated_paths": violated,
            "event_ids": event_ids,
            "window_seconds": window_seconds,
        }

    def check_unauthorized_path(self, actor: str, source: str, target: str) -> bool:
        """Return True if the (source -> target) transition is outside policy."""
        return not self.is_path_allowed(source, target)

    def get_summary(self) -> dict:
        """Return allowed policy edges and recent per-actor access history."""
        allowed_list = [[src, dst] for src, dst in sorted(self._allowed)]
        history_summary = {
            actor: [
                {"timestamp": ts, "source": src, "target": dst, "event_id": eid}
                for ts, src, dst, eid in accesses[-20:]
            ]
            for actor, accesses in self._actor_history.items()
        }
        return {
            "allowed_paths": allowed_list,
            "actor_access_history": history_summary,
        }


class RuleEngine:
    """Deterministic per-event rule evaluator for privilege escalation and revoked access."""

    def __init__(
        self,
        admin_nodes: Set[str] = None,
        maintenance_windows: List[dict] = None,
    ):
        self._admin_nodes: Set[str] = admin_nodes or set()
        self._maintenance_windows: List[dict] = maintenance_windows or []

    def is_in_maintenance_window(self, actor: str, check_time: float) -> bool:
        """Return True when `actor` has an active maintenance window covering `check_time`."""
        for window in self._maintenance_windows:
            if (
                window.get("actor") == actor
                and window.get("start", 0.0) <= check_time <= window.get("end", 0.0)
            ):
                return True
        return False

    def check_privilege_escalation(self, event: LogEvent) -> Optional[Alert]:
        """Flag non-admin privilege actions executed outside maintenance windows."""
        action_lower = event.action.lower()
        is_priv_action = any(
            kw in action_lower for kw in ("grant", "elevate", "sudo", "admin")
        )

        if not is_priv_action:
            return None

        if event.actor in self._admin_nodes:
            return None

        if self.is_in_maintenance_window(event.actor, event.timestamp):
            return None

        alert_id = _make_alert_id(AlertType.PRIVILEGE_ESCALATION.value, event.actor, event.event_id)
        return Alert(
            alert_id=alert_id,
            alert_type=AlertType.PRIVILEGE_ESCALATION,
            severity=Severity.HIGH,
            actor=event.actor,
            description=(
                f"Non-admin actor '{event.actor}' performed privilege-escalating "
                f"action '{event.action}' on '{event.target_service}' outside "
                f"any maintenance window."
            ),
            event_ids=[event.event_id],
            violated_rule=AlertType.PRIVILEGE_ESCALATION.value,
            services_involved=[event.source_service, event.target_service],
            detected_at=time.time(),
            ordering_uncertain=event.ordering_uncertain,
        )

    def check_revoked_access(
        self, event: LogEvent, revoked_nodes: Set[str]
    ) -> Optional[Alert]:
        """Flag any access attempt from an already-revoked actor as CRITICAL."""
        if event.actor not in revoked_nodes:
            return None

        alert_id = _make_alert_id(AlertType.REVOKED_ACCESS_ATTEMPT.value, event.actor, event.event_id)
        return Alert(
            alert_id=alert_id,
            alert_type=AlertType.REVOKED_ACCESS_ATTEMPT,
            severity=Severity.CRITICAL,
            actor=event.actor,
            description=(
                f"Revoked actor '{event.actor}' attempted to access "
                f"'{event.target_service}' via '{event.source_service}'. "
                f"Credential revocation may not have propagated."
            ),
            event_ids=[event.event_id],
            violated_rule=AlertType.REVOKED_ACCESS_ATTEMPT.value,
            services_involved=[event.source_service, event.target_service],
            detected_at=time.time(),
            ordering_uncertain=event.ordering_uncertain,
        )


    def check_replay_event(self, event: LogEvent) -> Optional[Alert]:
        """Flag replay telemetry events emitted by node gateways."""
        if event.action.upper() != "REPLAY_DETECTED":
            return None
        alert_id = _make_alert_id(AlertType.REPLAY_ATTACK.value, event.actor, event.event_id)
        return Alert(
            alert_id=alert_id,
            alert_type=AlertType.REPLAY_ATTACK,
            severity=Severity.HIGH,
            actor=event.actor,
            description=(
                f"Replay attack detected involving actor '{event.actor}' "
                f"from '{event.source_service}' to '{event.target_service}'."
            ),
            event_ids=[event.event_id],
            violated_rule=AlertType.REPLAY_ATTACK.value,
            services_involved=[event.source_service, event.target_service],
            detected_at=time.time(),
            ordering_uncertain=event.ordering_uncertain,
            violated_path=f"{event.source_service}->{event.target_service}",
        )


def _make_alert_id(rule: str, actor: str, event_id: str) -> str:
    raw = f"{rule}:{actor}:{event_id}:{time.time_ns()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


class WatchdogDetector:
    """Thread-safe detection pipeline combining reorder buffering, rules, and service graph."""

    def __init__(
        self,
        allowed_paths: List[List[str]],
        clock_tolerance: float = 5.0,
        lateral_window: float = 60.0,
        lateral_max_hops: int = 3,
        critical_threshold: float = 0.85,
        revocation_callback: Optional[Callable] = None,
        admin_nodes: Set[str] = None,
        maintenance_windows: List[dict] = None,
    ):
        self._clock_buffer = ClockSkewBuffer(tolerance_seconds=clock_tolerance)
        self._graph = ServiceAccessGraph(allowed_paths=allowed_paths)
        self._rules = RuleEngine(
            admin_nodes=admin_nodes,
            maintenance_windows=maintenance_windows,
        )

        self._alerts: List[Alert] = []
        self._lock = threading.RLock()
        self._revocation_callback = revocation_callback
        self._revoked_nodes: Set[str] = set()
        self._metrics = DetectionMetrics()
        self._severity_scores = {
            Severity.LOW: 0.3,
            Severity.MEDIUM: 0.5,
            Severity.HIGH: 0.75,
            Severity.CRITICAL: 1.0,
        }
        self._lateral_window = lateral_window
        self._lateral_max_hops = lateral_max_hops
        self._critical_threshold = critical_threshold

    def add_revoked_node(self, node_id: str) -> None:
        """Register `node_id` as revoked for REVOKED_001 detection."""
        with self._lock:
            self._revoked_nodes.add(node_id)

    def ingest_event(self, event: LogEvent) -> List[Alert]:
        """Ingest event through the clock-skew buffer and evaluate settled events."""
        with self._lock:
            settled = self._clock_buffer.ingest(event)

            new_alerts: List[Alert] = []
            for settled_event in settled:
                alerts = self._process_event(settled_event)
                new_alerts.extend(alerts)

            return new_alerts

    def flush(self) -> List[Alert]:
        """Flush buffered events and evaluate them immediately."""
        with self._lock:
            drained = self._clock_buffer.flush()
            new_alerts: List[Alert] = []
            for event in drained:
                new_alerts.extend(self._process_event(event))
            return new_alerts

    def _process_event(self, event: LogEvent) -> List[Alert]:
        new_alerts: List[Alert] = []

        replay_alert = self._rules.check_replay_event(event)
        if replay_alert:
            new_alerts.append(replay_alert)

        revoked_alert = self._rules.check_revoked_access(event, self._revoked_nodes)
        if revoked_alert:
            new_alerts.append(revoked_alert)

        priv_alert = self._rules.check_privilege_escalation(event)
        if priv_alert:
            new_alerts.append(priv_alert)

        if self._graph.check_unauthorized_path(event.actor, event.source_service, event.target_service):
            # Suppress redundant single-hop alert when revoked-access already fired for this event.
            if not revoked_alert:
                alert_id = _make_alert_id(
                    AlertType.LATERAL_MOVEMENT.value, event.actor, event.event_id
                )
                path_alert = Alert(
                    alert_id=alert_id,
                    alert_type=AlertType.LATERAL_MOVEMENT,
                    severity=Severity.HIGH,
                    actor=event.actor,
                    description=(
                        f"Actor '{event.actor}' accessed '{event.target_service}' "
                        f"from '{event.source_service}' — path not in policy graph."
                    ),
                    event_ids=[event.event_id],
                    violated_rule=AlertType.LATERAL_MOVEMENT.value,
                    services_involved=[event.source_service, event.target_service],
                    detected_at=time.time(),
                    ordering_uncertain=event.ordering_uncertain,
                    violated_path=f"{event.source_service}->{event.target_service}",
                )
                new_alerts.append(path_alert)

        self._graph.record_access(
            actor=event.actor,
            source=event.source_service,
            target=event.target_service,
            timestamp=event.timestamp,
            event_id=event.event_id,
        )

        lat_result = self._graph.check_lateral_movement(
            actor=event.actor,
            window_seconds=self._lateral_window,
            max_hops=self._lateral_max_hops,
            reference_time=event.timestamp,
        )
        if lat_result:
            involved_services: List[str] = []
            seen: Set[str] = set()
            for src, dst in lat_result["hops"]:
                for svc in (src, dst):
                    if svc not in seen:
                        involved_services.append(svc)
                        seen.add(svc)

            contributing_ids = list(dict.fromkeys(lat_result["event_ids"] or [event.event_id]))
            violated_path_str = ", ".join(f"{s}->{d}" for s, d in lat_result["violated_paths"])
            alert_id = _make_alert_id(
                AlertType.LATERAL_MOVEMENT.value + "_win", event.actor, event.event_id
            )
            lat_alert = Alert(
                alert_id=alert_id,
                alert_type=AlertType.LATERAL_MOVEMENT,
                severity=Severity.CRITICAL,
                actor=event.actor,
                description=(
                    f"Lateral movement detected: actor '{event.actor}' made "
                    f"{len(lat_result['hops'])} hops in {lat_result['window_seconds']}s "
                    f"with {len(lat_result['violated_paths'])} policy violation(s): "
                    + violated_path_str
                ),
                event_ids=contributing_ids,
                violated_rule=AlertType.LATERAL_MOVEMENT.value,
                services_involved=involved_services,
                detected_at=time.time(),
                ordering_uncertain=event.ordering_uncertain,
                violated_path=violated_path_str,
            )
            new_alerts.append(lat_alert)

        rapid_hop_alert = self._check_rapid_service_hops(event)
        if rapid_hop_alert:
            new_alerts.append(rapid_hop_alert)

        for alert in new_alerts:
            if self._severity_scores.get(alert.severity, 0.0) >= self._critical_threshold:
                self._trigger_auto_revocation(alert)

        self._alerts.extend(new_alerts)
        return new_alerts

    def _check_rapid_service_hops(self, event: LogEvent) -> Optional[Alert]:
        if event.actor in self._rules._admin_nodes or self._rules.is_in_maintenance_window(
            event.actor, event.timestamp
        ):
            return None

        rapid_window = 30.0
        max_distinct = 3
        cutoff = event.timestamp - rapid_window

        history = self._graph._actor_history.get(event.actor, [])
        recent_services: Set[str] = set()
        contributing_event_ids: List[str] = []
        has_unauthorized_hop = not self._graph.is_path_allowed(
            event.source_service, event.target_service
        )
        for ts, src, dst, eid in history:
            if ts >= cutoff:
                recent_services.add(src)
                recent_services.add(dst)
                if not self._graph.is_path_allowed(src, dst):
                    has_unauthorized_hop = True
                if eid:
                    contributing_event_ids.append(eid)

        recent_services.add(event.source_service)
        recent_services.add(event.target_service)
        if event.event_id:
            contributing_event_ids.append(event.event_id)
        contributing_event_ids = list(dict.fromkeys(contributing_event_ids))

        if len(recent_services) <= max_distinct or not has_unauthorized_hop:
            return None

        alert_id = _make_alert_id(AlertType.RAPID_SERVICE_HOP.value, event.actor, event.event_id)
        return Alert(
            alert_id=alert_id,
            alert_type=AlertType.RAPID_SERVICE_HOP,
            severity=Severity.HIGH,
            actor=event.actor,
            description=(
                f"Actor '{event.actor}' accessed {len(recent_services)} distinct "
                f"services within {rapid_window}s: {sorted(recent_services)}"
            ),
            event_ids=contributing_event_ids,
            violated_rule=AlertType.RAPID_SERVICE_HOP.value,
            services_involved=sorted(recent_services),
            detected_at=time.time(),
            ordering_uncertain=event.ordering_uncertain,
            violated_path=f"{event.source_service}->{event.target_service}",
        )

    def _trigger_auto_revocation(self, alert: Alert) -> None:
        alert.auto_revoke_triggered = True
        self._revoked_nodes.add(alert.actor)

        if self._revocation_callback is not None:
            try:
                self._revocation_callback(alert.actor)
            except Exception:
                # Isolate local containment state from external callback errors.
                pass

    def get_alerts(self, since: float = 0.0) -> List[Alert]:
        """Return generated alerts with `detected_at >= since`."""
        with self._lock:
            return [a for a in self._alerts if a.detected_at >= since]

    def run_batch_evaluation(
        self,
        events: List[LogEvent],
        ground_truth: Dict[str, bool],
    ) -> DetectionMetrics:
        """Evaluate a labeled event batch and compute F1, TTA, and FP/1,000 metrics."""
        metrics = DetectionMetrics()
        event_map: Dict[str, LogEvent] = {e.event_id: e for e in events}

        generated_alerts: List[Alert] = []
        for event in events:
            alerts = self.ingest_event(event)
            generated_alerts.extend(alerts)
        generated_alerts.extend(self.flush())

        alerted_event_ids: Set[str] = set()
        event_to_alerts: Dict[str, List[Alert]] = collections.defaultdict(list)
        for alert in generated_alerts:
            for eid in alert.event_ids:
                alerted_event_ids.add(eid)
                event_to_alerts[eid].append(alert)

        metrics.total_benign_events = sum(
            1 for is_attack in ground_truth.values() if not is_attack
        )

        for event_id, is_attack in ground_truth.items():
            was_alerted = event_id in alerted_event_ids

            if is_attack and was_alerted:
                metrics.true_positives += 1
                ev = event_map.get(event_id)
                if ev:
                    for alert in event_to_alerts[event_id]:
                        tta = alert.detected_at - ev.timestamp
                        # Clamp negative TTA caused by skewed event timestamps.
                        metrics.time_to_alert_seconds.append(max(0.0, tta))
                        break
            elif is_attack and not was_alerted:
                metrics.false_negatives += 1
            elif not is_attack and was_alerted:
                metrics.false_positives += 1
            else:
                metrics.true_negatives += 1

        with self._lock:
            self._metrics = metrics

        return metrics

    def get_metrics_report(self) -> dict:
        """Return summary detection metrics and auto-revocation counts."""
        with self._lock:
            total_alerts = len(self._alerts)
            critical_alerts = sum(
                1 for a in self._alerts if a.severity == Severity.CRITICAL
            )
            auto_revocations = sum(
                1 for a in self._alerts if a.auto_revoke_triggered
            )
            return {
                "f1_score": self._metrics.f1_score(),
                "median_tta_seconds": self._metrics.median_tta(),
                "fp_per_1000_events": self._metrics.fp_per_1000(),
                "total_alerts": total_alerts,
                "critical_alerts": critical_alerts,
                "auto_revocations": auto_revocations,
            }

    def get_service_graph_summary(self) -> dict:
        """Return allowed service graph edges and recent actor access patterns."""
        with self._lock:
            return self._graph.get_summary()
