# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Core engine for Network Guardian.

Orchestrates all subsystems: auditor, monitor, explorer, automator,
AI engine, NLP engine, sensors, dashboard, and plugins.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from network_guardian.config import Config
from network_guardian.core.events import EventBus
from network_guardian.core.plugins import PluginRegistry

if TYPE_CHECKING:
    from network_guardian.agent.smart_firewall_agent import SmartFirewallAgent
    from network_guardian.agent.web_browsing_agent import SafeWebBrowsingAgent
    from network_guardian.agent.probe import ProbeAgent
    from network_guardian.agent.probe_firewall_bridge import ProbeFirewallBridge
    from network_guardian.agent.payload_harvester import PayloadHarvester
    from network_guardian.agent.probe_defensive_scanner import ProbeDefensiveScanner
    from network_guardian.agent.probe_attack_correlator import ProbeAttackCorrelator
    from network_guardian.agent.triage_agent import TriageAgent
    from network_guardian.agent.mcp_protocol_parser import MCPProtocolParser
    from network_guardian.agent.dual_pass_evaluator import DualPassEvaluator
    from network_guardian.agent.isolation_sandbox_engine import IsolationSandboxEngine
    from network_guardian.ai import AIEngine
    from network_guardian.ai.nlp import NLPEngine
    from network_guardian.ai.nodes import NodeGraph
    from network_guardian.ai.training import TrainingPipeline
    from network_guardian.ai.device_baseline import DeviceBaselineManager
    from network_guardian.ai.lateral_movement import LateralMovementDetector
    from network_guardian.auditor import Auditor
    from network_guardian.automator import Automator
    from network_guardian.cloaking import IPCloakingSystem, WiFiStealthSystem
    from network_guardian.explorer import Explorer
    from network_guardian.ids import IntrusionDetectionSystem
    from network_guardian.interface.dashboard import Dashboard
    from network_guardian.ips import IntrusionPreventionSystem
    from network_guardian.monitor import Monitor
    from network_guardian.remote import RemoteAccessManager
    from network_guardian.sensors import SensorRegistry

logger = logging.getLogger("network_guardian.core")


class Engine:
    """Central orchestrator that initialises and coordinates subsystems."""

    def __init__(self, config: Config | None = None) -> None:
        self.config = config or Config()
        self.event_bus = EventBus()
        self.plugins = PluginRegistry()

        self._auditor: Auditor | None = None
        self._monitor: Monitor | None = None
        self._explorer: Explorer | None = None
        self._automator: Automator | None = None
        self._ai: AIEngine | None = None
        self._nlp: NLPEngine | None = None
        self._sensors: SensorRegistry | None = None
        self._dashboard: Dashboard | None = None
        self._node_graph: NodeGraph | None = None
        self._training: TrainingPipeline | None = None
        self._ids: IntrusionDetectionSystem | None = None
        self._ips: IntrusionPreventionSystem | None = None
        self._smart_firewall: SmartFirewallAgent | None = None
        self._web_browsing: SafeWebBrowsingAgent | None = None
        self._cloaking: IPCloakingSystem | None = None
        self._wifi_stealth: WiFiStealthSystem | None = None
        self._remote: RemoteAccessManager | None = None

        self._probe_bridge: ProbeFirewallBridge | None = None
        self._payload_harvester: PayloadHarvester | None = None
        self._defensive_scanner: ProbeDefensiveScanner | None = None
        self._attack_correlator: ProbeAttackCorrelator | None = None
        self._triage: TriageAgent | None = None

        self._mcp_parser: MCPProtocolParser | None = None
        self._dual_pass_evaluator: DualPassEvaluator | None = None
        self._isolation_sandbox: IsolationSandboxEngine | None = None
        self._device_baseline_manager: DeviceBaselineManager | None = None
        self._lateral_movement_detector: LateralMovementDetector | None = None

        self._running = False

    # -- Lazy subsystem access ------------------------------------------

    @property
    def auditor(self) -> Auditor:
        if self._auditor is None:
            from network_guardian.auditor import Auditor
            self._auditor = Auditor(self.config, self.event_bus)
        return self._auditor

    @property
    def monitor(self) -> Monitor:
        if self._monitor is None:
            from network_guardian.monitor import Monitor
            self._monitor = Monitor(self.config, self.event_bus)
        return self._monitor

    @property
    def explorer(self) -> Explorer:
        if self._explorer is None:
            from network_guardian.explorer import Explorer
            self._explorer = Explorer(self.config, self.event_bus)
        return self._explorer

    @property
    def automator(self) -> Automator:
        if self._automator is None:
            from network_guardian.automator import Automator
            self._automator = Automator(self.config, self.event_bus)
        return self._automator

    @property
    def ai(self) -> AIEngine:
        if self._ai is None:
            from network_guardian.ai import AIEngine
            self._ai = AIEngine(self.config, self.event_bus)
        return self._ai

    @property
    def nlp(self) -> NLPEngine:
        if self._nlp is None:
            from network_guardian.ai.nlp import NLPEngine
            self._nlp = NLPEngine(self.config, self.event_bus)
        return self._nlp

    @property
    def sensors(self) -> SensorRegistry:
        if self._sensors is None:
            from network_guardian.sensors import (
                PingSensor, PortScanner, SystemMetricsSensor, SensorRegistry,
            )
            self._sensors = SensorRegistry()
            self._sensors.register(PingSensor(self.config, self.event_bus))
            self._sensors.register(PortScanner(self.config, self.event_bus))
            self._sensors.register(SystemMetricsSensor(self.config, self.event_bus))
        return self._sensors

    @property
    def dashboard(self) -> Dashboard:
        if self._dashboard is None:
            from network_guardian.interface.dashboard import Dashboard
            self._dashboard = Dashboard(self)
        return self._dashboard

    @property
    def node_graph(self) -> NodeGraph:
        """ROS-inspired AI node compute graph."""
        if self._node_graph is None:
            from network_guardian.ai.nodes import NodeGraph
            self._node_graph = NodeGraph.create_default(self.event_bus)
        return self._node_graph

    @property
    def training(self) -> TrainingPipeline:
        """ML training pipeline with model registry."""
        if self._training is None:
            from network_guardian.ai.training import TrainingPipeline
            self._training = TrainingPipeline()
        return self._training

    @property
    def ids(self) -> IntrusionDetectionSystem:
        """Intrusion Detection System."""
        if self._ids is None:
            from network_guardian.ids import IntrusionDetectionSystem
            self._ids = IntrusionDetectionSystem(self.config, self.event_bus)
        return self._ids

    @property
    def ips(self) -> IntrusionPreventionSystem:
        """Intrusion Prevention System."""
        if self._ips is None:
            from network_guardian.ips import IntrusionPreventionSystem
            self._ips = IntrusionPreventionSystem(self.config, self.event_bus)
        return self._ips

    @property
    def smart_firewall(self) -> "SmartFirewallAgent":
        """Autonomous injection-detection and active-blocking agent."""
        if self._smart_firewall is None:
            from network_guardian.agent.smart_firewall_agent import SmartFirewallAgent
            self._smart_firewall = SmartFirewallAgent(
                ips=self.ips,
                event_bus=self.event_bus,
                probe_bridge=None,
                correlator=self.attack_correlator,
            )
            self._smart_firewall.set_probe_bridge(self.probe_bridge)
        return self._smart_firewall

    @property
    def web_browsing(self) -> "SafeWebBrowsingAgent":
        """Autonomous safe-browsing evaluation agent."""
        if self._web_browsing is None:
            from network_guardian.agent.web_browsing_agent import SafeWebBrowsingAgent
            self._web_browsing = SafeWebBrowsingAgent(
                event_bus=self.event_bus,
                ips=self.ips,
            )
        return self._web_browsing

    @property
    def probe_bridge(self) -> "ProbeFirewallBridge":
        """Probe-Firewall intelligence bridge."""
        if self._probe_bridge is None:
            from network_guardian.agent.probe_firewall_bridge import ProbeFirewallBridge
            self._probe_bridge = ProbeFirewallBridge(
                event_bus=self.event_bus,
                smart_firewall=None,
            )
            self._probe_bridge.set_smart_firewall(self.smart_firewall)
        return self._probe_bridge

    @property
    def payload_harvester(self) -> "PayloadHarvester":
        """Payload harvester for rule learning."""
        if self._payload_harvester is None:
            from network_guardian.agent.payload_harvester import PayloadHarvester
            self._payload_harvester = PayloadHarvester(
                event_bus=self.event_bus,
            )
        return self._payload_harvester

    @property
    def defensive_scanner(self) -> "ProbeDefensiveScanner":
        """Defensive scanner for internal vulnerability testing."""
        if self._defensive_scanner is None:
            from network_guardian.agent.probe_defensive_scanner import ProbeDefensiveScanner
            self._defensive_scanner = ProbeDefensiveScanner(
                smart_firewall=self.smart_firewall,
            )
        return self._defensive_scanner

    @property
    def attack_correlator(self) -> "ProbeAttackCorrelator":
        """Attack correlator for probe-discovery matching."""
        if self._attack_correlator is None:
            from network_guardian.agent.probe_attack_correlator import ProbeAttackCorrelator
            self._attack_correlator = ProbeAttackCorrelator()
        return self._attack_correlator

    @property
    def cloaking(self) -> "IPCloakingSystem":
        """IP Cloaking and privacy system."""
        if self._cloaking is None:
            from network_guardian.cloaking import IPCloakingSystem
            self._cloaking = IPCloakingSystem(self.config, self.event_bus)
        return self._cloaking

    @property
    def wifi_stealth(self) -> WiFiStealthSystem:
        """WiFi network stealth system."""
        if self._wifi_stealth is None:
            from network_guardian.cloaking import WiFiStealthSystem
            self._wifi_stealth = WiFiStealthSystem(self.config, self.event_bus)
        return self._wifi_stealth

    @property
    def remote(self) -> RemoteAccessManager:
        """Remote access manager (OpenClaw + CMDOP + messaging)."""
        if self._remote is None:
            from network_guardian.remote import RemoteAccessManager
            self._remote = RemoteAccessManager(self)
        return self._remote

    @property
    def triage(self) -> "TriageAgent":
        """Orchestration Central Brain — master coordinator for all sub-agents."""
        if self._triage is None:
            from network_guardian.agent.triage_agent import TriageAgent
            self._triage = TriageAgent(self)
        return self._triage

    @property
    def mcp_parser(self) -> "MCPProtocolParser":
        """MCP/API Protocol Parser — decodes JSON-RPC, MCP, GraphQL, and multi-agent streams."""
        if self._mcp_parser is None:
            from network_guardian.agent.mcp_protocol_parser import MCPProtocolParser
            self._mcp_parser = MCPProtocolParser(event_bus=self.event_bus)
        return self._mcp_parser

    @property
    def dual_pass_evaluator(self) -> "DualPassEvaluator":
        """Dual-Pass Evaluation Pipeline — async pre/post context injection verification."""
        if self._dual_pass_evaluator is None:
            from network_guardian.agent.dual_pass_evaluator import DualPassEvaluator
            self._dual_pass_evaluator = DualPassEvaluator(
                event_bus=self.event_bus,
                shadow_mode=self.config.shadow_mode,
            )
        return self._dual_pass_evaluator

    @property
    def isolation_sandbox(self) -> "IsolationSandboxEngine":
        """Isolation & Sandboxing Engine — threshold-based TCP session severance and honeypot."""
        if self._isolation_sandbox is None:
            from network_guardian.agent.isolation_sandbox_engine import IsolationSandboxEngine
            self._isolation_sandbox = IsolationSandboxEngine(
                ips=self.ips,
                event_bus=self.event_bus,
                shadow_mode=self.config.shadow_mode,
            )
        return self._isolation_sandbox

    @property
    def device_baseline_manager(self) -> "DeviceBaselineManager":
        """Per-device persistent behavioral baseline manager."""
        if self._device_baseline_manager is None:
            from network_guardian.ai.device_baseline import DeviceBaselineManager
            self._device_baseline_manager = DeviceBaselineManager(
                data_dir=self.config.data_dir / "baselines"
            )
        return self._device_baseline_manager

    @property
    def lateral_movement_detector(self) -> "LateralMovementDetector":
        """Connection fan-out lateral movement detector."""
        if self._lateral_movement_detector is None:
            from network_guardian.ai.lateral_movement import LateralMovementDetector
            self._lateral_movement_detector = LateralMovementDetector(
                data_dir=self.config.data_dir
            )
        return self._lateral_movement_detector

    # -- Lifecycle -------------------------------------------------------

    async def start(self) -> None:
        """Start all subsystems."""
        logger.info("Network Guardian engine starting...")
        self.config.data_dir.mkdir(parents=True, exist_ok=True)
        await self.plugins.start_all()
        if self._node_graph is not None:
            await self._node_graph.start_all()
        # Auto-start the Smart Firewall injection agent
        self.smart_firewall.start()
        # Auto-start the Triage Agent (Orchestration Central Brain)
        self.triage.start()
        # Auto-start semantic stream analysis and sandboxing pipeline
        self.mcp_parser.start()
        await self.dual_pass_evaluator.start()
        await self.isolation_sandbox.start()
        self._running = True
        logger.info("Engine started. Data directory: %s", self.config.data_dir)

    async def stop(self) -> None:
        """Gracefully stop all subsystems."""
        logger.info("Engine shutting down...")
        self._running = False
        if self._isolation_sandbox is not None:
            await self._isolation_sandbox.stop()
        if self._dual_pass_evaluator is not None:
            await self._dual_pass_evaluator.stop()
        if self._mcp_parser is not None:
            self._mcp_parser.stop()
        if self._triage is not None:
            await self._triage.stop()
        if self._smart_firewall is not None:
            self._smart_firewall.stop()
        if self._web_browsing is not None:
            logger.info("[Engine] SafeWebBrowsingAgent stopped (stats: %s)",
                        self._web_browsing.get_stats())
        if self._node_graph is not None:
            await self._node_graph.stop_all()
        if self._dashboard is not None:
            await self._dashboard.stop()
        if self._monitor is not None:
            await self._monitor.stop()
        if self._remote is not None:
            await self._remote.stop()
        await self.plugins.stop_all()
        logger.info("Engine stopped.")

    @property
    def is_running(self) -> bool:
        return self._running
