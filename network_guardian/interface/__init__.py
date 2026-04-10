"""
Interactive CLI interface for Network Guardian.

Provides the main command-line interface for human-AI collaboration.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, TYPE_CHECKING

from network_guardian.core.events import Event, EventBus

if TYPE_CHECKING:
    from network_guardian.core.engine import Engine

logger = logging.getLogger("network_guardian.interface")


class InteractiveCLI:
    """REPL-style interactive interface for Network Guardian."""

    COMMANDS = {
        "help":      "Show available commands",
        "audit":     "Run a network audit (usage: audit <target>)",
        "explore":   "Discover hosts in a subnet (usage: explore <subnet>)",
        "monitor":   "Start/stop monitoring (usage: monitor start|stop)",
        "tasks":     "List or run automated tasks (usage: tasks [list|run <name>])",
        "ai":        "AI commands (usage: ai recommend|classify)",
        "ask":       "Natural language query (usage: ask <question>)",
        "sensors":   "Show sensor status (usage: sensors [list|collect <name>])",
        "dashboard": "Start/stop the web dashboard (usage: dashboard start|stop)",
        "train":     "Train ML models (usage: train anomaly|forecast [method])",
        "nodes":     "AI node graph (usage: nodes start|stop|status|topology)",
        "datasets":  "Dataset tools (usage: datasets generate|stats)",
        "ids":       "Intrusion Detection System (usage: ids start|stop|status|scan <text>)",
        "ips":       "Intrusion Prevention System (usage: ips start|stop|status|block|unblock <ip>)",
        "cloak":     "IP Cloaking (usage: cloak mode|mask|identity|decoys|status)",
        "remote":    "Remote access (usage: remote status|channels|users|pipeline|start|stop)",
        "status":    "Show engine status",
        "quit":      "Exit Network Guardian",
    }

    def __init__(self, engine: Engine) -> None:
        self.engine = engine
        self._dispatch: dict[str, Any] = {
            "help": lambda _: self._show_help(),
            "status": lambda _: self._show_status(),
            "audit": self._handle_audit,
            "explore": self._handle_explore,
            "monitor": self._handle_monitor,
            "tasks": self._handle_tasks,
            "ai": self._handle_ai,
            "ask": lambda args: self._handle_ask(args),
            "sensors": self._handle_sensors,
            "dashboard": self._handle_dashboard,
            "train": self._handle_train,
            "nodes": self._handle_nodes,
            "datasets": self._handle_datasets,
            "ids": self._handle_ids,
            "ips": self._handle_ips,
            "cloak": self._handle_cloak,
            "remote": self._handle_remote,
        }

    async def run(self) -> None:
        """Main interactive loop."""
        print("\n=== Network Guardian ===")
        print("Type 'help' for available commands.\n")

        while True:
            try:
                raw = await asyncio.to_thread(input, "guardian> ")
            except (EOFError, KeyboardInterrupt):
                print()
                break

            parts = raw.strip().split()
            if not parts:
                continue

            cmd, *args = parts

            if cmd == "quit":
                break

            handler = self._dispatch.get(cmd)
            if handler is None:
                print(f"Unknown command: {cmd}. Type 'help' for options.")
                continue

            result = handler(args)
            if asyncio.iscoroutine(result):
                await result

    def _show_help(self) -> None:
        print("\nAvailable commands:")
        for cmd, desc in self.COMMANDS.items():
            print(f"  {cmd:<12} {desc}")
        print()

    def _show_status(self) -> None:
        status = "running" if self.engine.is_running else "stopped"
        print(f"Engine status: {status}")
        print(f"Data directory: {self.engine.config.data_dir}")

    async def _handle_audit(self, args: list[str]) -> None:
        if not args:
            print("Usage: audit <target> [target2 ...]")
            return
        findings = await self.engine.auditor.run_audit(args)
        print(f"Audit complete. {len(findings)} finding(s).")
        for f in findings:
            print(f"  [{f.severity.value.upper()}] {f.title}")

    async def _handle_explore(self, args: list[str]) -> None:
        if not args:
            print("Usage: explore <subnet>")
            return
        hosts = await self.engine.explorer.discover(args[0])
        print(f"Discovery complete. {len(hosts)} host(s) found.")

    async def _handle_monitor(self, args: list[str]) -> None:
        if not args or args[0] not in ("start", "stop"):
            print("Usage: monitor start|stop")
            return
        if args[0] == "start":
            self.engine.monitor.start()
            print("Monitoring started.")
        else:
            await self.engine.monitor.stop()
            print("Monitoring stopped.")

    async def _handle_tasks(self, args: list[str]) -> None:
        if not args or args[0] == "list":
            tasks = self.engine.automator.list_tasks()
            if not tasks:
                print("No tasks registered.")
            else:
                for t in tasks:
                    print(f"  {t.name:<20} {t.description}")
        elif args[0] == "run" and len(args) > 1:
            result = await self.engine.automator.run(args[1])
            print(f"Task '{result.task_name}': {result.status.value}")
            if result.error:
                print(f"  Error: {result.error}")
        else:
            print("Usage: tasks [list|run <name>]")

    async def _handle_ai(self, args: list[str]) -> None:
        if not args:
            print("Usage: ai recommend|classify|models")
            return
        ai_handlers = {
            "models": self._ai_models,
            "recommend": self._ai_recommend,
            "classify": self._ai_classify,
        }
        handler = ai_handlers.get(args[0])
        if handler is None:
            print("Usage: ai recommend|classify|models")
            return
        result = handler(args)
        if asyncio.iscoroutine(result):
            await result

    def _ai_models(self, _args: list[str]) -> None:
        print("Registered AI models:")
        for name in self.engine.ai.model_names:
            print(f"  {name}")

    async def _ai_recommend(self, _args: list[str]) -> None:
        findings = self.engine.auditor.findings if self.engine._auditor else []
        recs = await self.engine.ai.generate_recommendations(findings, [])
        if not recs:
            print("No recommendations (run an audit first).")
        for r in recs:
            print(f"  [{r.priority.value.upper()}] {r.title}")
            for a in r.actions:
                print(f"    -> {a}")

    async def _ai_classify(self, args: list[str]) -> None:
        if len(args) < 3:
            print("Usage: ai classify <metric_name> <value>")
            return
        pred = await self.engine.ai.classify_anomaly({
            "metric_name": args[1], "value": float(args[2]), "z_score": 0.0,
        })
        print(f"  Prediction: {pred.label} (confidence: {pred.confidence:.2f})")

    def _handle_ask(self, args: list[str]) -> None:
        if not args:
            print("Usage: ask <natural language question>")
            return
        text = " ".join(args)
        intent = self.engine.nlp.parse_intent(text)
        print(f"  Parsed intent: action={intent.action}, "
              f"targets={intent.targets}, confidence={intent.confidence:.2f}")

    async def _handle_sensors(self, args: list[str]) -> None:
        if not args or args[0] == "list":
            print("Registered sensors:")
            for name in self.engine.sensors.names:
                print(f"  {name}")
        elif args[0] == "collect":
            if len(args) > 1:
                sensor = self.engine.sensors.get(args[1])
                reading = await sensor.collect()
                print(f"  [{reading.sensor_name}] {reading.data}")
            else:
                readings = await self.engine.sensors.collect_all()
                for r in readings:
                    print(f"  [{r.sensor_name}] {r.data}")
        else:
            print("Usage: sensors [list|collect [name]]")

    async def _handle_dashboard(self, args: list[str]) -> None:
        if not args or args[0] not in ("start", "stop"):
            print("Usage: dashboard start|stop")
            return
        if args[0] == "start":
            await self.engine.dashboard.start()
            print(f"Dashboard running on {self.engine.dashboard.host}:{self.engine.dashboard.port}")
        else:
            await self.engine.dashboard.stop()

    def _handle_train(self, args: list[str]) -> None:
        if not args:
            print("Usage: train anomaly|forecast [method]")
            return
        if args[0] == "anomaly":
            report = self.engine.training.run_full_anomaly_pipeline()
            print(report.summary())
        elif args[0] == "forecast":
            method = args[1] if len(args) > 1 else "arima"
            report = self.engine.training.run_full_forecast_pipeline(method=method)
            print(report.summary())
        else:
            print("Usage: train anomaly|forecast [method]")

    async def _handle_nodes(self, args: list[str]) -> None:
        if not args:
            print("Usage: nodes start|stop|status|topology")
            return
        if args[0] == "start":
            await self.engine.node_graph.start_all()
            print(f"AI node graph started ({len(self.engine.node_graph.node_names)} nodes).")
        elif args[0] == "stop":
            await self.engine.node_graph.stop_all()
            print("AI node graph stopped.")
        elif args[0] == "status":
            for h in self.engine.node_graph.health_all():
                print(f"  {h['node']:<30} {h['state']:<10} in={h['messages_in']} out={h['messages_out']} err={h['errors']}")
        elif args[0] == "topology":
            topo = self.engine.node_graph.topology()
            for name, wiring in topo.items():
                print(f"  {name}:")
                print(f"    inputs:  {wiring['inputs']}")
                print(f"    outputs: {wiring['outputs']}")
        else:
            print("Usage: nodes start|stop|status|topology")

    def _handle_datasets(self, args: list[str]) -> None:
        if not args:
            print("Usage: datasets generate|stats")
            return
        if args[0] == "generate":
            from network_guardian.ai.datasets import NetworkTrafficGenerator
            gen = NetworkTrafficGenerator()
            ds = gen.generate()
            print(f"Generated dataset: {ds.name} ({len(ds)} samples, {len(ds.feature_names)} features)")
        elif args[0] == "stats":
            from network_guardian.ai.datasets import NetworkTrafficGenerator, compute_statistics
            gen = NetworkTrafficGenerator()
            ds = gen.generate()
            stats = compute_statistics(ds)
            for feat, s in stats.items():
                print(f"  {feat:<16} mean={s['mean']:>10.2f}  std={s['std']:>10.2f}  min={s['min']:>10.2f}  max={s['max']:>10.2f}")
        else:
            print("Usage: datasets generate|stats")

    # -- IDS / IPS / Cloaking handlers ----------------------------------

    async def _handle_ids(self, args: list[str]) -> None:
        if not args:
            print("Usage: ids start|stop|status|scan <text>|rules|alerts")
            return
        ids = self.engine.ids
        sub = args[0]
        if sub == "start":
            await self.engine.event_bus.publish(
                Event(topic="ids.started", data={}),
            )
            print("IDS started.")
        elif sub == "stop":
            print("IDS stopped.")
        elif sub == "status":
            print(f"  Rules loaded : {len(ids.rules)}")
            print(f"  Alerts fired : {len(ids.alerts)}")
        elif sub == "scan" and len(args) > 1:
            payload = " ".join(args[1:])
            alerts = await ids.analyse_payload(payload, source_ip="cli")
            if alerts:
                for a in alerts:
                    print(f"  [{a.severity.value.upper()}] {a.category.value}: {a.description}")
            else:
                print("  No threats detected.")
        elif sub == "rules":
            for r in ids.rules:
                status = "enabled" if r.enabled else "disabled"
                print(f"  SID {r.sid:<6} [{status:<8}] {r.name}")
        elif sub == "alerts":
            if not ids.alerts:
                print("  No alerts recorded.")
            else:
                for a in ids.alerts:
                    print(f"  [{a.severity.value.upper()}] {a.category.value}: "
                          f"{a.description} (src={a.source_ip})")
        else:
            print("Usage: ids start|stop|status|scan <text>|rules|alerts")

    async def _handle_ips(self, args: list[str]) -> None:
        if not args:
            print("Usage: ips start|stop|status|block <ip>|unblock <ip>|allowlist|blocked")
            return
        ips = self.engine.ips
        sub = args[0]
        if sub == "start":
            ips.set_auto_respond(True)
            await self.engine.event_bus.publish(
                Event(topic="ips.started", data={}),
            )
            print("IPS started (auto-respond enabled).")
        elif sub == "stop":
            ips.set_auto_respond(False)
            print("IPS stopped (auto-respond disabled).")
        elif sub == "status":
            blocked = ips.blocked_ips
            print(f"  Blocked IPs      : {len(blocked)}")
            print(f"  Quarantined IPs  : {len(ips.quarantined_ips)}")
            print(f"  Allowlist entries : {len(ips.allowlist)}")
        elif sub == "block" and len(args) > 1:
            from network_guardian.ips import BlockReason
            ip = args[1]
            duration = int(args[2]) if len(args) > 2 else 3600
            await ips.block_ip(ip, reason=BlockReason.MANUAL, duration=duration)
            print(f"  Blocked {ip} for {duration}s.")
        elif sub == "unblock" and len(args) > 1:
            if await ips.unblock_ip(args[1]):
                print(f"  Unblocked {args[1]}.")
            else:
                print(f"  {args[1]} is not blocked.")
        elif sub == "allowlist":
            for ip in sorted(ips.allowlist):
                print(f"  {ip}")
        elif sub == "blocked":
            entries = ips.blocked_ips
            if not entries:
                print("  No IPs currently blocked.")
            else:
                for b in entries:
                    exp = "permanent" if b.expires_at is None else f"{b.expires_at - __import__('time').monotonic():.0f}s remaining"
                    print(f"  {b.ip:<18} reason={b.reason.value}  expires={exp}")
        else:
            print("Usage: ips start|stop|status|block <ip>|unblock <ip>|allowlist|blocked")

    def _handle_cloak(self, args: list[str]) -> None:
        if not args:
            print("Usage: cloak mode <mode>|mask <ip>|identity create|activate|list|decoys <subnet>|status")
            return
        cloak = self.engine.cloaking
        sub = args[0]
        if sub == "status":
            print(f"  Mode            : {cloak.mode.value}")
            print(f"  Active identity : {cloak.active_identity or 'none'}")
            print(f"  Proxy hops      : {len(cloak.proxy_chain)}")
            print(f"  Identities      : {len(cloak.list_identities())}")
        elif sub == "mode" and len(args) > 1:
            from network_guardian.cloaking import CloakMode
            try:
                cloak.set_mode(CloakMode(args[1]))
                print(f"  Cloaking mode set to: {args[1]}")
            except ValueError:
                modes = ", ".join(m.value for m in CloakMode)
                print(f"  Invalid mode. Choose from: {modes}")
        elif sub == "mask" and len(args) > 1:
            masked = cloak.mask_ip(args[1])
            print(f"  {args[1]} -> {masked}")
        elif sub == "identity":
            if len(args) < 2:
                print("Usage: cloak identity create <name> <mode>|activate <name>|list")
                return
            if args[1] == "list":
                idents = cloak.list_identities()
                if not idents:
                    print("  No identities configured.")
                else:
                    for ident in idents:
                        active = " [ACTIVE]" if ident.name == cloak.active_identity else ""
                        print(f"  {ident.name:<20} mode={ident.mode.value}{active}")
            elif args[1] == "create" and len(args) >= 4:
                from network_guardian.cloaking import CloakMode
                try:
                    mode = CloakMode(args[3])
                except ValueError:
                    modes = ", ".join(m.value for m in CloakMode)
                    print(f"  Invalid mode. Choose from: {modes}")
                    return
                cloak.create_identity(args[2], mode)
                print(f"  Identity '{args[2]}' created (mode={args[3]}).")
            elif args[1] == "activate" and len(args) >= 3:
                if cloak.activate_identity(args[2]):
                    print(f"  Activated identity: {args[2]}")
                else:
                    print(f"  Identity '{args[2]}' not found.")
            else:
                print("Usage: cloak identity create <name> <mode>|activate <name>|list")
        elif sub == "decoys" and len(args) > 1:
            decoys = cloak.generate_decoys(args[1])
            print(f"  Generated {len(decoys)} decoy(s):")
            for d in decoys:
                ports = ", ".join(str(p) for p in d.ports)
                print(f"    {d.ip}  ports=[{ports}]")
        else:
            print("Usage: cloak mode <mode>|mask <ip>|identity create|activate|list|decoys <subnet>|status")

    # -- Remote access handler ---------------------------------------------

    async def _handle_remote(self, args: list[str]) -> None:
        if not args:
            print("Usage: remote status|channels|users|pipeline <name>|start|stop")
            return
        remote = self.engine.remote
        sub = args[0]
        if sub == "status":
            status = "running" if remote.is_running else "stopped"
            print(f"  Remote access : {status}")
            print(f"  Channels      : {remote.channel_count}")
            print(f"  Active        : {len(remote.active_channels)}")
            print(f"  Users         : {remote.permissions.user_count}")
            print(f"  Pipelines     : {len(remote.orchestrator.pipeline_names)}")
        elif sub == "channels":
            channels = remote.active_channels
            if not channels:
                print("  No active channels.")
            else:
                for ch in channels:
                    print(f"  {ch.value}")
        elif sub == "users":
            users = remote.permissions.list_users()
            if not users:
                print("  No users configured.")
            else:
                for u in users:
                    label = f" ({u.label})" if u.label else ""
                    print(f"  {u.channel.value}:{u.user_id} [{u.permission.value}]{label}")
        elif sub == "pipeline" and len(args) > 1:
            name = args[1]
            context: dict[str, str] = {}
            # Parse key=value pairs from remaining args
            for arg in args[2:]:
                if "=" in arg:
                    k, v = arg.split("=", 1)
                    context[k] = v
            result = await remote.execute_pipeline(name, context)
            print(f"  {result.summary}")
            for step_name, step_result in result.results.items():
                status_icon = "✓" if step_result.success else "✗"
                print(f"    {status_icon} {step_name}: {step_result.output[:80]}")
        elif sub == "pipelines":
            names = remote.orchestrator.pipeline_names
            if not names:
                print("  No pipelines available.")
            else:
                for n in names:
                    print(f"  {n}")
        elif sub == "start":
            await remote.start()
            print("  Remote access started.")
        elif sub == "stop":
            await remote.stop()
            print("  Remote access stopped.")
        else:
            print("Usage: remote status|channels|users|pipeline <name>|start|stop")
