"""Security Graph — relationship and entity graph for the Wolf-Pak stack.

The Security Graph ingests Detection events from the Event Fabric,
builds and maintains a graph of entities (hosts, users, processes,
files, network endpoints) and their relationships, and exposes
query primitives for investigation and correlation.
"""


__version__ = "0.1.0"
