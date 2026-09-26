"""Event Fabric — the pub/sub backbone of the Wolf-Pak stack.

The Event Fabric routes Detection, Intel, and Audit events between
modules via an internal bus.  Consumers subscribe to event families
and react asynchronously.
"""


__version__ = "0.1.0"
