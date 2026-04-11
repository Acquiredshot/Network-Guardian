"""Wolfpak admin mini-programs — CLI tools for the wolfpak admin team.

Each tool auto-generates a unique device tag (UUID + hostname) stored in
~/.ng_client/ so the base station can identify and monitor which admin
devices are connecting. Tags survive restarts and are tied to the device,
not the session.
"""

from network_guardian.wolfpak.client import WolfpakClient

__all__ = ["WolfpakClient"]
