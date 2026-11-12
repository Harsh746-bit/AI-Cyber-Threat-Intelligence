"""
SENTRIX Controlled Incident Response & Automated Execution Engine
------------------------------------------------------------------
Manages human-approved containment actions (BLOCK_IP, RATE_LIMIT) with
strict safety allowlist validation to protect infrastructure and hosts.
"""

from datetime import datetime, timezone
from typing import Optional, Set
from sqlalchemy.orm import Session

from backend.app.models.response import ResponseAction

"""
SENTRIX Controlled Incident Response & Automated Execution Engine
------------------------------------------------------------------
Manages human-approved containment actions (BLOCK_IP, RATE_LIMIT) with
strict safety allowlist and subnet validation to protect critical infrastructure,
DNS gateways, and management hosts using Python's standard `ipaddress` module.
"""

from datetime import datetime, timezone
import ipaddress
import os
from typing import List, Optional, Set, Union
from sqlalchemy.orm import Session

from backend.app.models.response import ResponseAction

# Default individual infrastructure IPs to protect from accidental containment
DEFAULT_PROTECTED_HOSTS: Set[str] = {
    "127.0.0.1",
    "::1",
    "0.0.0.0",
    "::",
    "10.0.0.1",
    "192.168.1.1",
    "localhost",
}

# Default CIDR subnets representing core enterprise management networks
DEFAULT_PROTECTED_NETWORKS: List[str] = [
    # Optional CIDR blocks can be configured here or loaded via env SENTRIX_PROTECTED_CIDRS
]


class ResponseEngine:
    """
    Safely executes, verifies, and rolls back defensive containment actions.
    Enforces deep IP validation using `ipaddress` to prevent containment of loopback,
    unspecified, link-local, multicast, broadcast, and configured infrastructure targets.
    """

    def __init__(
        self,
        protected_ips: Optional[Set[str]] = None,
        protected_cidrs: Optional[List[str]] = None,
    ):
        raw_hosts = protected_ips if protected_ips is not None else DEFAULT_PROTECTED_HOSTS
        env_cidrs = os.getenv("SENTRIX_PROTECTED_CIDRS", "")
        extra_cidrs = [c.strip() for c in env_cidrs.split(",") if c.strip()]
        raw_cidrs = (protected_cidrs if protected_cidrs is not None else DEFAULT_PROTECTED_NETWORKS) + extra_cidrs

        self.protected_hosts: Set[str] = set()
        self.protected_ip_objects: Set[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]] = set()

        for host in raw_hosts:
            host_clean = host.strip().lower()
            if not host_clean:
                continue
            self.protected_hosts.add(host_clean)
            try:
                ip_obj = ipaddress.ip_address(host_clean)
                self.protected_ip_objects.add(ip_obj)
            except ValueError:
                # Hostnames such as 'localhost'
                pass

        self.protected_networks: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
        for cidr in raw_cidrs:
            cidr_clean = cidr.strip()
            if not cidr_clean:
                continue
            try:
                net = ipaddress.ip_network(cidr_clean, strict=False)
                self.protected_networks.append(net)
            except ValueError:
                pass

    def validate_target(self, target: str) -> tuple[bool, str]:
        """
        Validates target IP address using `ipaddress`.
        Returns:
            (is_allowed: bool, reason: str)
            - If allowed: (True, "OK")
            - If denied or invalid: (False, <explanation>)
        """
        cleaned = (target or "").strip().lower()
        if not cleaned:
            return False, "Target address cannot be empty."

        # Parse and validate IP structure
        try:
            ip_obj = ipaddress.ip_address(cleaned)
        except ValueError:
            # Check if it's an explicitly allowed protected non-IP hostname (e.g. localhost)
            if cleaned in self.protected_hosts:
                return False, f"Target '{target}' is in the protected host allowlist."
            return False, f"Malformed IP address: '{target}' is not a valid IPv4 or IPv6 address."

        # Check loopback (e.g. 127.0.0.1, 127.0.0.2, ::1)
        if ip_obj.is_loopback:
            return False, f"Loopback address '{target}' is protected local infrastructure and cannot be contained."

        # Check unspecified / bind-all (e.g. 0.0.0.0, ::)
        if ip_obj.is_unspecified:
            return False, f"Unspecified address '{target}' cannot be a containment target."

        # Check link-local (169.254.0.0/16, fe80::/10)
        if ip_obj.is_link_local:
            return False, f"Link-local address '{target}' is protected host-local networking."

        # Check multicast (224.0.0.0/4, ff00::/8)
        if ip_obj.is_multicast:
            return False, f"Multicast address '{target}' cannot be contained."

        # Check IPv4 broadcast
        if isinstance(ip_obj, ipaddress.IPv4Address) and ip_obj == ipaddress.IPv4Address("255.255.255.255"):
            return False, f"Broadcast address '{target}' cannot be contained."

        # Check configured individual protected IPs
        if ip_obj in self.protected_ip_objects or cleaned in self.protected_hosts:
            return False, f"Target IP '{target}' is a configured protected infrastructure node."

        # Check configured protected enterprise CIDRs
        for net in self.protected_networks:
            if ip_obj in net:
                return False, f"Target IP '{target}' belongs to protected network subnet '{net}'."

        # Legitimate enterprise private (RFC1918) or public IP allowed for containment
        return True, "OK"

    def is_target_allowed(self, target: str) -> bool:
        """
        Boolean facade for backward-compatibility with existing API controllers.
        Returns False if the target is protected or malformed.
        Returns True if the target is valid for containment.
        """
        allowed, _ = self.validate_target(target)
        return allowed

    def execute_action(
        self, db: Session, response_action: ResponseAction, admin_user: str
    ) -> ResponseAction:
        """
        Executes a proposed response action after safety allowlist validation.
        """
        target = response_action.target.strip()
        allowed, reason = self.validate_target(target)
        if not allowed:
            raise ValueError(f"Safety Violation: {reason}")

        now = datetime.now(timezone.utc)
        response_action.approved_by = admin_user
        response_action.executed_at = now
        response_action.is_active = True
        response_action.status = "EXECUTED"

        if response_action.action_type == "BLOCK_IP":
            response_action.execution_output = (
                f"Active firewall drop rule applied for {target}. "
                f"Ingress telemetry from {target} will be rejected (HTTP 403)."
            )
        elif response_action.action_type == "RATE_LIMIT":
            response_action.execution_output = (
                f"Throughput rate-limiter applied for {target}. "
                f"Ingress throttled to 10 req/min."
            )
        else:
            response_action.execution_output = (
                f"Defensive containment rule '{response_action.action_type}' active for {target}."
            )

        db.commit()
        db.refresh(response_action)
        return response_action

    def rollback_action(
        self, db: Session, response_action: ResponseAction, admin_user: str
    ) -> ResponseAction:
        """
        Rolls back / deactivates an active response action.
        """
        now = datetime.now(timezone.utc)
        response_action.is_active = False
        response_action.status = "ROLLED_BACK"

        note = f" | [ROLLED BACK by {admin_user} at {now.isoformat()}]"
        response_action.execution_output = (response_action.execution_output or "") + note

        db.commit()
        db.refresh(response_action)
        return response_action

    def is_ip_blocked(self, db: Session, ip: str) -> bool:
        """
        Queries active firewall block rules for an IP.
        Normalizes IP representation for consistent lookup.
        """
        if not ip:
            return False
        cleaned = ip.strip()

        # Direct match first
        active_block = (
            db.query(ResponseAction)
            .filter(
                ResponseAction.target == cleaned,
                ResponseAction.action_type == "BLOCK_IP",
                ResponseAction.status == "EXECUTED",
                ResponseAction.is_active == True,
            )
            .first()
        )
        if active_block is not None:
            return True

        # Normalized IP comparison if valid IP
        try:
            target_obj = ipaddress.ip_address(cleaned)
            all_blocks = (
                db.query(ResponseAction)
                .filter(
                    ResponseAction.action_type == "BLOCK_IP",
                    ResponseAction.status == "EXECUTED",
                    ResponseAction.is_active == True,
                )
                .all()
            )
            for blk in all_blocks:
                try:
                    if ipaddress.ip_address(blk.target.strip()) == target_obj:
                        return True
                except ValueError:
                    continue
        except ValueError:
            pass

        return False


# Global singleton
response_engine = ResponseEngine()
