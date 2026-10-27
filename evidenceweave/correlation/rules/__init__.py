"""Rules run in this order; each is run(events, cfg, hosts, prior_findings) -> list[Finding]."""
from . import brute_force, initial_access, lateral_movement, persistence, privilege_escalation, web_recon

# lateral_movement runs before persistence so persistence skips task events lateral movement already explains
RULES = (brute_force, initial_access, privilege_escalation, lateral_movement, persistence, web_recon)
