import ipaddress


class SafetySwitch:
    def __init__(self, allowed_cidrs: list[str]):
        if not allowed_cidrs:
            raise ValueError("At least one allowed CIDR must be specified")
        self._networks = [
            ipaddress.ip_network(cidr.strip(), strict=False)
            for cidr in allowed_cidrs
        ]

    def validate(self, target: str) -> bool:
        try:
            ip = ipaddress.ip_address(target)
            return any(ip in network for network in self._networks)
        except ValueError:
            return False

    def assert_target_allowed(self, target: str) -> str:
        if not self.validate(target):
            allowed = ", ".join(str(n) for n in self._networks)
            raise PermissionError(
                f"Target {target} is not in allowed range(s): {allowed}"
            )
        return target

    def get_allowed_ranges(self) -> list[str]:
        return [str(n) for n in self._networks]
