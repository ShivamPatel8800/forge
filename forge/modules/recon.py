import xml.etree.ElementTree as ET

from ..core.engine import register
from ..core.state import Host

AD_PORTS = "53,88,135,139,389,445,464,636,3268,3269,5985,5986,9389"


@register("recon")
class ReconPhase:
    def __init__(self, ctx):
        self.ctx = ctx

    def run(self):
        t = self.ctx.cfg.target
        r = self.ctx.ex.run(
            f"nmap -Pn -sV -p {AD_PORTS} -oX {self.ctx.ex.rawdir}/nmap.xml {t.range or t.dc_ip}",
            name="nmap", timeout=1800)
        if r.ok or (self.ctx.ex.rawdir / "nmap.xml").exists():
            self._parse_nmap()

    def _parse_nmap(self):
        tree = ET.parse(self.ctx.ex.rawdir / "nmap.xml")
        for h in tree.findall(".//host"):
            ip_el = h.find("address")
            if ip_el is None:
                continue
            ip = ip_el.get("addr")
            ports = {}
            for p in h.findall("ports/port"):
                if p.find("state").get("state") == "open":
                    ports[p.get("portid")] = p.find("service").get("name", "")
            if not ports:
                continue
            roles = []
            if "88" in ports and "389" in ports:
                roles.append("dc")
            self.ctx.state.hosts.append(Host(ip=ip, roles=roles, ports=ports))
        dcs = [h.ip for h in self.ctx.state.hosts if "dc" in h.roles]
        self.ctx.state.facts["domain_controllers"] = dcs
        self.ctx.state.facts["live_hosts"] = [h.ip for h in self.ctx.state.hosts]
