#!/usr/bin/env python3
from argparse import ArgumentParser
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from typing import Set, Dict
import json
import os
import subprocess
import sys
import tarfile


def main():
    if not Path("ca.crt").is_file:
        initial_setup()

    args = ArgumentParser()
    args.add_argument("host", help="Name of host")
    args.add_argument(
        "-i", "--ip", help="Try to force ip address", default=None, type=IPv4Address
    )
    args.add_argument("-g", "--groups", help="Additional groups")
    args = args.parse_args()

    settings_path = "settings.json"
    with open(settings_path) as fh:
        settings = Settings.from_json_obj(json.load(fh))

    fqdn = f"{args.host}.{settings.domain}"
    ip = args.ip
    assert args.ip not in settings.used_ips, "ip already assigned"
    assert fqdn not in settings.assignments, "fqdn already assigned"

    # NOTE: pythons funny scoping makes this actually work
    if ip is None:
        # this is terrible but at least it doesn't leave holes
        for ip in settings.network.hosts():
            if ip not in settings.used_ips:
                break

    assert ip is not None, "Ran out of assignable ip addresses"
    assert ip in settings.network, "ip outside of network"

    nebula_args = [
        "-name",
        fqdn,
        "-ip",
        f"{ip}/{settings.network.prefixlen}",
    ]
    if args.groups is not None:
        nebula_args += ["-groups", args.groups]
    run_nebula_cert("sign", nebula_args)

    settings.add_assignment(fqdn, ip)

    tar_name = "send_me.tar"
    with tarfile.open(tar_name, "w") as tar:
        tar.add(f"{fqdn}.crt", arcname="crt.crt")
        tar.add(f"{fqdn}.key", arcname="key.key")
        tar.add("ca.crt")

    tempsettings_path = "settings.json.tmp"
    with open(tempsettings_path, "w") as fh:
        json.dump(settings.to_json_obj(), fh, indent=4, sort_keys=True)
    os.rename(tempsettings_path, settings_path)

    print(f"Tared to {tar_name}")


def prompt(text: str, type=str):
    while True:
        putput = input(text)
        try:
            return type(putput)
        except Exception as exception:
            print("Invalid input")
            print(exception)


def initial_setup():
    domain_name = prompt("Domain name? (example: nebula.example.com) ")
    network_range = prompt("Network range? (example: 192.168.100.0/24) ", IPv4Network)
    organization = prompt("Name of organization? (example: Evil Company) ")
    run_nebula_cert("ca", ["-name", organization])
    with open("settings.json", "w") as fh:
        settings = Settings(
            domain=domain_name, network=network_range, used_ips=set(), assignments={}
        )
        json.dump(settings.to_json_obj(), fh, indent=4, sort_keys=True)


@dataclass
class Settings:
    network: IPv4Network
    domain: str
    used_ips: Set[IPv4Address]
    assignments: Dict[str, IPv4Address]

    def add_assignment(self, fqdn: str, ip: IPv4Address):
        self.used_ips.add(ip)
        self.assignments[fqdn] = ip

    def to_json_obj(self):
        return {
            "network": str(self.network),
            "domain": self.domain,
            "assignments": {fqdn: str(ip) for fqdn, ip in self.assignments.items()},
        }

    @staticmethod
    def from_json_obj(obj):
        return Settings(
            network=IPv4Network(
                obj["network"],
            ),
            domain=obj["domain"],
            used_ips=set(map(IPv4Address, obj["assignments"].values())),
            assignments={
                fqdn: IPv4Address(ip) for fqdn, ip in obj["assignments"].items()
            },
        )


def run_nebula_cert(subcmd, args):
    try:
        subprocess.run(["nebula-cert", subcmd] + args, check=True)
    except FileNotFoundError:
        sys.exit("nebula-cert is not installed")


if __name__ == "__main__":
    main()
