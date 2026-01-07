#!/usr/bin/env python3

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

def parse_args():
    p = argparse.ArgumentParser(description="Simple Nmap scanner (python3). Use responsibly.")
    p.add_argument("--target", "-t", required=True, help="Target host / network (e.g. 192.168.1.1 or 192.168.1.0/24 or example.com)")
    p.add_argument("--ports", "-p", default=None, help="Ports to scan (e.g. 22,80,443 or 1-1024). If omitted, nmap defaults apply.")
    p.add_argument("--scan-args", "-s", default="-sS -T4 -Pn", help="Extra nmap args. Default: '-sS -T4 -Pn' (TCP SYN, faster, no host discovery). Adjust as needed.")
    p.add_argument("--save-xml", default=None, help="Save raw nmap XML output to file")
    p.add_argument("--save-json", default=None, help="Save parsed JSON results to file")
    p.add_argument("--timeout", type=int, default=0, help="Timeout in seconds for nmap subprocess (0 = no timeout)")
    return p.parse_args()

def try_python_nmap_scan(target, ports, scan_args):
    try:
        import nmap  
    except Exception as e:
        return None  

    scanner = nmap.PortScanner()
    nm_args = scan_args or ""
    port_arg = ports if ports else None

    try:
        if port_arg:
            scanner.scan(hosts=target, ports=port_arg, arguments=nm_args)
        else:
            scanner.scan(hosts=target, arguments=nm_args)
    except Exception as e:
        raise RuntimeError(f"python-nmap scan failed: {e}")

    #structured dict from PortScanner results(my dumb ahh will forget shii)
    results = {"scanned_targets": target, "scan_args": nm_args, "hosts": []}
    for host in scanner.all_hosts():
        host_entry = {
            "ip": host,
            "hostname": scanner[host].hostname() if scanner[host].hostname() else None,
            "state": scanner[host].state(),
            "protocols": {}
        }
        for proto in scanner[host].all_protocols():
            ports_list = []
            for port in sorted(scanner[host][proto].keys()):
                pinfo = scanner[host][proto][port]
                ports_list.append({
                    "port": port,
                    "state": pinfo.get("state"),
                    "reason": pinfo.get("reason"),
                    "name": pinfo.get("name"),
                    "product": pinfo.get("product"),
                    "version": pinfo.get("version"),
                    "extrainfo": pinfo.get("extrainfo"),
                })
            host_entry["protocols"][proto] = ports_list
        results["hosts"].append(host_entry)
    return results

def run_nmap_subprocess(target, ports, scan_args, timeout=0):
    if not shutil.which("nmap"):
        raise FileNotFoundError("nmap binary not found on PATH. Install nmap or install python-nmap package.")
    args = ["nmap"]
    if scan_args:
        args += scan_args.split()
    if ports:
        args += ["-p", ports]
    # request XML output to a temp file for parsing
    with tempfile.NamedTemporaryFile(prefix="nmap_", suffix=".xml", delete=False) as tmp:
        xml_path = tmp.name
    args += ["-oX", xml_path, target]
    try:
        proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=(timeout if timeout>0 else None))
    except subprocess.TimeoutExpired:
        raise TimeoutError("nmap subprocess timed out.")
    if proc.returncode != 0:
        err = proc.stderr.decode(errors="ignore")
        raise RuntimeError(f"nmap subprocess failed (return code {proc.returncode}): {err}")
    parsed = parse_nmap_xml(xml_path)
    return parsed, xml_path

def parse_nmap_xml(xml_file_path):
    tree = ET.parse(xml_file_path)
    root = tree.getroot()
    ns = ""  
    results = {"hosts": []}
    for host in root.findall("host"):
        status_elem = host.find("status")
        state = status_elem.get("state") if status_elem is not None else None

        addr_elem = host.find("address")
        ip = addr_elem.get("addr") if addr_elem is not None else None

        hostnames = []
        hn_parent = host.find("hostnames")
        if hn_parent is not None:
            for hn in hn_parent.findall("hostname"):
                hostnames.append(hn.get("name"))

        proto_map = {}
        ports_parent = host.find("ports")
        if ports_parent is not None:
            for port_el in ports_parent.findall("port"):
                pnum = int(port_el.get("portid"))
                proto = port_el.get("protocol")
                state_el = port_el.find("state")
                state_p = state_el.get("state") if state_el is not None else None
                svc_el = port_el.find("service")
                svc = {
                    "name": svc_el.get("name") if svc_el is not None else None,
                    "product": svc_el.get("product") if svc_el is not None else None,
                    "version": svc_el.get("version") if svc_el is not None else None,
                    "extrainfo": svc_el.get("extrainfo") if svc_el is not None else None,
                }
                proto_map.setdefault(proto, []).append({
                    "port": pnum,
                    "state": state_p,
                    "service": svc
                })
        host_entry = {
            "ip": ip,
            "hostnames": hostnames,
            "state": state,
            "protocols": proto_map
        }
        results["hosts"].append(host_entry)
    return results

def print_results(results):
    hosts = results.get("hosts", [])
    if not hosts:
        print("No hosts found in results.")
        return
    for h in hosts:
        ip = h.get("ip")
        hostname = (h.get("hostname") or (h.get("hostnames")[0] if h.get("hostnames") else None))
        state = h.get("state")
        print(f"\nHost: {ip}  {('('+hostname+')') if hostname else ''}  State: {state}")
        protocols = h.get("protocols", {})
        if not protocols:
            print("  No ports/protocols found.")
            continue
        for proto, ports in protocols.items():
            print(f"  Protocol: {proto}")
            for p in sorted(ports, key=lambda x: x.get("port")):
                portnum = p.get("port")
                pstate = p.get("state")
                svc = p.get("service") if "service" in p else p.get("name") or {}
                svcname = svc.get("name") if isinstance(svc, dict) else svc
                svcprod = svc.get("product") if isinstance(svc, dict) else None
                svcver = svc.get("version") if isinstance(svc, dict) else None
                extras = []
                if svcname:
                    extras.append(svcname)
                if svcprod:
                    extras.append(svcprod)
                if svcver:
                    extras.append(svcver)
                extras_str = (" — " + " / ".join(filter(None, extras))) if extras else ""
                print(f"    {portnum}/{proto} : {pstate}{extras_str}")

def main():
    args = parse_args()

    print("==== nmap_scanner ====")
    print("Target:", args.target)
    if args.ports:
        print("Ports:", args.ports)
    print("Scan args:", args.scan_args)
    print("Note: run only on networks you are authorized to scan.\n")

    json_results = None
    xml_path = None
    try:
        res = try_python_nmap_scan(args.target, args.ports, args.scan_args)
        if res is not None:
            print("Used python-nmap (PortScanner) for scanning.")
            json_results = res
        else:
            print("python-nmap not available. Falling back to calling nmap binary.")
            parsed, xml_path = run_nmap_subprocess(args.target, args.ports, args.scan_args, timeout=args.timeout)
            json_results = parsed
            # Attach xml path into results so user can save or inspect
            if xml_path:
                json_results["_xml_file"] = xml_path
    except Exception as e:
        print("Error during scan:", e)
        sys.exit(1)

    print_results(json_results)

    if args.save_xml and xml_path:
        try:
            shutil.copy(xml_path, args.save_xml)
            print(f"\nSaved XML output to: {args.save_xml}")
        except Exception as e:
            print(f"Failed to save XML: {e}")

    if args.save_json:
        try:
            with open(args.save_json, "w", encoding="utf-8") as f:
                json.dump(json_results, f, indent=2)
            print(f"Saved JSON parsed output to: {args.save_json}")
        except Exception as e:
            print(f"Failed to save JSON: {e}")

if __name__ == "__main__":
    main()
