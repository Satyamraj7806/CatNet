"""Run an Nmap port scan and turn its XML into structured, readable results."""

import re
import subprocess
import time
import xml.etree.ElementTree as ET
from threading import Lock

_PROGRESS_LOCK = Lock()


def _format_duration(seconds):
    seconds = max(0, int(seconds))
    minutes, seconds = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    return f"{minutes:02d}:{seconds:02d}"


def _show_progress(ip, line, started_at, inline_progress, last_update):
    """Render Nmap's periodic progress status without mixing parallel scans."""
    elapsed = time.monotonic() - started_at
    match = re.search(r"About\s+(\d+(?:\.\d+)?)%\s+done", line, re.IGNORECASE)
    percent = float(match.group(1)) if match else None

    if percent is not None:
        # Limit updates for multi-host scans, which may have several Nmap jobs running.
        if not inline_progress and elapsed - last_update[0] < 3 and percent < 100:
            return
        width = 24
        filled = int(width * min(100.0, max(0.0, percent)) / 100.0)
        bar = "#" * filled + "-" * (width - filled)
        message = f"[{ip}] [{bar}] {percent:5.1f}% | elapsed {_format_duration(elapsed)}"
    elif "elapsed" in line.lower():
        if elapsed - last_update[0] < 3:
            return
        message = f"[{ip}] Nmap is scanning... elapsed {_format_duration(elapsed)}"
    else:
        return

    with _PROGRESS_LOCK:
        if inline_progress:
            print("\r" + message.ljust(115), end="", flush=True)
        else:
            print(f"  {message}", flush=True)
    last_update[0] = elapsed


def _empty_result(ip, error, xml_file=None, elapsed=0.0):
    return {
        "target": ip,
        "ports": [],
        "port_summary": {"open": 0, "closed": 0, "filtered": 0, "other": 0},
        "host_info": {},
        "error": error,
        "stage": "port_scan",
        "xml_file": xml_file,
        "elapsed_seconds": elapsed,
    }



_DATABASE_SERVICES = {
    "mysql": "MySQL / MariaDB database",
    "mariadb": "MariaDB database",
    "postgresql": "PostgreSQL database",
    "postgres": "PostgreSQL database",
    "pgsql": "PostgreSQL database",
    "ms-sql-s": "Microsoft SQL Server database",
    "mssql": "Microsoft SQL Server database",
    "oracle-tns": "Oracle database listener",
    "mongodb": "MongoDB document database",
    "redis": "Redis key-value store",
    "memcached": "Memcached cache service",
    "cassandra": "Apache Cassandra database",
    "couchdb": "Apache CouchDB database",
    "elasticsearch": "Elasticsearch search/database API",
    "ibm-db2": "IBM Db2 database",
    "informix": "IBM Informix database",
    "neo4j": "Neo4j graph database",
}

_DATABASE_PORTS = {
    1433: "Possible Microsoft SQL Server database",
    1521: "Possible Oracle database listener",
    2483: "Possible Oracle database listener",
    2484: "Possible Oracle database listener (TLS)",
    3306: "Possible MySQL / MariaDB database",
    5432: "Possible PostgreSQL database",
    5984: "Possible CouchDB database/API",
    6379: "Possible Redis key-value store",
    9042: "Possible Cassandra database",
    9200: "Possible Elasticsearch API",
    9300: "Possible Elasticsearch transport",
    11211: "Possible Memcached cache service",
    27017: "Possible MongoDB database",
}

_WEB_PORTS = {80, 81, 443, 3000, 5000, 5001, 7001, 7002, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9090, 9443}


def _classify_application(port_number, protocol, service_data, scripts):
    """Classify a service conservatively and state what evidence supports it."""
    service = (service_data.get("name") or "").lower()
    product = (service_data.get("product") or "").lower()
    extra = (service_data.get("extrainfo") or "").lower()
    service_text = f"{service} {product} {extra}"
    script_ids = {item.get("id", "").lower() for item in scripts}
    script_text = " ".join(
        f"{item.get('id', '')} {item.get('output', '')}".lower() for item in scripts
    )
    try:
        number = int(port_number)
    except (TypeError, ValueError):
        number = -1

    role = None
    strong_evidence = bool(
        service_data.get("method") == "probed"
        or service_data.get("product")
        or script_ids.intersection({"http-title", "http-server-header", "mysql-info", "ms-sql-info", "pgsql-info", "redis-info", "mongodb-info", "smb-os-discovery"})
    )

    # More specific product families should win before generic HTTP/database terms.
    if any(token in service_text for token in ("tomcat", "jetty", "wildfly", "jboss", "weblogic", "websphere", "glassfish", "gunicorn", "uwsgi", "php-fpm")):
        role = "Web application server / application runtime"
    elif any(token in service_text for token in ("mysql", "mariadb", "postgres", "pgsql", "ms-sql", "mssql", "oracle-tns", "mongodb", "redis", "memcached", "cassandra", "couchdb", "elasticsearch", "ibm-db2", "informix", "neo4j", "sybase")):
        for token, description in _DATABASE_SERVICES.items():
            if token in service_text:
                role = description
                break
        if role is None and any(token in service_text for token in ("ms-sql", "mssql", "tds")):
            role = "Microsoft SQL Server database"
        if role is None:
            role = "Database / data service"
    elif "docker" in service_text or number in {2375, 2376}:
        role = "Possible Docker remote API"
    elif "kubernetes" in service_text or number == 6443:
        role = "Possible Kubernetes API / control plane"
    elif service in {"http", "https", "http-proxy", "http-alt", "httpapi", "http-mgmt", "ssl/http"} or "http-title" in script_ids or "http-server-header" in script_ids or "http/" in script_text:
        if any(token in service_text for token in ("apache httpd", "nginx", "caddy", "lighttpd", "microsoft httpapi", "microsoft-iis", "iis")):
            role = "Web server / HTTP application"
        else:
            role = "Web service / HTTP application"
    elif any(token in service_text for token in ("ssh", "openssh")) or service == "ssh":
        role = "Remote administration (SSH)"
    elif any(token in service_text for token in ("rdp", "ms-wbt-server", "vnc")) or number in {3389, 5900, 5901}:
        role = "Remote desktop service"
    elif any(token in service_text for token in ("smb", "microsoft-ds", "netbios-ssn", "samba")) or number in {139, 445}:
        role = "Windows/Samba file sharing (SMB)"
    elif any(token in service_text for token in ("ftp", "tftp")) or number in {21, 69}:
        role = "File transfer service (FTP/TFTP)"
    elif any(token in service_text for token in ("smtp", "submission", "pop3", "imap")) or number in {25, 110, 143, 465, 587, 993, 995}:
        role = "Email service"
    elif service in {"domain", "dns", "dns-udp"} or number == 53:
        role = "DNS / name-resolution service"
    elif any(token in service_text for token in ("ldap", "ldaps")) or number in {389, 636}:
        role = "Directory service (LDAP)"
    elif any(token in service_text for token in ("nfs", "mountd", "rpcbind", "portmapper")) or number in {111, 2049}:
        role = "Network file system / RPC service"
    elif any(token in service_text for token in ("snmp",)) or number in {161, 162}:
        role = "Network monitoring / management (SNMP)"
    elif any(token in service_text for token in ("mqtt",)) or number in {1883, 8883}:
        role = "IoT messaging broker (MQTT)"
    elif any(token in service_text for token in ("amqp", "rabbitmq")) or number in {5672, 5671}:
        role = "Message queue / broker (AMQP)"
    elif any(token in service_text for token in ("proxy", "socks")) or number in {1080, 3128, 8080, 8888}:
        role = "Proxy service (possible)"
    elif number in _DATABASE_PORTS:
        role = _DATABASE_PORTS[number]
    elif number in _WEB_PORTS:
        role = "Possible web server / web application (port-based)"
    else:
        role = "Other / not yet classified network service"

    if strong_evidence:
        confidence = "Nmap identified service"
        basis = "Nmap service probe/product fingerprint or script evidence"
    else:
        confidence = "Possible role"
        basis = "service-name/port mapping only; verify before treating as confirmed"

    return role, confidence, basis


def _read_scripts(parent):
    """Read script outputs attached to a host or port in Nmap XML."""
    results = []
    if parent is None:
        return results
    for script_elem in parent.findall("script"):
        script_id = script_elem.get("id", "script")
        output = (script_elem.get("output") or "").strip()
        if output:
            results.append({"id": script_id, "output": output})
    return results

def port_scan(host, output_base, profile, inline_progress=True):
    """Scan one host, show live progress, and parse Nmap's XML report.

    inline_progress should be True for a single target. For a network scan,
    progress updates use separate lines so concurrent Nmap jobs do not overwrite
    one another in the terminal.
    """
    ip = host["target"]
    safe_ip = ip.replace(":", "_")
    xml_file = f"{output_base}_{safe_ip}.xml"
    label = profile.get("name", "Nmap scan")

    print(f"\n[+] Starting {label} on {ip}")
    # Service/version detection is needed to distinguish a product from a
    # port-number guess. Quick mode uses lighter probes; Deep already enables
    # service/version detection through -A. Preserve the Stealth profile's intent.
    profile_args = list(profile.get("nmap_args", []))
    is_stealth = "stealth" in label.lower()
    if not is_stealth and "-sV" not in profile_args and "-A" not in profile_args:
        profile_args.append("-sV")
        if "quick" in label.lower():
            profile_args.append("--version-light")

    # Preserve Nmap's default scripts and add a small service-identification set.
    # Do not activate extra NSE probing in the profile explicitly named Stealth.
    service_scripts = (
        "default,redis-info,memcached-info,cassandra-info,http-headers,"
        "ssl-cert,smb-protocols"
    )
    command = ["nmap"] + profile_args
    if not is_stealth:
        command += ["--script", service_scripts]
    command += ["--stats-every", "1s", "-oX", xml_file, ip]

    started_at = time.monotonic()
    stderr_lines = []
    last_update = [-999.0]
    process = None

    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        if process.stderr is not None:
            for line in process.stderr:
                cleaned = line.strip()
                if cleaned:
                    stderr_lines.append(cleaned)
                    # Keep memory bounded if Nmap emits a lot of diagnostics.
                    if len(stderr_lines) > 100:
                        del stderr_lines[:50]
                _show_progress(ip, line, started_at, inline_progress, last_update)
        return_code = process.wait()
    except FileNotFoundError:
        if inline_progress:
            print()
        return _empty_result(ip, "Nmap executable was not found. Install Nmap or check PATH.", xml_file)
    except KeyboardInterrupt:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        if inline_progress:
            print()
        raise
    finally:
        if process is not None and process.stderr is not None:
            process.stderr.close()

    elapsed = time.monotonic() - started_at
    if inline_progress:
        print()

    if return_code != 0:
        errors = [line for line in stderr_lines if "error" in line.lower() or "failed" in line.lower()]
        detail = errors[-1] if errors else f"Nmap exited with status {return_code}."
        print(f"[ERROR] Scan failed for {ip}: {detail}")
        return _empty_result(ip, detail, xml_file, elapsed)

    try:
        root = ET.parse(xml_file).getroot()
    except FileNotFoundError:
        return _empty_result(ip, f"Nmap completed but its XML report was not found: {xml_file}", xml_file, elapsed)
    except ET.ParseError as exc:
        return _empty_result(ip, f"Nmap produced unreadable XML: {exc}", xml_file, elapsed)
    except OSError as exc:
        return _empty_result(ip, f"Could not read Nmap XML: {exc}", xml_file, elapsed)

    host_elem = root.find("host")
    if host_elem is None:
        return _empty_result(ip, "Nmap XML contains no host result.", xml_file, elapsed)

    status_elem = host_elem.find("status")
    status = status_elem.get("state", "unknown") if status_elem is not None else "unknown"

    hostnames = []
    for hostname_elem in host_elem.findall("hostnames/hostname"):
        hostname = hostname_elem.get("name")
        if hostname and hostname not in hostnames:
            hostnames.append(hostname)

    mac_elem = next(
        (addr for addr in host_elem.findall("address") if addr.get("addrtype") == "mac"),
        None,
    )
    mac = mac_elem.get("addr") if mac_elem is not None else None
    mac_vendor = mac_elem.get("vendor") if mac_elem is not None else None

    os_matches = []
    os_elem = host_elem.find("os")
    if os_elem is not None:
        for match_elem in os_elem.findall("osmatch")[:3]:
            match = {
                "name": match_elem.get("name", "Unknown OS"),
                "accuracy": match_elem.get("accuracy", "?"),
                "classes": [],
            }
            for class_elem in match_elem.findall("osclass"):
                os_class = {
                    "vendor": class_elem.get("vendor"),
                    "family": class_elem.get("osfamily"),
                    "generation": class_elem.get("osgen"),
                    "type": class_elem.get("type"),
                    "accuracy": class_elem.get("accuracy"),
                }
                match["classes"].append(os_class)
            os_matches.append(match)

    uptime_elem = host_elem.find("uptime")
    uptime = None
    if uptime_elem is not None:
        uptime = {
            "seconds": uptime_elem.get("seconds"),
            "lastboot": uptime_elem.get("lastboot"),
        }

    distance_elem = host_elem.find("distance")
    distance = distance_elem.get("value") if distance_elem is not None else None

    ports = []
    summary = {"open": 0, "closed": 0, "filtered": 0, "other": 0}
    ports_elem = host_elem.find("ports")
    if ports_elem is not None:
        for port_elem in ports_elem.findall("port"):
            state_elem = port_elem.find("state")
            port_state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"
            summary[port_state if port_state in summary else "other"] += 1
            if port_state != "open":
                continue

            service_elem = port_elem.find("service")
            service_data = {}
            if service_elem is not None:
                for field in ("name", "product", "version", "extrainfo", "tunnel", "method", "conf", "ostype"):
                    service_data[field] = service_elem.get(field, "")
            else:
                service_data = {field: "" for field in ("name", "product", "version", "extrainfo", "tunnel", "method", "conf", "ostype")}

            script_results = _read_scripts(port_elem)
            port_number = port_elem.get("portid", "?")
            service_role, role_confidence, role_basis = _classify_application(
                port_number, port_elem.get("protocol", "tcp"), service_data, script_results
            )
            cpes = [item.text.strip() for item in (service_elem.findall("cpe") if service_elem is not None else []) if item.text and item.text.strip()]
            ports.append({
                "port": port_number,
                "protocol": port_elem.get("protocol", "tcp"),
                "state": port_state,
                "reason": state_elem.get("reason", "") if state_elem is not None else "",
                "service": service_data.get("name") or "unknown",
                "product": service_data.get("product", ""),
                "version": service_data.get("version", ""),
                "extrainfo": service_data.get("extrainfo", ""),
                "tunnel": service_data.get("tunnel", ""),
                "method": service_data.get("method", ""),
                "confidence": service_data.get("conf", ""),
                "service_os": service_data.get("ostype", ""),
                "cpe": cpes,
                "scripts": script_results,
                "application_role": service_role,
                "role_confidence": role_confidence,
                "role_basis": role_basis,
            })

        # Nmap groups large sets of closed/filtered ports in extraports elements.
        for extra_elem in ports_elem.findall("extraports"):
            extra_state = extra_elem.get("state", "other")
            try:
                extra_count = int(extra_elem.get("count", "0"))
            except ValueError:
                extra_count = 0
            summary[extra_state if extra_state in summary else "other"] += extra_count

    finished_elem = root.find("runstats/finished")
    nmap_elapsed = None
    if finished_elem is not None:
        try:
            nmap_elapsed = float(finished_elem.get("elapsed", ""))
        except (TypeError, ValueError):
            pass

    hosts_elem = root.find("runstats/hosts")
    host_info = {
        "status": status,
        "hostnames": hostnames,
        "mac": mac,
        "mac_vendor": mac_vendor,
        "os_matches": os_matches,
        "uptime": uptime,
        "distance": distance,
        "scripts": _read_scripts(host_elem.find("hostscript")),
        "hosts_up": hosts_elem.get("up") if hosts_elem is not None else None,
        "hosts_total": hosts_elem.get("total") if hosts_elem is not None else None,
    }

    total_elapsed = nmap_elapsed if nmap_elapsed is not None else elapsed
    print(f"[✓] Nmap finished for {ip} in {_format_duration(total_elapsed)}.")

    return {
        "target": ip,
        "ports": ports,
        "port_summary": summary,
        "host_info": host_info,
        "error": None,
        "stage": "port_scan",
        "xml_file": xml_file,
        "elapsed_seconds": total_elapsed,
    }
