from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
import json
import os
import subprocess
import socket
import psutil
import hashlib
import ipaddress
import shutil
from datetime import datetime
import threading
import ping3
import telnetlib
from dotenv import load_dotenv
load_dotenv()
import uuid
import subprocess
import platform
import netifaces
from datetime import datetime
from werkzeug.utils import secure_filename



app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-this-in-production')
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Configuration
USERS_FILE = os.environ.get('USERS_FILE', 'users.json')
DOCKER_COMPOSE_FILE = os.environ.get('DOCKER_COMPOSE_FILE', 'docker-compose.yml')
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DOCKER_DIR = os.path.join(PROJECT_ROOT, 'docker')

def _clean_env_path(value, fallback):
    raw = (value or fallback or '').strip()
    return raw.strip('"').strip("'")

COMPOSE_BASE_DIR = _clean_env_path(
    os.environ.get('COMPOSE_BASE_DIR'),
    DEFAULT_DOCKER_DIR
)
HOST = os.environ.get('HOST', '0.0.0.0')
PORT = int(os.environ.get('PORT', 8085))

CERT_PATH = os.environ.get('CERT_PATH', '/var/www/ssl/tst/tst.cert')
KEY_PATH = os.environ.get('KEY_PATH', '/var/www/ssl/tst/tst.key')


MANAGEMENT_DOCKER_PATH = _clean_env_path(
    os.getenv("MANAGEMENT_DOCKER_PATH"),
    os.path.join(DEFAULT_DOCKER_DIR, 'management')
)
MCU_DOCKER_PATH = _clean_env_path(
    os.getenv("MCU_DOCKER_PATH"),
    os.path.join(DEFAULT_DOCKER_DIR, 'mcu')
)

# Encrypted keys (from env)
MANAGEMENT_KEY = os.getenv("MANAGEMENT_KEY", "Not set")
MCU_KEY = os.getenv("MCU_KEY", "Not set")

def load_users():
    try:
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)



@app.route('/')
def index():
    if 'user' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('system_page'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if not username or not password:
            flash('Please enter both username and password!', 'error')
            return render_template('login.html')
        
        users = load_users()
        if username in users and users[username]['password'] == password:
            session['user'] = username
            session['role'] = users[username]['role']
            session.permanent = True
            flash('Login successful!', 'success')
            return redirect(url_for('system_page'))
        else:
            flash('Invalid username or password!', 'error')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'info')
    return redirect(url_for('login'))

@app.route('/debug/session')
def debug_session():
    return jsonify({
        'session_data': dict(session),
        'session_id': session.get('_id', 'No session ID'),
        'user': session.get('user', 'Not logged in')
    })

@app.route('/debug/users')
def debug_users():
    users = load_users()
    return jsonify({
        'users': users,
        'total_users': len(users),
        'admin_exists': 'admin' in users
    })



@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    system_info = get_system_info()
    network_info = get_network_info()   
    
    return render_template('system.html', 
                         system_info=system_info, 
                         network_info=network_info,
                         user=session['user'],
                         role=session['role'])

@app.route('/system')
def system_page():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    system_info = get_system_info()
    network_info = get_network_info()
    return render_template('system.html', system_info=system_info, network_info=network_info)

@app.route('/api/system_info')
def api_system_info():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    return jsonify(get_system_info())

@app.route('/network')
def network_page():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    network_info = get_network_info()
    return render_template('network.html', network_info=network_info)

def get_network_info():
    info = {'interfaces': [], 'routes': [], 'dns': {}, 'default_gateway': None}

    try:
        # Network interfaces and IPs
        for iface, addrs in psutil.net_if_addrs().items():
            if iface == "lo":  # skip loopback
                continue

            ip = next((a.address for a in addrs if a.family == socket.AF_INET), None)
            mask = next((a.netmask for a in addrs if a.family == socket.AF_INET), None)
            mac = next((a.address for a in addrs if a.family == psutil.AF_LINK), None)
            info['interfaces'].append({
                'name': iface,
                'ip': ip,
                'mask': mask,
                'mac': mac
            })

        # Default gateway
        gw_data = netifaces.gateways().get('default', {}).get(netifaces.AF_INET)
        if gw_data:
            info['default_gateway'] = gw_data[0]

        # DNS servers (from /etc/resolv.conf)
        if os.path.exists('/etc/resolv.conf'):
            with open('/etc/resolv.conf') as f:
                dns_lines = [line.strip() for line in f.readlines() if line.startswith('nameserver')]
                info['dns']['servers'] = [line.split()[1] for line in dns_lines]

        # Routing table
        try:
            routes_output = subprocess.check_output(['ip', 'route'], text=True)
            for line in routes_output.strip().splitlines():
                parts = line.split()
                if len(parts) >= 3:
                    info['routes'].append({
                        'destination': parts[0],
                        'via': parts[2] if 'via' in parts else '-'
                    })
        except Exception:
            info['routes'].append({'error': 'Unable to fetch routes'})

    except Exception as e:
        info['error'] = str(e)

    return info


# Global storage for I/O tracking
last_disk_io = None
last_io_time = None

# Global storage for I/O tracking and background metrics
last_disk_io = None
last_io_time = None
cached_system_stats = {
    'read_speed': 0,
    'write_speed': 0,
    'serial_number': 'Unknown'
}

def start_background_monitor():
    """Background thread to sample real-time metrics"""
    import threading, time, psutil, os
    global last_disk_io, last_io_time, cached_system_stats
    
    # One-time Serial Detection
    serial = "Unknown"
    try:
        import subprocess
        # Priority 1: dmidecode (requires sudo, but try the non-interactive check)
        try:
            res = subprocess.check_output(
                ["sudo", "-n", "dmidecode", "-s", "system-serial-number"],
                text=True, stderr=subprocess.DEVNULL
            ).strip()
            if res and res.lower() not in ['not specified', 'unknown', 'to be filled by oem', 'serial number']:
                serial = res
        except:
            pass

        # Priority 2: Sysfs (direct kernel info)
        if (not serial or serial == "Unknown"):
            for path in ['/sys/class/dmi/id/product_serial', '/sys/devices/virtual/dmi/id/product_serial']:
                if os.path.exists(path):
                    with open(path, 'r') as f:
                        val = f.read().strip()
                        if val and val.lower() not in ['not specified', 'unknown', 'to be filled by oem']:
                            serial = val
                            break
        
        # Priority 3: machine-id (always exists on systemd linux)
        if (not serial or serial == "Unknown"):
            for path in ['/etc/machine-id', '/var/lib/dbus/machine-id']:
                if os.path.exists(path):
                    with open(path, 'r') as f:
                        # Use the first 12 chars as a unique identifier
                        serial = "SID-" + f.read().strip()[:12].upper()
                        break
        
        # Priority 4: node name (hostname)
        if not serial or serial == "Unknown":
            import platform
            serial = "SID-" + platform.node().upper()
    except Exception as e:
        # Final emergency fallback
        import platform
        serial = "SID-" + platform.node().upper()
    
    cached_system_stats['serial_number'] = serial

    def monitor():
        global last_disk_io, last_io_time, cached_system_stats
        while True:
            try:
                now = time.time()
                curr_io = psutil.disk_io_counters()
                if last_disk_io and last_io_time:
                    dt = now - last_io_time
                    if dt > 0:
                        cached_system_stats['read_speed'] = round((curr_io.read_bytes - last_disk_io.read_bytes) / dt / 1024, 2)
                        cached_system_stats['write_speed'] = round((curr_io.write_bytes - last_disk_io.write_bytes) / dt / 1024, 2)
                last_disk_io = curr_io
                last_io_time = now
            except:
                pass
            time.sleep(2)

    t = threading.Thread(target=monitor, daemon=True)
    t.start()

# Start the monitor when app loads
start_background_monitor()

def get_system_info():
    """Get comprehensive system information with true active route detection"""
    try:
        import psutil, socket, uuid, subprocess, platform, time, datetime

        def get_real_active_interface():
            """Return the actual interface used for outbound traffic"""
            try:
                # Create a UDP socket to an external IP (no data sent)
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                ip_used = s.getsockname()[0]
                s.close()

                # Match IP to interface
                for iface, addrs in psutil.net_if_addrs().items():
                    for addr in addrs:
                        if addr.family == socket.AF_INET and addr.address == ip_used:
                            mac = next(
                                (a.address for a in addrs if a.family == psutil.AF_LINK),
                                "N/A"
                            )
                            return iface, ip_used, mac
                return "N/A", ip_used, "N/A"
            except Exception:
                return "N/A", "N/A", "N/A"

        # Get actual route-based active interface
        primary_iface, primary_ip, primary_mac = get_real_active_interface()
        # Get netmask via psutil
        try:
            netmask = 'Unavailable'
            if primary_iface in psutil.net_if_addrs():
                for addr in psutil.net_if_addrs()[primary_iface]:
                    if getattr(socket, 'AF_INET', None) == addr.family or str(addr.family) == 'AddressFamily.AF_INET':
                        netmask = addr.netmask
                        break
        except Exception:
            netmask = 'Unavailable'

        # Get gateway
        try:
            gws = netifaces.gateways()
            gateway = gws['default'][netifaces.AF_INET][0] if 'default' in gws and netifaces.AF_INET in gws['default'] else 'Unavailable'
        except Exception:
            gateway = 'Unavailable'

        # Get all interfaces with status
        net_if_stats = psutil.net_if_stats()
        net_if_addrs = psutil.net_if_addrs()
        interfaces = []
        for iface, stats in net_if_stats.items():
            if any(prefix in iface.lower() for prefix in ["eth", "en", "wl", "wifi", "wlan"]):
                ip = "N/A"
                mac = "N/A"
                if iface in net_if_addrs:
                    for addr in net_if_addrs[iface]:
                        if addr.family == socket.AF_INET:
                            ip = addr.address
                        elif getattr(psutil, 'AF_LINK', None) == addr.family or addr.family == psutil.AF_LINK:
                            mac = addr.address
                interfaces.append({
                    'name': iface,
                    'is_up': stats.isup,
                    'ip': ip,
                    'mac': mac
                })

        # Serial number from cache
        serial = cached_system_stats.get('serial_number', 'Unknown')

        # OS info
        os_info = f"{platform.system()} {platform.release()}"
        if platform.system() == "Linux":
            try:
                with open('/etc/os-release', 'r') as f:
                    for line in f:
                        if line.startswith('PRETTY_NAME='):
                            os_info = line.split('=')[1].strip().strip('"')
                            break
            except:
                pass

        # CPU, Memory, Disk, etc.
        cpu_count = psutil.cpu_count()
        cpu_freq_info = psutil.cpu_freq()
        cpu_freq = round(cpu_freq_info.current, 2) if cpu_freq_info and cpu_freq_info.current else 'N/A'
        # Align dashboard CPU usage closer to `top` summary by sampling
        # active CPU time components over a 1-second window.
        cpu_times = psutil.cpu_times_percent(interval=1)
        cpu_percent = round(
            max(
                0.0,
                min(
                    100.0,
                    float(getattr(cpu_times, 'user', 0.0))
                    + float(getattr(cpu_times, 'system', 0.0))
                    + float(getattr(cpu_times, 'nice', 0.0))
                    + float(getattr(cpu_times, 'irq', 0.0))
                    + float(getattr(cpu_times, 'softirq', 0.0))
                    + float(getattr(cpu_times, 'steal', 0.0))
                ),
            ),
            1,
        )
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        boot_time_dt = datetime.datetime.fromtimestamp(psutil.boot_time())
        current_time_dt = datetime.datetime.now()

        # Real-time Disk I/O speed from cache
        read_kb = cached_system_stats.get('read_speed', 0)
        write_kb = cached_system_stats.get('write_speed', 0)

        return {
            'ip': primary_ip,
            'netmask': netmask,
            'gateway': gateway,
            'mac_address': primary_mac,
            'primary_interface': primary_iface,
            'cpu_percent': cpu_percent,
            'cpu_count': cpu_count,
            'cpu_freq': cpu_freq,
            'memory_percent': mem.percent,
            'memory_total': round(mem.total / (1024**3), 2),
            'memory_used': round(mem.used / (1024**3), 2),
            'disk_total': round(disk.total / (1024**3), 2),
            'disk_used': round(disk.used / (1024**3), 2),
            'disk_free': round(disk.free / (1024**3), 2),
            'disk_percent': int(disk.percent),
            'read_speed': round(read_kb, 2),
            'write_speed': round(write_kb, 2),
            'serial_number': serial,
            'os_info': os_info,
            'uptime': time.time() - psutil.boot_time(),
            'boot_time': boot_time_dt.strftime("%Y-%m-%d %H:%M:%S"),
            'current_time': current_time_dt.strftime("%Y-%m-%d %H:%M:%S"),
            'load_avg': os.getloadavg() if hasattr(os, 'getloadavg') else [0, 0, 0],
            'process_count': len(psutil.pids()),
            'network_interfaces': interfaces
        }

    except Exception as e:
        return {'error': str(e)}



@app.route('/api/disk_info')
def api_disk_info():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    partitions = psutil.disk_partitions()
    disks = []

    for part in partitions:
        if part.mountpoint != '/':
            continue  # Only root

        try:
            usage = psutil.disk_usage(part.mountpoint)
            disks.append({
                'mountpoint': part.mountpoint,
                'total': round(usage.total / (1024**3)),   # GB
                'used': round(usage.used / (1024**3)),     # GB
                'free': round(usage.free / (1024**3))      # GB
            })
        except PermissionError:
            continue

    return jsonify({'disks': disks})


def get_network_info():
    """Get network interface information"""
    try:
        interfaces = {}
        stats = psutil.net_if_stats()
        link_family = getattr(psutil, 'AF_LINK', getattr(socket, 'AF_PACKET', None))
        for interface, addrs in psutil.net_if_addrs().items():
            ipv4 = next((a for a in addrs if a.family == socket.AF_INET), None)
            mac = next((a for a in addrs if link_family is not None and a.family == link_family), None)
            iface_stats = stats.get(interface)
            interfaces[interface] = {
                'name': interface,
                'ipv4': ipv4.address if ipv4 else '',
                'netmask': ipv4.netmask if ipv4 else '',
                'mac': mac.address if mac else '',
                'is_up': bool(iface_stats.isup) if iface_stats else False,
                'speed_mbps': getattr(iface_stats, 'speed', 0) if iface_stats else 0,
                'mtu': getattr(iface_stats, 'mtu', 0) if iface_stats else 0,
            }
        # Determine primary interface from routing table
        primary_iface = 'unknown'
        try:
            with open('/proc/net/route') as f:
                for line in f.readlines()[1:]:
                    fields = line.strip().split('\t')
                    if len(fields) >= 11 and fields[1] == '00000000' and int(fields[3], 16) & 2:
                        primary_iface = fields[0]
                        break
        except Exception:
            pass
        return {'interfaces': interfaces, 'primary': primary_iface}
    except Exception as e:
        return {'error': str(e)}

def _resolve_compose_file(path_hint):
    """Return compose file path from either a directory or a file hint."""
    if not path_hint:
        return None
    p = _clean_env_path(path_hint, '')
    if os.path.isfile(p):
        return p
    if os.path.isdir(p):
        for fname in ('docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml'):
            candidate = os.path.join(p, fname)
            if os.path.isfile(candidate):
                return candidate
    return None

def _collect_compose_files():
    """Collect compose files from COMPOSE_BASE_DIR and explicit management/mcu paths."""
    files = []

    # Handle COMPOSE_BASE_DIR as either compose file path or directory of projects.
    base_file = _resolve_compose_file(COMPOSE_BASE_DIR)
    if base_file:
        files.append(base_file)
    elif os.path.isdir(COMPOSE_BASE_DIR):
        for entry in os.listdir(COMPOSE_BASE_DIR):
            entry_path = os.path.join(COMPOSE_BASE_DIR, entry)
            if os.path.isdir(entry_path):
                candidate = _resolve_compose_file(entry_path)
                if candidate:
                    files.append(candidate)

    # Add explicit paths too (deduplicated later).
    for hint in (MANAGEMENT_DOCKER_PATH, MCU_DOCKER_PATH):
        candidate = _resolve_compose_file(hint)
        if candidate:
            files.append(candidate)

    # Dedupe while preserving order.
    seen = set()
    result = []
    for f in files:
        if f not in seen:
            seen.add(f)
            result.append(f)
    return result

def update_docker_compose_env(key, value):
    """Update an env var in all discovered compose files."""
    compose_files = _collect_compose_files()
    if not compose_files:
        return False

    updated_any = False
    for compose_path in compose_files:
        try:
            with open(compose_path, 'r') as f:
                lines = f.readlines()

            updated = False
            env_index = None
            env_indent = "      "

            for i, line in enumerate(lines):
                stripped = line.strip()
                if stripped.startswith(f"- {key}="):
                    leading = line[:len(line) - len(line.lstrip())]
                    lines[i] = f"{leading}- {key}={value}\n"
                    updated = True
                    break
                if env_index is None and stripped.startswith('environment:'):
                    env_index = i
                    env_indent = line[:len(line) - len(line.lstrip())] + "  "

            if not updated and env_index is not None:
                lines.insert(env_index + 1, f"{env_indent}- {key}={value}\n")
                updated = True

            if updated:
                with open(compose_path, 'w') as f:
                    f.writelines(lines)
                updated_any = True
        except Exception as inner_e:
            print(f"Error updating {compose_path}: {inner_e}")

    return updated_any

def restart_docker_container(service=None):
    """
    Restart containers in discovered compose files.
    If requested service is not present in a compose file, restart whole project.
    """
    compose_files = _collect_compose_files()
    if not compose_files:
        return False

    success = True
    for compose_file in compose_files:
        cwd = os.path.dirname(compose_file)
        try:
            if service:
                svc_check = subprocess.run(
                    ['docker', 'compose', '-f', compose_file, 'config', '--services'],
                    capture_output=True, text=True, cwd=cwd, check=False
                )
                services = set((svc_check.stdout or '').split())

                if service in services:
                    cmd = ['docker', 'compose', '-f', compose_file, 'restart', service]
                else:
                    # Service alias doesn't exist in this compose; restart project safely.
                    cmd = ['docker', 'compose', '-f', compose_file, 'restart']
            else:
                cmd = ['docker', 'compose', '-f', compose_file, 'restart']

            subprocess.run(cmd, check=True, cwd=cwd)
        except subprocess.CalledProcessError as e:
            print(f"Error restarting compose at {compose_file}: {e}")
            success = False

    return success




@app.route('/api/network_info')
def api_network_info():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    return jsonify(get_network_info())

@app.route('/api/network_config', methods=['POST'])
def api_network_config():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    config = request.json
    try:
        os.makedirs('logs', exist_ok=True)
        with open(os.path.join('logs', 'network_last_config.json'), 'w') as f:
            json.dump({
                'mode': config.get('mode'),
                'ip_address': config.get('ip_address'),
                'netmask': config.get('netmask'),
                'gateway': config.get('gateway'),
                'dns_servers': config.get('dns_servers'),
                'dns_config': config.get('dns_config', {}),
                'routes': config.get('routes', []),
                'timestamp': datetime.now().isoformat()
            }, f, indent=2)

        mode = (config.get('mode') or 'manual').strip().lower()
        ip_address = (config.get('ip_address') or '').strip()
        netmask = (config.get('netmask') or '').strip()
        gateway = (config.get('gateway') or '').strip()

        if shutil.which('nmcli') is None:
            return jsonify({
                'status': 'error',
                'message': 'Network apply failed: nmcli is not available on this system.'
            }), 400

        # Determine active interface from current system info.
        system_info = get_system_info()
        iface = (system_info.get('primary_interface') or '').strip()
        if not iface or iface == 'N/A':
            return jsonify({
                'status': 'error',
                'message': 'Network apply failed: could not determine active network interface.'
            }), 400

        # Find active connection profile bound to this interface.
        con_name = None
        con_cmd = subprocess.run(
            ['nmcli', '-t', '-f', 'NAME,DEVICE', 'connection', 'show', '--active'],
            capture_output=True, text=True, check=False
        )
        for line in (con_cmd.stdout or '').splitlines():
            if ':' not in line:
                continue
            name, device = line.split(':', 1)
            if device.strip() == iface:
                con_name = name.strip()
                break

        if not con_name:
            con_name = iface

        def run_nmcli(args):
            result = subprocess.run(
                ['sudo', '-n', 'nmcli'] + args,
                capture_output=True,
                text=True,
                check=False
            )
            if result.returncode != 0:
                stderr = (result.stderr or '').strip()
                stdout = (result.stdout or '').strip()
                detail = stderr or stdout or 'Unknown nmcli error'
                raise RuntimeError(detail)

        if mode == 'manual':
            if not ip_address or not netmask or not gateway:
                return jsonify({
                    'status': 'error',
                    'message': 'Manual mode requires IP address, netmask, and gateway.'
                }), 400

            try:
                ipaddress.IPv4Address(ip_address)
                ipaddress.IPv4Address(gateway)
                prefix_len = ipaddress.IPv4Network(f"0.0.0.0/{netmask}").prefixlen
            except Exception:
                return jsonify({
                    'status': 'error',
                    'message': 'Invalid network input. Please enter valid IPv4 IP, netmask, and gateway.'
                }), 400

            cidr = f'{ip_address}/{prefix_len}'
            run_nmcli(['connection', 'modify', con_name, 'ipv4.method', 'manual'])
            run_nmcli(['connection', 'modify', con_name, 'ipv4.addresses', cidr])
            run_nmcli(['connection', 'modify', con_name, 'ipv4.gateway', gateway])
            run_nmcli(['connection', 'up', con_name])

        elif mode == 'dhcp':
            run_nmcli(['connection', 'modify', con_name, 'ipv4.method', 'auto'])
            run_nmcli(['connection', 'modify', con_name, '-ipv4.addresses'])
            run_nmcli(['connection', 'modify', con_name, '-ipv4.gateway'])
            run_nmcli(['connection', 'up', con_name])

        elif mode == 'disable':
            run_nmcli(['device', 'disconnect', iface])
        else:
            return jsonify({'status': 'error', 'message': f'Unsupported network mode: {mode}'}), 400

        return jsonify({
            'status': 'success',
            'message': f'Network configuration applied successfully in {mode} mode on {iface}.',
            'dns_status': 'pending'
        })
    except Exception as e:
        err = str(e)
        if 'sudo' in err.lower() or 'a password is required' in err.lower():
            err = 'Permission denied. Please allow passwordless sudo for required network commands.'
        return jsonify({'status': 'error', 'message': f'Network apply failed: {err}'})


""""
@app.route('/dns')
def dns_page():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    return render_template('network.html')

@app.route('/api/dns_config', methods=['POST'])
def api_dns_config():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    config = request.json
    hostname = config.get('hostname')
    name_server = config.get('name_server')
    secondary_name_server = config.get('secondary_name_server')
    domain_suffix = config.get('domain_suffix')
    try:
        # Persist requested DNS settings
        os.makedirs('logs', exist_ok=True)
        with open(os.path.join('logs', 'dns_last_config.json'), 'w') as f:
            json.dump({
                'hostname': hostname,
                'name_server': name_server,
                'secondary_name_server': secondary_name_server,
                'domain_suffix': domain_suffix,
                'timestamp': datetime.now().isoformat()
            }, f, indent=2)
        return jsonify({'status': 'success', 'message': 'DNS configuration applied', 'dns_status': 'applied'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})
"""
@app.route('/api/dns_config', methods=['POST'])
def api_dns_config():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    config = request.json
    dns_mode = config.get('dns_mode', 'manual')
    hostname = config.get('hostname')
    name_server = config.get('name_server')
    secondary_name_server = config.get('secondary_name_server')
    domain_suffix = config.get('domain_suffix')

    try:
        # --- Save config to log ---
        os.makedirs('logs', exist_ok=True)
        with open('logs/dns_last_config.json', 'w') as f:
            json.dump(config, f, indent=2)

        # --- Apply based on DNS mode ---
        if dns_mode == 'manual':
            if not name_server and not secondary_name_server:
                return jsonify({
                    'status': 'error',
                    'message': 'Manual DNS mode requires at least one DNS server.'
                }), 400

            resolv_content = ""
            if domain_suffix:
                resolv_content += f"domain {domain_suffix}\n"
            if name_server:
                resolv_content += f"nameserver {name_server}\n"
            if secondary_name_server:
                resolv_content += f"nameserver {secondary_name_server}\n"

            subprocess.run(["sudo", "-n", "cp", "/etc/resolv.conf", "/etc/resolv.conf.backup"], check=True)
            # subprocess.run(["sudo", "-n", "cp", "/etc/resolv.conf", "/etc/resolv.conf.backup"], check=True)
            subprocess.run(["sudo", "-n", "hostnamectl", "set-hostname", hostname], check=True)

            with open("/etc/resolv.conf", "w") as f:
                f.write(resolv_content)

        elif dns_mode == 'dhcp':
            # Enable DHCP client to manage DNS
            subprocess.run(["sudo", "-n", "dhclient", "-r"], check=False)
            subprocess.run(["sudo", "-n", "dhclient"], check=False)

        elif dns_mode == 'disable':
            # Clear DNS (not recommended, but for completeness)
            with open("/etc/resolv.conf", "w") as f:
                f.write("# DNS disabled by user\n")

        # --- Set hostname if provided ---
        if hostname:
            subprocess.run(["sudo", "-n", "hostnamectl", "set-hostname", hostname], check=True)

        return jsonify({
            'status': 'success',
            'message': f'DNS configuration applied in {dns_mode} mode',
            'dns_status': dns_mode
        })
    except Exception as e:
        err = str(e)
        if 'sudo' in err.lower() or 'a password is required' in err.lower():
            err = 'Permission denied. Please allow passwordless sudo for DNS and hostname commands.'
        return jsonify({'status': 'error', 'message': f'DNS apply failed: {err}'})
    


@app.route('/api/dns_status', methods=['GET'])
def api_dns_status():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    dns_info = {
        'hostname': '',
        'domain': '',
        'nameservers': []
    }

    # Get hostname
    try:
        dns_info['hostname'] = subprocess.run(['hostname'], capture_output=True, text=True).stdout.strip()
    except:
        dns_info['hostname'] = 'Error'

    # Get domain
    try:
        dns_info['domain'] = subprocess.run(['hostname', '-d'], capture_output=True, text=True).stdout.strip()
    except:
        dns_info['domain'] = 'Error'

    # Get nameservers
    try:
        with open('/etc/resolv.conf', 'r') as f:
            dns_info['nameservers'] = [line.split()[1] for line in f if line.startswith('nameserver')]
    except:
        dns_info['nameservers'] = ['Unavailable']

    return jsonify(dns_info)



@app.route('/api/routes_status')
def api_routes_status():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        result = subprocess.check_output(['ip', 'route'], text=True)
        routes = []
        for line in result.strip().splitlines():
            parts = line.split()
            if len(parts) >= 3:
                routes.append({
                    'destination': parts[0],
                    'via': parts[2] if 'via' in parts else '-'
                })
        return jsonify({'status': 'success', 'routes': routes})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/remote_check')
def remote_check_page():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    return render_template('remote_check.html')

@app.route('/api/remote_check', methods=['POST'])
def api_remote_check():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    target = data.get('target')
    check_type = data.get('type')  # ping, telnet, traceroute
    port = data.get('port', 80)
    timeout = int(data.get('timeout', 5))
    
    try:
        if check_type == 'ping':
            result = ping3.ping(target, timeout=5)
            if result is not None:
                return jsonify({'status': 'success', 'message': f'Ping successful: {result*1000:.2f}ms'})
            else:
                return jsonify({'status': 'error', 'message': 'Ping failed'})
        elif check_type == 'telnet':
            try:
                tn = telnetlib.Telnet(target, port, timeout=timeout)
                tn.close()
                return jsonify({'status': 'success', 'message': f'Connection successful to {target}:{port}'})
            except:
                return jsonify({'status': 'error', 'message': f'Connection failed to {target}:{port}'})
        elif check_type == 'traceroute':
            # Try traceroute, fall back to tracepath if not available
            try:
                cmd = ['traceroute', '-m', '20', '-w', str(timeout), target]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout*4)
            except FileNotFoundError:
                try:
                    cmd = ['tracepath', '-m', '20', target]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout*4)
                except FileNotFoundError:
                    return jsonify({'status': 'error', 'message': 'traceroute/tracepath not installed'})

            output = (result.stdout or result.stderr or '').strip()
            # Limit very long outputs
            if len(output) > 5000:
                output = output[:5000] + '\n... truncated ...'
            if result.returncode in (0, 1):  # traceroute may return 1 even when producing output
                return jsonify({'status': 'success', 'message': output})
            return jsonify({'status': 'error', 'message': output or 'Traceroute failed'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/ports')
def ports_page():
    if 'user' not in session:
        return redirect('/login')
    return render_template('ports.html')

@app.route('/port-config')
def port_config_page():
    if 'user' not in session:
        return redirect('/login')
    return render_template('port_config.html')


@app.route('/api/ports_config', methods=['POST'])
def api_ports_config():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    config = request.json
    h323_enabled = config.get('h323_enabled', False)
    sip_enabled = config.get('sip_enabled', False)
    h323_port = config.get('h323_port', '1720')
    sip_port = config.get('sip_port', '5060')
    private_ip = config.get('private_ip', '')
    public_ip = config.get('public_ip', '')

    try:
        update_docker_compose_env('H323_ENABLED', str(h323_enabled).lower())
        update_docker_compose_env('SIP_ENABLED', str(sip_enabled).lower())
        update_docker_compose_env('H323_PORT', str(h323_port))
        update_docker_compose_env('SIP_PORT', str(sip_port))
        update_docker_compose_env('PRIVATE_IP', private_ip)
        update_docker_compose_env('PUBLIC_IP', public_ip)

        restart_results = []
        restarted_names = []

        # Restart only enabled protocol stacks (best-effort per compose project).
        if h323_enabled:
            restart_results.append(restart_docker_container('h323'))
            restarted_names.append('H323')
        if sip_enabled:
            restart_results.append(restart_docker_container('sip'))
            restarted_names.append('SIP')

        # If nothing is enabled, env update is still a valid success.
        if not restart_results:
            message = 'Configuration applied successfully. No enabled services to restart.'
            return jsonify({
                'status': 'success',
                'message': message,
                'current_state': {
                    'h323_enabled': h323_enabled,
                    'sip_enabled': sip_enabled,
                    'h323_port': h323_port,
                    'sip_port': sip_port,
                    'private_ip': private_ip,
                    'public_ip': public_ip
                }
            })

        if all(restart_results):
            message = f'Configuration applied successfully. Restarted: {", ".join(restarted_names)}'
            return jsonify({
                'status': 'success',
                'message': message,
                'current_state': {
                    'h323_enabled': h323_enabled,
                    'sip_enabled': sip_enabled,
                    'h323_port': h323_port,
                    'sip_port': sip_port,
                    'private_ip': private_ip,
                    'public_ip': public_ip
                }
            })
        else:
            return jsonify({'status': 'error', 'message': 'Failed to restart one or more containers'})

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


@app.route('/api/ports_config_state', methods=['GET'])
def api_ports_config_state():
    state = {
        'h323_enabled': False,
        'sip_enabled': False,
        'h323_port': '1720',
        'sip_port': '5060',
        'private_ip': '',
        'public_ip': ''
    }
    try:
        for compose_path in _collect_compose_files():
            with open(compose_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('- H323_ENABLED='):
                        state['h323_enabled'] = line.split('=', 1)[1].lower() == 'true'
                    elif line.startswith('- SIP_ENABLED='):
                        state['sip_enabled'] = line.split('=', 1)[1].lower() == 'true'
                    elif line.startswith('- H323_PORT='):
                        state['h323_port'] = line.split('=', 1)[1]
                    elif line.startswith('- SIP_PORT='):
                        state['sip_port'] = line.split('=', 1)[1]
                    elif line.startswith('- PRIVATE_IP='):
                        state['private_ip'] = line.split('=', 1)[1]
                    elif line.startswith('- PUBLIC_IP='):
                        state['public_ip'] = line.split('=', 1)[1]
        return jsonify({'status': 'success', 'current_state': state})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


@app.route('/users')
def users_page():
    if 'user' not in session or session.get('role') != 'admin':
        flash('Access denied! Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        with open('users.json', 'r') as f:
            users_data = json.load(f)
            
            # Support both dict- and list-style JSON formats
            if isinstance(users_data, dict):
                users = []
                for username, info in users_data.items():
                    # Ensure each user entry includes a username field
                    user_entry = info
                    user_entry['username'] = username
                    users.append(user_entry)
            elif isinstance(users_data, list):
                users = users_data
            else:
                users = []
    except (FileNotFoundError, json.JSONDecodeError):
        users = []
    
    return render_template('users.html', users=users)


@app.route('/api/users', methods=['GET'])
def api_list_users():
    if 'user' not in session or session.get('role') != 'admin':
        return jsonify({'error': 'Admin privileges required'}), 403
    users = load_users()
    return jsonify({'status': 'success', 'users': users})

@app.route('/api/users', methods=['POST'])
def api_create_user():
    if 'user' not in session or session['role'] != 'admin':
        return jsonify({'error': 'Admin privileges required'}), 403
    
    data = request.json
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'user')

    users = load_users()
    if username in users:
        return jsonify({'status': 'error', 'message': 'User already exists'})
    
    users[username] = {
        'password': password,  # Storing as plain text as requested
        'role': role,
        'created': datetime.now().isoformat()
    }
    
    save_users(users)
    return jsonify({'status': 'success', 'message': 'User created successfully'})

@app.route('/api/users/<username>', methods=['PUT'])
def api_update_user(username):
    try:
        if 'user' not in session or session.get('role') != 'admin':
            return jsonify({'status': 'error', 'message': 'Admin privileges required'}), 403

        data = request.json
        users = load_users()

        if username not in users:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404

        # Update role if provided
        if 'role' in data and data['role']:
            users[username]['role'] = data['role']

        # Update password if provided and not empty
        if 'password' in data and data['password']:
            users[username]['password'] = data['password']

        # Optionally update other fields
        users[username]['updated'] = datetime.now().isoformat()

        save_users(users)
        return jsonify({'status': 'success', 'message': 'User updated successfully'})
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500



@app.route('/api/users/<username>', methods=['DELETE'])
def api_delete_user(username):
    try:
        if 'user' not in session or session.get('role') != 'admin':
            return jsonify({'status': 'error', 'message': 'Admin privileges required'}), 403

        users = load_users()
        
        if username not in users:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404
        
        del users[username]
        save_users(users)
        
        return jsonify({'status': 'success', 'message': f'User {username} deleted successfully'})
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/ssl')
def ssl_page():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('ssl.html')


ALLOWED_EXTENSIONS = {
    'cert': '.cert',
    'key': '.key'
}

# CERT_PATH = '/var/www/ssl/tst/tst.cert'  # change to writable path
# KEY_PATH = '/var/www/ssl/tst/tst.key'

@app.route('/api/ssl_upload', methods=['POST'])
def api_ssl_upload():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        field = request.form.get('field')  # 'cert' or 'key'
        file = request.files.get('file')
        if not file or field not in ['cert', 'key']:
            return jsonify({'status': 'error', 'message': 'Invalid upload'}), 400

        # Server-side extension check
        allowed_ext = ALLOWED_EXTENSIONS[field]
        if not file.filename.lower().endswith(allowed_ext):
            return jsonify({'status': 'error', 'message': f'Invalid file type! Only {allowed_ext} allowed.'}), 400

        save_path = CERT_PATH if field == 'cert' else KEY_PATH
        os.makedirs(os.path.dirname(save_path), exist_ok=True)

        try:
            file.save(save_path)
            os.chmod(save_path, 0o600)
            return jsonify({'status': 'success', 'message': f'{field.upper()} uploaded successfully'})
        except PermissionError:
            return jsonify({'status': 'error', 'message': 'Permission denied. Check folder permissions.'}), 403

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


@app.route('/api/nginx_restart', methods=['POST'])
def api_nginx_restart():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    try:
        subprocess.run(['sudo', 'systemctl', 'restart', 'nginx'], check=True)
        return jsonify({'status': 'success', 'message': 'Nginx Restarted successfully'})
    except subprocess.CalledProcessError:
        return jsonify({'status': 'error', 'message': 'Restart failed'})

"""
@app.route('/api/nginx_restart', methods=['POST'])
def api_nginx_restart():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    host = os.getenv("SSH_HOST")
    key_path = os.getenv("SSH_KEY_PATH")

    if not host or not key_path:
        return jsonify({'error': 'SSH config missing in environment'}), 500

    # ✅ Fix key permissions before using it
    if os.path.exists(key_path):
        try:
            os.chmod(key_path, 0o600)
        except PermissionError:
            pass  # read-only mount, safe to ignore

    try:
        cmd = [
            'ssh', '-i', key_path,
            '-o', 'StrictHostKeyChecking=no',
            host, 'sudo /bin/systemctl restart nginx'
        ]
        subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return jsonify({'status': 'success', 'message': f'Nginx restarted on {host}'})
    except FileNotFoundError:
        return jsonify({'error': 'SSH not installed in container'}), 500
    except subprocess.CalledProcessError as e:
        return jsonify({'status': 'error', 'message': e.stderr.decode() or f'Failed to restart Nginx on {host}'})
"""

@app.route('/api/check_port_status', methods=['GET'])
def api_check_port_status():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        default_ports = [
            {'id': 'http', 'name': 'HTTP', 'port': 80, 'enabled': True, 'isDefault': True},
            {'id': 'https', 'name': 'HTTPS', 'port': 443, 'enabled': True, 'isDefault': True},
            {'id': 'ssh', 'name': 'SSH', 'port': 22, 'enabled': True, 'isDefault': True}
        ]
        
        # Get ports currently open in system (ss)
        ss_output = subprocess.getoutput("ss -tuln | awk '{print $5}' | grep -oE '[0-9]+$' | sort -u")
        system_open_ports = set()
        for port in ss_output.split():
            if port.strip().isdigit():
                system_open_ports.add(int(port.strip()))

        # Get UFW status for each port with a timeout to prevent stalls
        ufw_ports = {}
        try:
            result = subprocess.run(["sudo", "ufw", "status"], capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if "ALLOW" in line or "DENY" in line:
                        parts = line.split()
                        for part in parts:
                            if part.isdigit():
                                port_num = int(part)
                                ufw_ports[port_num] = "ALLOW" in line
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            pass # Fallback: assume enabled if we can't check

        # Update default ports with actual system status
        for port in default_ports:
            port_num = port['port']
            if port_num in system_open_ports:
                port['enabled'] = ufw_ports.get(port_num, True)
            else:
                port['enabled'] = False

        # Add other open ports found in system
        other_ports = []
        for port_num in system_open_ports:
            if port_num not in [80, 443, 22]:  # Not a default port
                other_ports.append({
                    'id': f'port_{port_num}',
                    'name': f'Port {port_num}',
                    'port': port_num,
                    'enabled': ufw_ports.get(port_num, True),
                    'isDefault': False
                })

        all_ports = default_ports + other_ports
        
        return jsonify({
            'status': 'success', 
            'ports': all_ports,
            'system_open_ports': sorted(list(system_open_ports))
        })

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/scan_ports', methods=['GET'])
def api_scan_ports():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        # Use nmap to scan common ports
        nmap_output = subprocess.getoutput("nmap -sT -O localhost 2>/dev/null || echo 'nmap not available'")
        
        # Also get netstat output as fallback
        netstat_output = subprocess.getoutput("netstat -tuln 2>/dev/null || ss -tuln")
        
        # Parse netstat/ss output for open ports
        open_ports = []
        for line in netstat_output.split('\n'):
            if 'LISTEN' in line or 'tcp' in line.lower():
                parts = line.split()
                for part in parts:
                    if ':' in part and part.split(':')[-1].isdigit():
                        port = int(part.split(':')[-1])
                        if port not in [port_info['port'] for port_info in open_ports]:
                            # Try to identify service
                            service_name = "Unknown"
                            if port == 22:
                                service_name = "SSH"
                            elif port == 80:
                                service_name = "HTTP"
                            elif port == 443:
                                service_name = "HTTPS"
                            elif port == 21:
                                service_name = "FTP"
                            elif port == 25:
                                service_name = "SMTP"
                            elif port == 53:
                                service_name = "DNS"
                            elif port == 110:
                                service_name = "POP3"
                            elif port == 143:
                                service_name = "IMAP"
                            elif port == 993:
                                service_name = "IMAPS"
                            elif port == 995:
                                service_name = "POP3S"
                            elif port == 587:
                                service_name = "SMTP-Submission"
                            elif port == 465:
                                service_name = "SMTPS"
                            elif port == 8080:
                                service_name = "HTTP-Alt"
                            elif port == 8443:
                                service_name = "HTTPS-Alt"
                            elif port == 3306:
                                service_name = "MySQL"
                            elif port == 5432:
                                service_name = "PostgreSQL"
                            elif port == 6379:
                                service_name = "Redis"
                            elif port == 27017:
                                service_name = "MongoDB"
                            elif port == 9200:
                                service_name = "Elasticsearch"
                            elif port == 5601:
                                service_name = "Kibana"
                            
                            open_ports.append({
                                'port': port,
                                'service': service_name,
                                'state': 'open',
                                'protocol': 'tcp'
                            })

        # Sort by port number
        open_ports.sort(key=lambda x: x['port'])
        
        return jsonify({
            'status': 'success',
            'scan_results': open_ports,
            'nmap_output': nmap_output if 'nmap not available' not in nmap_output else None,
            'total_ports': len(open_ports)
        })

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/system_ports', methods=['POST'])
def api_system_ports():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        data = request.json
        ports = data.get('ports', [])
        default_ports = data.get('defaultPorts', [])
        custom_ports = data.get('customPorts', [])
        
        # Process all ports (default + custom)
        all_ports = ports if ports else (default_ports + custom_ports)
        
        # Log the configuration for debugging
        os.makedirs('logs', exist_ok=True)
        with open(os.path.join('logs', 'ports_last_config.json'), 'w') as f:
            json.dump({
                'ports': all_ports,
                'default_ports': default_ports,
                'custom_ports': custom_ports,
                'timestamp': datetime.now().isoformat()
            }, f, indent=2)
        
        # Apply UFW rules for each port
        for port_config in all_ports:
            port_num = port_config.get('port')
            enabled = port_config.get('enabled', False)
            port_name = port_config.get('name', f'Port {port_num}')

            # Validate port number
            if not isinstance(port_num, int) or not (1 <= port_num <= 65535):
                continue

            port_str = str(port_num)
            
            try:
                # Apply firewall rules safely
                if enabled:
                    # Allow the port
                    result = subprocess.run(["sudo", "ufw", "allow", port_str], 
                                          capture_output=True, text=True, check=False)
                    print(f"UFW allow {port_str}: {result.returncode} - {result.stdout} - {result.stderr}")
                else:
                    # Deny the port
                    result = subprocess.run(["sudo", "ufw", "deny", port_str], 
                                          capture_output=True, text=True, check=False)
                    print(f"UFW deny {port_str}: {result.returncode} - {result.stdout} - {result.stderr}")
                    
            except Exception as port_error:
                print(f"Error configuring port {port_str}: {port_error}")
                continue

        # Reload UFW to apply changes
        reload_result = subprocess.run(["sudo", "ufw", "--force", "reload"], 
                                     capture_output=True, text=True, check=False)
        print(f"UFW reload: {reload_result.returncode} - {reload_result.stdout} - {reload_result.stderr}")
        
        return jsonify({
            'status': 'success', 
            'message': f'Port configuration applied successfully. {len(all_ports)} ports processed.',
            'processed_ports': len(all_ports)
        })

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})



# These should already be defined somewhere in your config
@app.route("/licence")
def licence_page():
    if "user" not in session:
        return redirect("/login")
    return render_template("licence.html")

import yaml
import traceback
# --- Read current licence keys from docker-compose.yml ---
@app.route("/api/licence_get", methods=["GET"])
def licence_get():
    try:
        def read_key(compose_path, key_name):
            yml_path = _resolve_compose_file(compose_path)
            if not yml_path or not os.path.exists(yml_path):
                return None

            with open(yml_path, "r") as f:
                data = yaml.safe_load(f)

            for service, conf in data.get("services", {}).items():
                env = conf.get("environment", {})

                # If list format
                if isinstance(env, list):
                    for e in env:
                        if e.startswith(key_name + "="):
                            return e.split("=", 1)[1]

                # If dict format
                elif isinstance(env, dict):
                    if key_name in env:
                        return env[key_name]
            return None

        management_key = read_key(MANAGEMENT_DOCKER_PATH, "LICENCE_KEY_MANAGEMENT")
        mcu_key = read_key(MCU_DOCKER_PATH, "LICENCE_KEY_MCU")

        return jsonify({
            "LICENCE_KEY_MANAGEMENT": management_key or "Not Set",
            "LICENCE_KEY_MCU": mcu_key or "Not Set"
        })

    except Exception as e:
        print("🔥 ERROR in /api/licence_get:", traceback.format_exc())
        return jsonify({"error": str(e)}), 500


@app.route("/api/licence_update", methods=["POST"])
def licence_update():
    try:
        data = request.json
        target = data.get("target")
        key_value = data.get("key_value")

        if not target or not key_value:
            return jsonify({"status": "error", "message": "Missing target or value"}), 400

        if target == "management":
            compose_path = MANAGEMENT_DOCKER_PATH
            key_name = "LICENCE_KEY_MANAGEMENT"
        elif target == "mcu":
            compose_path = MCU_DOCKER_PATH
            key_name = "LICENCE_KEY_MCU"
        else:
            return jsonify({"status": "error", "message": "Invalid target"}), 400

        yml_path = _resolve_compose_file(compose_path)
        if not yml_path or not os.path.exists(yml_path):
            return jsonify({"status": "error", "message": f"Missing {yml_path}"}), 400

        with open(yml_path, "r") as f:
            data = yaml.safe_load(f)

        for service, conf in data.get("services", {}).items():
            env = conf.get("environment", {})

            # Handle dict-style
            if isinstance(env, dict):
                env[key_name] = key_value
            # Handle list-style
            elif isinstance(env, list):
                updated = False
                for i, e in enumerate(env):
                    if e.startswith(key_name + "="):
                        env[i] = f"{key_name}={key_value}"
                        updated = True
                if not updated:
                    env.append(f"{key_name}={key_value}")
            else:
                env = [f"{key_name}={key_value}"]

            conf["environment"] = env

        with open(yml_path, "w") as f:
            yaml.dump(data, f, default_flow_style=False)

        return jsonify({"status": "success", "message": f"{key_name} updated successfully"})

    except Exception as e:
        print("🔥 ERROR in /api/licence_update:", traceback.format_exc())
        return jsonify({"status": "error", "message": str(e)}), 500


# --- Restart docker-compose stack ---
@app.route("/api/docker_compose_restart", methods=["POST"])
def restart_docker_compose():
    data = request.json
    target = data.get("target")

    if target == "management":
        compose_path = MANAGEMENT_DOCKER_PATH
    elif target == "mcu":
        compose_path = MCU_DOCKER_PATH
    else:
        return jsonify({"status": "error", "message": "Invalid target"}), 400

    try:
        compose_file = _resolve_compose_file(compose_path)
        if not compose_file:
            return jsonify({"status": "error", "message": f"Missing compose file in {compose_path}"}), 400

        cwd = os.path.dirname(compose_file)
        subprocess.run(
            ["docker", "compose", "-f", compose_file, "down", "--remove-orphans"],
            check=True,
            cwd=cwd
        )
        subprocess.run(
            ["docker", "compose", "-f", compose_file, "up", "-d", "--force-recreate"],
            check=True,
            cwd=cwd
        )
        return jsonify({"status": "success", "message": f"{target.capitalize()} restarted successfully"})

    except subprocess.CalledProcessError as e:
        return jsonify({"status": "error", "message": f"Docker error: {str(e)}"}), 500


if __name__ == '__main__':
    # Create default admin user if users.json doesn't exist
    if not os.path.exists(USERS_FILE):
        default_users = {
            'admin': {
                'password': 'admin123',
                'role': 'admin',
                'created': datetime.now().isoformat()
            }
        }
        save_users(default_users)
    
    app.run(debug=True, host=HOST, port=PORT)
