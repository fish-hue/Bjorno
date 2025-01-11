import json
import subprocess
import os
import csv
import zipfile
import uuid
import cgi
import io
import importlib
import logging
from datetime import datetime
from logger import Logger
from urllib.parse import unquote
from actions.nmap_vuln_scanner import NmapVulnScanner
from pathlib import Path

logger = Logger(name="utils.py", level=logging.DEBUG)

class WebUtils:
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.logger = logger
        self.actions = []
        self.standalone_actions = []

    def send_json_response(self, handler, status_code, data=None):
        """Utility function to send JSON responses."""
        handler.send_response(status_code)
        handler.send_header("Content-type", "application/json")
        handler.end_headers()
        if data:
            handler.wfile.write(json.dumps(data).encode('utf-8'))

    def send_error_response(self, handler, error_message, status_code=500):
        """Send an error response in JSON format."""
        self.send_json_response(handler, status_code, {"status": "error", "message": str(error_message)})

    def load_actions(self):
        """Load all actions from the actions file."""
        if not self.actions and not self.standalone_actions:
            actions_file = Path(self.shared_data.actions_file)
            with actions_file.open('r') as file:
                actions_config = json.load(file)

            for action in actions_config:
                module_name = action["b_module"]
                if module_name == 'scanning':
                    self.load_scanner(module_name)
                elif module_name == 'nmap_vuln_scanner':
                    self.load_nmap_vuln_scanner(module_name)
                else:
                    self.load_action(module_name, action)

    def load_scanner(self, module_name):
        """Load the network scanner."""
        module = importlib.import_module(f'actions.{module_name}')
        self.network_scanner = getattr(module, 'b_class')(self.shared_data)

    def load_nmap_vuln_scanner(self, module_name):
        """Load the nmap vulnerability scanner."""
        self.nmap_vuln_scanner = NmapVulnScanner(self.shared_data)

    def load_action(self, module_name, action):
        """Load an action from the actions file."""
        module = importlib.import_module(f'actions.{module_name}')
        try:
            b_class = action["b_class"]
            action_instance = getattr(module, b_class)(self.shared_data)
            action_instance.action_name = b_class
            action_instance.port = action.get("b_port", 0)
            action_instance.b_parent_action = action.get("b_parent")
            if action_instance.port == 0:
                self.standalone_actions.append(action_instance)
            else:
                self.actions.append(action_instance)
        except AttributeError as e:
            self.logger.error(f"Module {module_name} is missing required attributes: {e}")

    def serve_netkb_data_json(self, handler):
        """Serve JSON data from the netkb file."""
        try:
            with open(self.shared_data.netkbfile, 'r', encoding='utf-8') as file:
                reader = csv.DictReader(file)
                data = [row for row in reader if row['Alive'] == '1']
            actions = reader.fieldnames[5:]  
            response_data = {
                'ips': [row['IPs'] for row in data],
                'ports': {row['IPs']: row['Ports'].split(';') for row in data},
                'actions': actions
            }
            self.send_json_response(handler, 200, response_data)
        except Exception as e:
            self.send_error_response(handler, e)

    def execute_manual_attack(self, handler):
        """Handles manual attack execution."""
        try:
            content_length = int(handler.headers['Content-Length'])
            post_data = handler.rfile.read(content_length).decode('utf-8')
            params = json.loads(post_data)
            ip, port, action_class = params['ip'], params['port'], params['action']

            self.logger.info(f"Received request to execute {action_class} on {ip}:{port}")
            self.load_actions()

            action_instance = next((action for action in self.actions if action.action_name == action_class), None)
            if action_instance is None:
                raise ValueError(f"Action class '{action_class}' not found")

            current_data = self.shared_data.read_data()
            row = next((r for r in current_data if r["IPs"] == ip), None)
            if row is None:
                raise ValueError(f"No data found for IP: {ip}")

            action_key = action_instance.action_name
            self.logger.info(f"Executing {action_key} on {ip}:{port}")
            result = action_instance.execute(ip, port, row, action_key)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            row[action_key] = f"{result}_{timestamp}"
            result_status = "success" if result == 'success' else "failed"
            self.logger.info(f"Action {action_key} {result_status} on {ip}:{port}")
            self.shared_data.write_data(current_data)

            self.send_json_response(handler, 200, {"status": "success", "message": "Manual attack executed"})
        except Exception as e:
            self.logger.error(f"Error executing manual attack: {e}")
            self.send_error_response(handler, e)

    def serve_logs(self, handler):
        """Serve the logs."""
        try:
            log_file_path = Path(self.shared_data.webconsolelog)
            if not log_file_path.exists():
                subprocess.Popen(f"sudo tail -f /home/bjorn/Bjorn/data/logs/* > {log_file_path}", shell=True)

            with log_file_path.open('r') as log_file:
                log_lines = log_file.readlines()[-2000:]  # Get last 2000 lines

            handler.send_response(200)
            handler.send_header("Content-type", "text/plain")
            handler.end_headers()
            handler.wfile.write(''.join(log_lines).encode('utf-8'))
        except Exception as e:
            self.logger.error(f"Error serving logs: {e}")
            self.send_error_response(handler, e)

    def start_orchestrator(self, handler):
        """Start the orchestrator."""
        try:
            self.shared_data.bjorn_instance.start_orchestrator()
            self.send_json_response(handler, 200, {"status": "success", "message": "Orchestrator starting..."})
        except Exception as e:
            self.send_error_response(handler, e)

    def stop_orchestrator(self, handler):
        """Stop the orchestrator."""
        try:
            self.shared_data.bjorn_instance.stop_orchestrator()
            self.shared_data.orchestrator_should_exit = True
            self.send_json_response(handler, 200, {"status": "success", "message": "Orchestrator stopping..."})
        except Exception as e:
            self.send_error_response(handler, e)

    def backup(self, handler):
        """Create a backup of important directories."""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_filename = f"backup_{timestamp}.zip"
            backup_path = Path(self.shared_data.backupdir) / backup_filename

            with zipfile.ZipFile(backup_path, 'w') as backup_zip:
                for folder in [self.shared_data.configdir, self.shared_data.datadir, 
                               self.shared_data.actions_dir, self.shared_data.resourcesdir]:
                    for root, dirs, files in os.walk(folder):
                        for file in files:
                            file_path = Path(root) / file
                            backup_zip.write(file_path, file_path.relative_to(self.shared_data.currentdir))

            self.send_json_response(handler, 200, {
                "status": "success",
                "url": f"/download_backup?filename={backup_filename}",
                "filename": backup_filename
            })
        except Exception as e:
            self.send_error_response(handler, e)

    def restore(self, handler):
        """Restore from a backup file."""
        try:
            content_length = int(handler.headers['Content-Length'])
            field_data = handler.rfile.read(content_length)
            field_storage = cgi.FieldStorage(fp=io.BytesIO(field_data), headers=handler.headers, 
                                              environ={'REQUEST_METHOD': 'POST'})

            file_item = field_storage['file']
            if file_item.filename:
                backup_path = Path(self.shared_data.upload_dir) / file_item.filename
                with open(backup_path, 'wb') as output_file:
                    output_file.write(file_item.file.read())

                with zipfile.ZipFile(backup_path, 'r') as backup_zip:
                    backup_zip.extractall(self.shared_data.currentdir)

                self.send_json_response(handler, 200, {"status": "success", "message": "Restore completed successfully"})
            else:
                self.send_json_response(handler, 400, {"status": "error", "message": "No selected file"})
        except Exception as e:
            self.send_error_response(handler, e)

    def download_backup(self, handler):
        """Download a backup file."""
        try:
            query = unquote(handler.path.split('?filename=')[1])
            backup_path = Path(self.shared_data.backupdir) / query
            
            if backup_path.is_file():
                handler.send_response(200)
                handler.send_header("Content-Disposition", f'attachment; filename="{backup_path.name}"')
                handler.send_header("Content-type", "application/zip")
                handler.end_headers()
                with backup_path.open('rb') as file:
                    handler.wfile.write(file.read())
            else:
                handler.send_response(404)
                handler.end_headers()
        except Exception as e:
            self.send_error_response(handler, e)

    def serve_credentials_data(self, handler):
        """Serve credential data as HTML."""
        try:
            html_content = self.generate_html_for_csv_files(self.shared_data.crackedpwddir)
            handler.send_response(200)
            handler.send_header("Content-type", "text/html")
            handler.end_headers()
            handler.wfile.write(html_content.encode('utf-8'))
        except Exception as e:
            self.send_error_response(handler, e)

    def generate_html_for_csv_files(self, directory):
        """Generate HTML for CSV files in a directory."""
        html = '<div class="credentials-container">\n'
        for filename in os.listdir(directory):
            if filename.endswith('.csv'):
                filepath = Path(directory) / filename
                html += f'<h2>{filename}</h2>\n<table class="styled-table">\n<thead>\n<tr>\n'
                with filepath.open('r') as file:
                    reader = csv.reader(file)
                    headers = next(reader)
                    html += ''.join(f'<th>{header}</th>' for header in headers)
                    html += '</tr>\n</thead>\n<tbody>\n'
                    for row in reader:
                        html += '<tr>\n' + ''.join(f'<td>{cell}</td>' for cell in row) + '</tr>\n'
                html += '</tbody>\n</table>\n'
        html += '</div>\n'
        return html

    def list_files(self, directory):
        """Recursively list files and subdirectories."""
        files = []
        for entry in os.scandir(directory):
            if entry.is_dir():
                files.append({"name": entry.name, "is_directory": True, "children": self.list_files(entry.path)})
            else:
                files.append({"name": entry.name, "is_directory": False, "path": entry.path})
        return files

    def list_files_endpoint(self, handler):
        """Serve the list of files as JSON."""
        try:
            files = self.list_files(self.shared_data.datastolendir)
            self.send_json_response(handler, 200, files)
        except Exception as e:
            self.send_error_response(handler, e)

    def serve_file(self, handler, filename):
        """Serve a file for download."""
        try:
            file_path = Path(self.shared_data.webdir) / filename
            with file_path.open('r', encoding='utf-8') as file:
                content = file.read().replace('{{ web_delay }}', str(self.shared_data.web_delay * 1000))
                handler.send_response(200)
                handler.send_header("Content-type", "text/html")
                handler.end_headers()
                handler.wfile.write(content.encode('utf-8'))
        except FileNotFoundError:
            handler.send_response(404)
            handler.end_headers()

    def serve_current_config(self, handler):
        """Serve the current configuration as JSON."""
        try:
            with open(self.shared_data.shared_config_json, 'r') as f:
                config = json.load(f)
            self.send_json_response(handler, 200, config)
        except Exception as e:
            self.send_error_response(handler, e)

    def restore_default_config(self, handler):
        """Restore the default configuration."""
        try:
            self.shared_data.config = self.shared_data.default_config.copy()
            self.shared_data.save_config()
            self.send_json_response(handler, 200, self.shared_data.config)
        except Exception as e:
            self.send_error_response(handler, e)

    def serve_image(self, handler):
        """Serve an image file."""
        image_path = Path(self.shared_data.webdir) / 'screen.png'
        self.serve_file_from_path(handler, image_path, "image/png")

    def serve_favicon(self, handler):
        """Serve the favicon."""
        favicon_path = Path(self.shared_data.webdir) / 'images/favicon.ico'
        self.serve_file_from_path(handler, favicon_path, "image/x-icon")

    def serve_manifest(self, handler):
        """Serve the manifest file."""
        manifest_path = Path(self.shared_data.webdir) / 'manifest.json'
        self.serve_file_from_path(handler, manifest_path, "application/json")

    def serve_apple_touch_icon(self, handler):
        """Serve the Apple touch icon."""
        icon_path = Path(self.shared_data.webdir) / 'icons/apple-touch-icon.png'
        self.serve_file_from_path(handler, icon_path, "image/png")

    def serve_file_from_path(self, handler, file_path, content_type):
        """Serve any file from path."""
        try:
            if file_path.is_file():
                handler.send_response(200)
                handler.send_header("Content-type", content_type)
                handler.end_headers()
                with file_path.open('rb') as file:
                    handler.wfile.write(file.read())
            else:
                handler.send_response(404)
                handler.end_headers()
        except Exception as e:
            self.logger.error(f"Error serving file {file_path}: {e}")
            self.send_error_response(handler, e)

    def scan_wifi(self, handler):
        """Scan for available Wi-Fi networks."""
        try:
            result = subprocess.Popen(['sudo', 'iwlist', 'wlan0', 'scan'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = result.communicate()
            if result.returncode != 0:
                raise Exception(stderr)

            networks = self.parse_scan_result(stdout)
            current_ssid = self.get_current_ssid()
            self.send_json_response(handler, 200, {"networks": networks, "current_ssid": current_ssid})
        except Exception as e:
            self.logger.error(f"Error scanning Wi-Fi networks: {e}")
            self.send_error_response(handler, e)

    def get_current_ssid(self):
        """Get the current connected Wi-Fi SSID."""
        current_ssid_process = subprocess.Popen(['iwgetid', '-r'], stdout=subprocess.PIPE, text=True)
        ssid_out, ssid_err = current_ssid_process.communicate()
        if current_ssid_process.returncode != 0:
            raise Exception(ssid_err)
        return ssid_out.strip()

    def parse_scan_result(self, scan_output):
        """Extract wireless SSIDs from scan results."""
        networks = []
        for line in scan_output.split('\n'):
            if 'ESSID' in line:
                ssid = line.split(':')[1].strip('"')
                if ssid not in networks:
                    networks.append(ssid)
        return networks

    def connect_wifi(self, handler):
        """Connect to a specified Wi-Fi network."""
        try:
            content_length = int(handler.headers['Content-Length'])
            post_data = handler.rfile.read(content_length).decode('utf-8')
            params = json.loads(post_data)
            ssid = params['ssid']
            password = params['password']

            self.update_nmconnection(ssid, password)
            command = 'sudo nmcli connection up "preconfigured"'
            connect_result = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = connect_result.communicate()
            if connect_result.returncode != 0:
                raise Exception(stderr)

            self.shared_data.wifichanged = True
            self.send_json_response(handler, 200, {"status": "success", "message": f"Connected to {ssid}"})
        except Exception as e:
            self.send_error_response(handler, e)

    def disconnect_and_clear_wifi(self, handler):
        """Disconnect from Wi-Fi and clear connections."""
        try:
            command_disconnect = 'sudo nmcli connection down "preconfigured"'
            disconnect_result = subprocess.Popen(command_disconnect, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = disconnect_result.communicate()
            if disconnect_result.returncode != 0:
                raise Exception(stderr)

            config_path = Path('/etc/NetworkManager/system-connections/preconfigured.nmconnection')
            config_path.write_text("")  # Clear the config
            subprocess.Popen(['sudo', 'chmod', '600', str(config_path)]).communicate()
            subprocess.Popen(['sudo', 'nmcli', 'connection', 'reload']).communicate()

            self.shared_data.wifichanged = False
            self.send_json_response(handler, 200, {"status": "success", "message": "Disconnected from Wi-Fi and cleared preconfigured settings"})
        except Exception as e:
            self.send_error_response(handler, e)

    def clear_files(self, handler):
        """Clear specified files from directories."""
        self.clear_files_helper(handler, force_full_clear=True)

    def clear_files_light(self, handler):
        """Clear only light files from directories."""
        self.clear_files_helper(handler, force_full_clear=False)

    def clear_files_helper(self, handler, force_full_clear):
        """Helper function to clear files based on the specified mode."""
        command = """
        sudo rm -rf data/*.log && sudo rm -rf data/output/data_stolen/* && 
        sudo rm -rf data/output/crackedpwd/*  && sudo rm -rf data/output/scan_results/* && 
        sudo rm -rf __pycache__ && sudo rm -rf config/__pycache__ && 
        sudo rm -rf data/__pycache__  && sudo rm -rf actions/__pycache__  && 
        sudo rm -rf resources/__pycache__ && sudo rm -rf web/__pycache__ && 
        sudo rm -rf resources/waveshare_epd/__pycache__ && 
        sudo rm -rf data/logs/*  && sudo rm -rf data/output/vulnerabilities/*
        """
        if force_full_clear:
            command = """
            sudo rm -rf config/*.json && sudo rm -rf data/*.csv && sudo rm -rf backup/backups/* && 
            sudo rm -rf backup/uploads/* && sudo rm -rf config/* && 
            """ + command

        try:
            result = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = result.communicate()

            if result.returncode == 0:
                self.send_json_response(handler, 200, {"status": "success", "message": "Files cleared successfully"})
            else:
                self.send_error_response(handler, stderr)
        except Exception as e:
            self.send_error_response(handler, e)

    def initialize_csv(self, handler):
        """Initialize CSV files."""
        try:
            self.shared_data.generate_actions_json()
            self.shared_data.initialize_csv()
            self.shared_data.create_livestatusfile()
            self.send_json_response(handler, 200, {"status": "success", "message": "CSV files initialized successfully"})
        except Exception as e:
            self.send_error_response(handler, e)

    def reboot_system(self, handler):
        """Reboot the system."""
        try:
            subprocess.Popen("sudo reboot", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.send_json_response(handler, 200, {"status": "success", "message": "System is rebooting"})
        except Exception as e:
            self.send_error_response(handler, e)

    def shutdown_system(self, handler):
        """Shut down the system."""
        try:
            subprocess.Popen("sudo shutdown now", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.send_json_response(handler, 200, {"status": "success", "message": "System is shutting down"})
        except Exception as e:
            self.send_error_response(handler, e)

    def restart_bjorn_service(self, handler):
        """Restart the Bjorn service."""
        try:
            subprocess.Popen("sudo systemctl restart bjorn.service", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.send_json_response(handler, 200, {"status": "success", "message": "Bjorn service restarted successfully"})
        except Exception as e:
            self.send_error_response(handler, e)

    def serve_network_data(self, handler):
        """Serve the latest network scan results as HTML."""
        try:
            latest_file = max(
                (f for f in os.listdir(self.shared_data.scan_results_dir) if f.startswith('result_')),
                key=lambda f: os.path.getctime(os.path.join(self.shared_data.scan_results_dir, f))
            )
            table_html = self.generate_html_table(Path(self.shared_data.scan_results_dir) / latest_file)
            self.send_html_response(handler, 200, table_html)
        except Exception as e:
            self.send_error_response(handler, e)

    def generate_html_table(self, file_path):
        """Generate an HTML table from a CSV file."""
        header_html = ""
        rows_html = ""
        try:
            with open(file_path, 'r') as file:
                reader = csv.reader(file)
                headers = next(reader)
                header_html = ''.join(f'<th>{header}</th>' for header in headers)

                for row in reader:
                    cell_classes = ['green' if cell.strip() else 'red' for cell in row] 
                    rows_html += '<tr>' + ''.join(f'<td class="{cell_class}">{cell}</td>' for cell, cell_class in zip(row, cell_classes)) + '</tr>'
        except Exception as e:
            self.logger.error(f"Error in generate_html_table: {e}")
        
        return f'<table class="styled-table"><thead><tr>{header_html}</tr></thead><tbody>{rows_html}</tbody></table>'

    def generate_html_table_netkb(self, file_path):
        """Generate an HTML table for NetKB data."""
        header_html = ""
        rows_html = ""
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                reader = csv.reader(file)
                headers = next(reader)
                header_html = ''.join(f'<th>{header}</th>' for header in headers)

                for row in reader:
                    row_class = "blue-row" if '0' in row[3] else ""
                    rows_html += f'<tr class="{row_class}">' + ''.join(self.generate_cell_html(cell) for cell in row) + '</tr>'
        except Exception as e:
            self.logger.error(f"Error in generate_html_table_netkb: {e}")

        return f'<table class="styled-table"><thead><tr>{header_html}</tr></thead><tbody>{rows_html}</tbody></table>'

    def generate_cell_html(self, cell):
        """Generate the cell HTML with class based on the content."""
        if "success" in cell:
            cell_class = "green bold"
        elif "failed" in cell:
            cell_class = "red bold"
        elif cell.strip() == "":
            cell_class = "grey"
        else:
            cell_class = ""

        return f'<td class="{cell_class}">{cell}</td>'

    def serve_netkb_data(self, handler):
        """Serve the NetKB data as HTML."""
        try:
            latest_file = self.shared_data.netkbfile
            table_html = self.generate_html_table_netkb(latest_file)
            self.send_html_response(handler, 200, table_html)
        except Exception as e:
            self.send_error_response(handler, e)

    def send_html_response(self, handler, status_code, html_content):
        """Utility function to send HTML responses."""
        handler.send_response(status_code)
        handler.send_header("Content-type", "text/html")
        handler.end_headers()
        handler.wfile.write(html_content.encode('utf-8'))

    def update_nmconnection(self, ssid, password):
        """Update the NM connection with the provided SSID and password."""
        config_path = Path('/etc/NetworkManager/system-connections/preconfigured.nmconnection')
        config_data = f"""
[connection]
id=preconfigured
uuid={uuid.uuid4()}
type=wifi
autoconnect=true

[wifi]
ssid={ssid}
mode=infrastructure

[wifi-security]
key-mgmt=wpa-psk
psk={password}

[ipv4]
method=auto

[ipv6]
method=auto
"""
        config_path.write_text(config_data)
        subprocess.Popen(['sudo', 'chmod', '600', str(config_path)]).communicate()
        subprocess.Popen(['sudo', 'nmcli', 'connection', 'reload']).communicate()

    def save_configuration(self, handler):
        """Save the configuration passed from the request."""
        try:
            content_length = int(handler.headers['Content-Length'])
            post_data = handler.rfile.read(content_length).decode('utf-8')
            params = json.loads(post_data)

            with open(self.shared_data.shared_config_json, 'r') as f:
                current_config = json.load(f)

            for key, value in params.items():
                current_config[key] = self.cast_value(value)

            with open(self.shared_data.shared_config_json, 'w') as f:
                json.dump(current_config, f, indent=4)

            self.shared_data.load_config()
            self.send_json_response(handler, 200, {"status": "success", "message": "Configuration saved"})
        except Exception as e:
            self.send_error_response(handler, e)

    def cast_value(self, value):
        """Cast the incoming parameter value to the appropriate type."""
        if isinstance(value, bool):
            return value
        elif isinstance(value, str) and value.lower() in ['true', 'false']:
            return value.lower() == 'true'
        elif isinstance(value, (int, float)):
            return value
        elif isinstance(value, list):
            return [val for val in value if val != ""]
        elif isinstance(value, str):
            try:
                return float(value) if '.' in value else int(value)
            except ValueError:
                return value
        return value

    def download_file(self, handler):
        """Download a specified file."""
        try:
            query = unquote(handler.path.split('?path=')[1])
            file_path = Path(self.shared_data.datastolendir) / query

            if file_path.is_file():
                handler.send_response(200)
                handler.send_header("Content-Disposition", f'attachment; filename="{file_path.name}"')
                handler.send_header("Content-type", "application/octet-stream")
                handler.end_headers()
                with file_path.open('rb') as file:
                    handler.wfile.write(file.read())
            else:
                handler.send_response(404)
                handler.end_headers()
        except Exception as e:
            self.send_error_response(handler, e)
