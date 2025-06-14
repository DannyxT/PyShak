Crearemos una aplicación web local usando Flask (un micro-framework de Python) que te permitirá controlar la captura desde tu navegador.
Arquitectura de la Solución

Backend (Python + Flask):
El script de Python se convertirá en un servidor web.
Tendrá una ruta principal (/) que mostrará la interfaz web (el frontend).
Tendrá rutas API (ej. /api/start, /api/stop, /api/status) que el frontend usará para controlar la captura.
La captura de paquetes se ejecutará en un hilo separado para no bloquear el servidor web.
Frontend (HTML + CSS + JavaScript):
Una página web simple con un diseño de "dashboard".
Un menú desplegable para seleccionar la interfaz de red.
Botones para "Iniciar" y "Detener" la captura.
Un área de estado que se actualizará en tiempo real para mostrar si la captura está activa y qué dispositivos se han detectado.
Enlaces para descargar los archivos .pcap generados.
Prerrequisitos (Sin cambios)
Asegúrate de tener todo lo del script anterior:
Wireshark (con tshark en el PATH del sistema).
Python.

La librería pyshark (pip install pyshark).
¡NUEVO! La librería Flask (pip install Flask).
Paso 1: Estructura del Proyecto
Crea una carpeta para tu proyecto (ej. C:\PysharkUI). Dentro, crea la siguiente estructura:
C:\PysharkUI\
├── templates\
│   └── index.html
└── app.py
Use code with caution.
app.py: Será nuestro servidor Flask y la lógica de captura.
templates/index.html: Será nuestro frontend.
Paso 2: El Backend (app.py)
Este es el archivo principal. Contiene el servidor web y la lógica para manejar la captura en un hilo separado.
Copia este código en app.py:
import os
import subprocess
import threading
import time
import pyshark
from flask import Flask, render_template, jsonify, request, send_from_directory

# --- Configuración y Estado Global ---
app = Flask(__name__)
OUTPUT_DIR = "capturas_por_dispositivo"

# Variables de estado para controlar el hilo de captura
capture_thread = None
is_capturing = False
# Usamos un lock para acceder a la lista de IPs desde múltiples hilos de forma segura
detected_ips_lock = threading.Lock()
detected_ips = {} # { "ip_address": "file_path.pcap" }

# --- Lógica de Captura ---

def run_capture(interface_name):
    """Esta función se ejecuta en un hilo separado para capturar paquetes."""
    global is_capturing, detected_ips

    # Asegura que el directorio de salida exista
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
    
    live_caps = {}
    
    try:
        capture = pyshark.LiveCapture(interface=interface_name)
        # Bucle que se controla con la variable global is_capturing
        for packet in capture.sniff_continuously():
            if not is_capturing:
                break # Salir del bucle si se detiene la captura

            if 'IP' in packet:
                ip_src = packet.ip.src
                ip_dst = packet.ip.dst
                
                # Procesamos ambas IPs (origen y destino)
                for ip_addr in {ip_src, ip_dst}:
                    with detected_ips_lock:
                        if ip_addr not in detected_ips:
                            filepath = os.path.join(OUTPUT_DIR, f"{ip_addr}.pcap")
                            detected_ips[ip_addr] = filepath
                            live_caps[ip_addr] = pyshark.LiveRingCapture(output_file=filepath)
                            print(f"Nuevo dispositivo: {ip_addr}")
                    
                    # Guardamos el paquete en el archivo correspondiente
                    if ip_addr in live_caps:
                        live_caps[ip_addr].sniff(packet_count=1, packet=packet)

    except Exception as e:
        print(f"Error en el hilo de captura: {e}")
    finally:
        # Limpieza al finalizar
        for cap in live_caps.values():
            cap.close()
        is_capturing = False
        print("Hilo de captura finalizado.")


# --- Rutas del Servidor Web (Endpoints) ---

@app.route('/')
def index():
    """Sirve la página principal del frontend."""
    return render_template('index.html')

@app.route('/api/interfaces')
def get_interfaces():
    """Obtiene y devuelve la lista de interfaces de red."""
    try:
        # Ejecuta 'tshark -D' para listar interfaces y captura la salida
        result = subprocess.run(['tshark', '-D'], capture_output=True, text=True, check=True)
        interfaces = [line.split('(')[-1].replace(')','').strip() for line in result.stdout.strip().split('\n') if '(' in line]
        return jsonify(interfaces)
    except Exception as e:
        print(f"Error al listar interfaces: {e}")
        return jsonify({"error": "No se pudo obtener la lista de interfaces. ¿Está Wireshark instalado y en el PATH?"}), 500

@app.route('/api/start', methods=['POST'])
def start_capture():
    """Inicia la captura en un hilo."""
    global capture_thread, is_capturing, detected_ips
    
    if is_capturing:
        return jsonify({"status": "error", "message": "La captura ya está en progreso."}), 400

    interface = request.json.get('interface')
    if not interface:
        return jsonify({"status": "error", "message": "No se especificó una interfaz."}), 400
    
    is_capturing = True
    # Reiniciamos la lista de IPs detectadas para la nueva sesión
    with detected_ips_lock:
        detected_ips = {}
        
    capture_thread = threading.Thread(target=run_capture, args=(interface,))
    capture_thread.start()
    
    return jsonify({"status": "ok", "message": f"Captura iniciada en '{interface}'."})

@app.route('/api/stop', methods=['POST'])
def stop_capture():
    """Detiene el hilo de captura."""
    global is_capturing
    
    if not is_capturing:
        return jsonify({"status": "error", "message": "No hay ninguna captura activa."}), 400

    is_capturing = False
    if capture_thread:
        capture_thread.join(timeout=5) # Espera a que el hilo termine

    return jsonify({"status": "ok", "message": "La captura ha sido detenida."})

@app.route('/api/status')
def get_status():
    """Devuelve el estado actual de la captura y los dispositivos detectados."""
    with detected_ips_lock:
        return jsonify({
            "is_capturing": is_capturing,
            "detected_ips": detected_ips
        })
        
@app.route('/download/<filename>')
def download_file(filename):
    """Permite descargar los archivos pcap generados."""
    return send_from_directory(OUTPUT_DIR, filename, as_attachment=True)


if __name__ == '__main__':
    print("Iniciando servidor web...")
    print(f"Abre tu navegador y ve a http://127.0.0.1:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)
Use code with caution.
Python
Paso 3: El Frontend (templates/index.html)
Este archivo contiene toda la interfaz de usuario. Usa JavaScript para comunicarse con el backend de Flask sin necesidad de recargar la página.
Copia este código en templates/index.html:
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Pyshark UI - Filtro de Dispositivos</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #1a1a1d; color: #c5c6c7; margin: 0; padding: 20px; }
        .container { max-width: 900px; margin: auto; background: #2c2f33; padding: 25px; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.4); }
        h1 { color: #66fcf1; border-bottom: 2px solid #45a29e; padding-bottom: 10px; }
        .controls, .status-box, .devices-list { margin-bottom: 25px; }
        label { font-weight: bold; color: #45a29e; }
        select, button { padding: 10px 15px; font-size: 16px; border-radius: 5px; border: none; cursor: pointer; }
        select { background: #99aab5; color: #23272a; width: 300px; }
        button { background-color: #66fcf1; color: #1f2833; font-weight: bold; margin-left: 10px; }
        #stopBtn { background-color: #c3073f; color: white; }
        button:disabled { background-color: #555; color: #888; cursor: not-allowed; }
        .status-box { background: #23272a; padding: 15px; border-radius: 5px; }
        #status-indicator { display: inline-block; width: 15px; height: 15px; border-radius: 50%; margin-right: 10px; vertical-align: middle; }
        .stopped { background: #c3073f; }
        .running { background: #66fcf1; animation: pulse 1.5s infinite; }
        @keyframes pulse { 0% { box-shadow: 0 0 0 0 rgba(102, 252, 241, 0.7); } 70% { box-shadow: 0 0 0 10px rgba(102, 252, 241, 0); } 100% { box-shadow: 0 0 0 0 rgba(102, 252, 241, 0); } }
        #device-table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        #device-table th, #device-table td { padding: 12px; text-align: left; border-bottom: 1px solid #45a29e; }
        #device-table th { background-color: #45a29e; color: #1f2833; }
        #device-table a { color: #66fcf1; text-decoration: none; }
        #device-table a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Pyshark UI - Filtro de Dispositivos</h1>

        <div class="controls">
            <label for="interface-select">Seleccionar Interfaz:</label>
            <select id="interface-select"></select>
            <button id="startBtn">Iniciar Captura</button>
            <button id="stopBtn" disabled>Detener Captura</button>
        </div>

        <div class="status-box">
            <strong>Estado:</strong>
            <span id="status-indicator" class="stopped"></span>
            <span id="status-text">Detenido</span>
        </div>

        <div class="devices-list">
            <h2>Dispositivos Detectados</h2>
            <table id="device-table">
                <thead>
                    <tr>
                        <th>Dirección IP</th>
                        <th>Archivo de Captura</th>
                    </tr>
                </thead>
                <tbody id="device-table-body">
                    <tr><td colspan="2">Inicie una captura para ver los dispositivos.</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const interfaceSelect = document.getElementById('interface-select');
            const startBtn = document.getElementById('startBtn');
            const stopBtn = document.getElementById('stopBtn');
            const statusIndicator = document.getElementById('status-indicator');
            const statusText = document.getElementById('status-text');
            const deviceTableBody = document.getElementById('device-table-body');
            let statusInterval;

            // 1. Cargar las interfaces al iniciar la página
            fetch('/api/interfaces')
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        alert(data.error);
                        return;
                    }
                    data.forEach(iface => {
                        const option = document.createElement('option');
                        option.value = iface;
                        option.textContent = iface;
                        interfaceSelect.appendChild(option);
                    });
                });

            // 2. Iniciar la captura
            startBtn.addEventListener('click', () => {
                const selectedInterface = interfaceSelect.value;
                if (!selectedInterface) {
                    alert('Por favor, selecciona una interfaz.');
                    return;
                }
                
                fetch('/api/start', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ interface: selectedInterface })
                })
                .then(response => response.json())
                .then(data => {
                    console.log(data.message);
                    updateUI(true);
                    statusInterval = setInterval(updateStatus, 2000); // Actualizar estado cada 2 segundos
                });
            });

            // 3. Detener la captura
            stopBtn.addEventListener('click', () => {
                fetch('/api/stop', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    console.log(data.message);
                    clearInterval(statusInterval);
                    updateUI(false);
                });
            });

            // 4. Función para actualizar el estado y la lista de dispositivos
            function updateStatus() {
                fetch('/api/status')
                .then(response => response.json())
                .then(data => {
                    updateUI(data.is_capturing);
                    
                    deviceTableBody.innerHTML = '';
                    const ips = Object.keys(data.detected_ips);
                    if (ips.length === 0) {
                        deviceTableBody.innerHTML = '<tr><td colspan="2">Esperando tráfico...</td></tr>';
                    } else {
                        ips.sort().forEach(ip => {
                            const filename = data.detected_ips[ip].split(/[\\/]/).pop();
                            const row = `<tr>
                                <td>${ip}</td>
                                <td><a href="/download/${filename}">${filename}</a></td>
                            </tr>`;
                            deviceTableBody.innerHTML += row;
                        });
                    }
                });
            }

            // 5. Función para actualizar la interfaz de usuario (botones y estado)
            function updateUI(isCapturing) {
                if (isCapturing) {
                    statusIndicator.className = 'running';
                    statusText.textContent = 'Capturando...';
                    startBtn.disabled = true;
                    stopBtn.disabled = false;
                    interfaceSelect.disabled = true;
                } else {
                    statusIndicator.className = 'stopped';
                    statusText.textContent = 'Detenido';
                    startBtn.disabled = false;
                    stopBtn.disabled = true;
                    interfaceSelect.disabled = false;
                }
            }
        });
    </script>
</body>
</html>
Use code with caution.
Html

Cómo Ejecutar la Aplicación Completa

Guarda los archivos app.py y templates/index.html en sus respectivas carpetas.
Ejecuta como Administrador: Como antes, la captura de paquetes necesita privilegios. Abre CMD o PowerShell como administrador.
Navega a la carpeta del proyecto (cd C:\PysharkUI).
Ejecuta el servidor Flask:
python app.py
Use code with caution.
Bash

Abre tu navegador: Ve a la dirección http://127.0.0.1:5000.
Usa la interfaz:
El menú desplegable se llenará con tus interfaces de red.
Selecciona la que quieras monitorear (ej. "Wi-Fi").
Haz clic en "Iniciar Captura".
El indicador de estado se pondrá verde y parpadeará.
A medida que los dispositivos de tu red generen tráfico, aparecerán en la tabla "Dispositivos Detectados".
Puedes hacer clic en el nombre del archivo .pcap para descargarlo.
Cuando termines, haz clic en "Detener Captura".
