# Modbus-RTU-tool-with-Python
Tkinter Modbus RTU scanner &amp; read/write utility (pymodbus + pyserial). Scan through different speeds.
# Modbus RTU Scanner (Tkinter)
Tested with Python 3.12. This tool is for users with basic Python experience who need to scan or read devices on a Modbus RTU network. It requires external hardware: a serial adapter (e.g., USB-to-RS-485/RS-232) to connect the RTU network to your PC; install the adapter’s drivers and select the corresponding COM port in the app.

Herramienta en Python para **escanear dispositivos Modbus RTU** (combinando baudrate, paridad, stop bits y byte size) y realizar **lectura/escritura** de coils y registers. Incluye **GUI en Tkinter**.
Este código no funciona por si solo, necesita correrse en un entorno con Python 3.12 y requiere de hardware adicional para poder escanear/leer la red RTU, un adaptador serial como USB a RS-485 es el ideal.

## Requisitos
Python 3.12+, `pymodbus`, `pyserial`, `pillow`
```bash
python -m venv .venv
# Activar venv (Win) .venv\Scripts\activate
pip install -r requirements.txt
