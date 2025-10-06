# Modbus-RTU-tool-with-Python
Tkinter Modbus RTU scanner &amp; read/write utility (pymodbus + pyserial). Scan through different speeds.
# Modbus RTU Scanner (Tkinter)

Herramienta en Python para **escanear dispositivos Modbus RTU** (combinando baudrate, paridad, stop bits y byte size) y realizar **lectura/escritura** de coils y registers. Incluye **GUI en Tkinter**.

## Requisitos
Python 3.12+, `pymodbus`, `pyserial`, `pillow`
```bash
python -m venv .venv
# Activar venv (Win) .venv\Scripts\activate
pip install -r requirements.txt
