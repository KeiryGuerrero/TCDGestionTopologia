# Sistema de Descubrimiento y Gestion de Topologia de Red (SNMP/LLDP)

Aplicacion web en **Flask** (archivo unico `app.py`) para descubrir dispositivos de red por SNMP, inferir enlaces por LLDP y visualizar la topologia en una interfaz web interactiva.

## Caracteristicas

- Descubrimiento de dispositivos en rangos IP configurados.
- Consulta de metadatos SNMP (hostname, descripcion, uptime, contacto, ubicacion, interfaces, etc.).
- Deteccion de vecinos LLDP para construir enlaces entre nodos.
- API JSON para topologia y detalle por dispositivo.
- UI embebida en el backend (HTML/CSS/JS en `render_template_string`).
- Actualizacion periodica de topologia desde el frontend.

## Arquitectura (resumen)

- **Backend**: Flask + sockets UDP manuales para SNMP GET/GETNEXT.
- **Descubrimiento**:
  - `discover_topology()` consulta dispositivos en `SCAN_RANGES`.
  - `get_lldp_neighbors()` arma enlaces a partir de LLDP.
- **Detalle**:
  - `get_device_detail()` consulta OIDs clave y estado de interfaces.
- **Frontend**:
  - D3.js para visualizacion de nodos/enlaces.
  - Panel lateral con dispositivos y panel de detalle SNMP.

## Requisitos

- Python 3.9+ (recomendado 3.10 o superior).
- Dependencia Python:
  - `flask`
- Acceso de red UDP/161 desde el host donde corre la app hacia los equipos SNMP.
- Equipos con SNMP habilitado y comunidad correcta (por defecto: `public`).

## Instalacion

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install flask
```

> Si ya tienes un entorno virtual activo en el proyecto, instala solo `flask`.

## Ejecucion

Asegura que `app.py` este en el mismo directorio y luego ejecuta:

```powershell
python app.py
```

Salida esperada en consola:

- `Iniciando en http://localhost:5000`

Abre en navegador:

- `http://localhost:5000`

## Endpoints

### `GET /`

Devuelve la interfaz web de topologia.

### `GET /api/topology`

Ejecuta descubrimiento y retorna nodos/enlaces.

Ejemplo de respuesta:

```json
{
  "nodes": [
    {"name": "router", "ip": "192.168.216.254", "type": "router", "status": "online", "hostname": "router"}
  ],
  "links": [
    {"source": "router", "target": "switch1"}
  ]
}
```

### `GET /api/device/<ip>`

Retorna detalle SNMP del dispositivo especificado.

Ejemplo:

```json
{
  "ip": "192.168.216.254",
  "type": "router",
  "status": "online",
  "hostname": "router",
  "model": "Cisco IOS Software",
  "os_version": "15.7",
  "full_description": "...",
  "uptime": "2d 3h 10m",
  "contact": "admin",
  "location": "LAB",
  "object_id": "1.3.6.1.4.1...",
  "if_count": "8",
  "interfaces": [
    {"name": "GigabitEthernet0/0", "status": "up", "speed": "1 Gbps"}
  ]
}
```

## Configuracion

La configuracion principal esta en constantes dentro de `app.py`:

- `SCAN_RANGES`: lista de rangos IP a explorar.
- `ALL_IPS`: lista plana derivada de `SCAN_RANGES`.
- Comunidad SNMP por defecto: `public` (en funciones `snmp_get` y `snmp_getnext`).
- Timeout SNMP por defecto: `2` segundos.

### Ajustar rangos de escaneo

Ejemplo:

```python
SCAN_RANGES = [
    [f"192.168.1.{i}" for i in range(1, 255)],
    ["10.0.0.1"]
]
```

## Consideraciones de seguridad

- Esta implementacion usa comunidad SNMP en texto plano (`public`), tipico de SNMPv1/v2c.
- **No exponer** esta aplicacion directamente a Internet.
- Restringir acceso por firewall/VPN.
- Ejecutar en red de gestion o laboratorio.
- Para entornos productivos, considerar migracion a SNMPv3 y autenticacion robusta.

## Limitaciones conocidas

- Parser SNMP minimalista y manual (TLV/BER basico), no cubre todos los casos del protocolo.
- Deteccion de tipo de dispositivo basada en hostname (`router` vs `switch`), heuristica simple.
- Maximo de interfaces listadas por equipo: 12 (`return interfaces[:12]`).
- El frontend depende de CDN para D3.js y Google Fonts (requiere salida a Internet para esos recursos).
- No hay autenticacion de usuario en la UI/API.

## Solucion de problemas

### No aparecen dispositivos

- Verifica conectividad IP hacia los targets.
- Confirma SNMP habilitado y comunidad correcta.
- Revisa reglas de firewall para UDP/161.
- Amplia timeout SNMP si hay latencia alta.

### Topologia sin enlaces

- Puede no haber LLDP habilitado en equipos.
- La app aplica fallback a enlaces secuenciales por nombre cuando no detecta vecinos LLDP.

### Error al abrir la UI

- Confirma que Flask este instalado en el entorno activo.
- Revisa que el puerto `5000` este libre.
- Ejecuta desde el directorio donde se encuentra `app.py`.


