# ASCON-128a Educational Visualizer

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/downloads/)

Herramienta educativa interactiva para aprender el algoritmo de cifrado autenticado **ASCON-128a** paso a paso. Visualiza permutaciones, operaciones criptográficas, S-box, y mucho más.

## Características Principales

### 🌟 Interfaz Educativa Completa
- **Ejecución paso a paso**: Visualiza cada ronda de la permutación
- **Navegación interactiva**: Explora cada fase del cifrado
- **Visualización en hexadecimal y binario**: Entiende a nivel de bits
- **Modo comparativo**: Compara dos ejecuciones lado a lado
- **Ejemplos predefinidos**: Casos de uso básicos a avanzados

### 🚀 Características Técnicas
- Implementación completa de ASCON-128a
- Visualización detallada de:
  - Estado interno (5 registros de 64 bits)
  - Operaciones XOR, rotaciones y S-box
  - Capa lineal (difusión)
  - Permutaciones pa (12 rondas) y pb (6 rondas)
- Suite completa de 20 tests unitarios
- Validación de padding ASCON
- Soporte para Associated Data (AD)

### 🎨 Interfaz Gráfica (Tkinter)
- Diseño moderno y responsivo
- 4 pestañas principales:
  - **Visualización**: Ejecución paso a paso
  - **Resultados**: Salidas del cifrado
  - **Detalles**: Análisis profundo de cada fase
  - **Guía Educativa**: Conceptos, operaciones y ejemplos

## Estructura del Proyecto

```
.
├── ASCON-128a.py           # Implementación principal + Visualizador GUI
├── test_ascon.py          # Suite de tests unitarios (20 tests)
├── README_TESTS.md        # Documentación de tests
├── README.md              # Este archivo
├── LICENSE                # MIT License
└── .gitignore             # Archivos ignorados por Git
```

## Requisitos

- **Python**: 3.8 o superior
- **Tkinter**: Incluido en la mayoría de instalaciones de Python
- Sin dependencias externas adicionales

## Instalación

### Opción 1: Clonar el repositorio

```bash
git clone https://github.com/javiermapelli/ASCON-128a-Educational-Visualizer.git
cd ASCON-128a-Educational-Visualizer
```

### Opción 2: Descargar ZIP

Descarga el repositorio como ZIP desde GitHub y extrae los archivos.

## Uso

### Ejecutar el Visualizador GUI

```bash
python ASCON-128a.py
```

La interfaz gráfica se abrirá con la pantalla de bienvenida.

### Ejecutar Tests

```bash
# Método 1: Ejecución directa
python test_ascon.py

# Método 2: Con pytest (recomendado)
pip install pytest pytest-cov
pytest test_ascon.py -v

# Método 3: Con cobertura
pytest test_ascon.py --cov=ASCON128a --cov-report=html
```

## Tutoriales de Uso

### 1. Empezar desde Cero

1. Abre la aplicación
2. Haz clic en **"Cargar Ejemplo"** para elegir un caso predefinido
3. Haz clic en **"Iniciar"**
4. Navega entre los pasos usando **"Paso Anterior"** y **"Siguiente Paso"**
5. Explora cada pestaña para entender el proceso

### 2. Comparar Dos Ejecuciones

1. Ejecuta ASCON dos veces con parámetros diferentes
2. Usa la opción **"Comparar Ejecuciones"** en la pestaña Comparación
3. Observa las diferencias en los resultados

### 3. Analizar Vectores de Prueba

1. Abre **"Verificar Vectores de Prueba"**
2. Selecciona un vector de la lista oficial
3. Compara el resultado con el valor esperado

## Conceptos Criptográficos

### ¿Qué es ASCON-128a?

ASCON-128a es un algoritmo **Authenticated Encryption with Associated Data** (AEAD) ganador de la competencia CAESAR 2019. Combina:

- **Cifrado**: Protege la confidencialidad
- **Autenticación**: Verifica la integridad
- **Datos Asociados**: Autentica datos sin cifrarlos

### Componentes

- **Key** (128 bits): Clave secreta compartida
- **Nonce** (128 bits): Valor único por mensaje (NUNCA reutilizar)
- **Associated Data**: Datos que se autentican pero NO se cifran
- **Plaintext**: Datos a cifrar
- **Ciphertext**: Datos cifrados
- **Tag** (128 bits): Etiqueta de autenticación

### Fases de Ejecución

1. **Inicialización**: Crea estado de 320 bits (5x64), mezcla Key y Nonce
2. **Absorción de AD**: Procesa datos asociados en bloques de 64 bits
3. **Cifrado**: XOR del plaintext con el estado, permutación
4. **Finalización**: Mezcla Key nuevamente
5. **Generación de Tag**: Extrae 128 bits como etiqueta

### Operaciones Clave

- **XOR**: Mezcla de bits (reversible para descifrado)
- **Rotación**: Desplazamiento circular de bits
- **S-box**: Substitución no-lineal (confusión)
- **Difusión Lineal**: Propaga cambios a través del estado
- **Permutación pa/pb**: 12/6 rondas de transformación

## Tests Unitarios

La suite incluye 20 tests que cubren:

### Padding (5 tests)
- Padding de bloque vacío
- Padding de bloque parcial
- Bloque completo sin modificación
- Remoción correcta de padding
- Validación de padding válido

### Operaciones Básicas (7 tests)
- Inicialización
- Cifrado de mensaje vacío
- Cifrado/descifrado ida y vuelta
- Rechazo de tag inválido
- Detección de ciphertext corrupto
- Cifrado con datos asociados
- Cambios en ciphertext

### Propiedades Criptográficas (2 tests)
- Cifrado determinista
- Diferentes nonces producen diferentes outputs

### Seguridad (2 tests)
- Detección de reutilización de nonce (advertencia)
- Validación de longitud de clave

### Utilidades (4 tests)
- Conversión hex ↔ int
- Casos límite de padding
- Remoción con varias longitudes

## Requisitos de Seguridad

⚠️ **IMPORTANTE**: Esta herramienta es solo para educación. Para uso en producción:

1. **NUNCA reutilices un Nonce** con la misma clave
2. **SIEMPRE verifica el Tag** antes de usar datos descifrados
3. **Usa claves criptográficamente seguras**
4. **Mantén la Key en secreto absoluto**
5. **Usa Nonces únicos y no predecibles** (timestamp, contador, random)

## Documentación de Vectores de Prueba

Ver `README_TESTS.md` para:
- Lista completa de tests
- Vectores de prueba oficiales
- Instrucciones de validación
- Troubleshooting

## Ejemplos de Uso

### Ejemplo 1: Cifrado Básico

```python
from ASCON128a import ASCON128a

key = "000102030405060708090A0B0C0D0E0F"
nonce = "000102030405060708090A0B0C0D0E0F"
plaintext = "4142434445464748"  # "ABCDEFGH" en hex

ascon = ASCON128a()
ascon.initialize(key, nonce)
ascon.process_ad("")  # Sin datos asociados
ciphertext, _ = ascon.encrypt(plaintext)
tag, _ = ascon.finalize(key)

print(f"Ciphertext: {ciphertext}")
print(f"Tag: {tag}")
```

### Ejemplo 2: Cifrado con Datos Asociados

```python
ascon = ASCON128a()
ascon.initialize(key, nonce)

# Autenticar metadatos sin cifrar
metadata = "606162636465666768696A6B6C6D6E6F"
ascon.process_ad(metadata)

# Cifrar datos sensibles
sensitive_data = "4142434445464748"
ciphertext, _ = ascon.encrypt(sensitive_data)
tag, _ = ascon.finalize(key)
```

## Contribuciones

Este es un proyecto educativo. Las contribuciones son bienvenidas:

1. Fork el repositorio
2. Crea una rama para tu feature (`git checkout -b feature/mejora`)
3. Commit tus cambios (`git commit -am 'Añade mejora'`)
4. Push a la rama (`git push origin feature/mejora`)
5. Abre un Pull Request

## Licencia

MIT License - Ver `LICENSE` para detalles

## Referencias

- [ASCON Official Website](https://ascon.iaik.tugraz.at/)
- [ASCON Specification v1.2](https://ascon.iaik.tugraz.at/files/asconv12-final.pdf)
- [ASCON GitHub Repository](https://github.com/ascon/ascon-c)
- [CAESAR Competition](https://competitions.cr.yp.to/caesar.html)
- [NIST Lightweight Cryptography](https://csrc.nist.gov/projects/lightweight-cryptography)

## Autores

Desarrollado como herramienta educativa para estudiantes de criptografía y profesionales de la seguridad.

---

⚠️ **Nota Legal**: Esta herramienta es solo para fines educativos. El autor no es responsable del uso indebido o la implementación insegura en producción.
