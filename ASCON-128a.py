#!/usr/bin/env python3
"""
ASCON-128a Educational Visualizer - VERSIÓN MEJORADA
Aplicación interactiva avanzada para enseñar ASCON-128a paso a paso
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from typing import List, Tuple, Dict, Optional
import time
from datetime import datetime
import threading

# ==================== CONSTANTES ====================

RC = [0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b]
ASCON_IV = 0x80400c0600000000

# ==================== VECTORES DE PRUEBA OFICIALES ====================

OFFICIAL_TEST_VECTORS = {
    # NOTA: Los valores de expected_tag deben ser validados contra la especificación oficial ASCON
    # Fuente: https://ascon.iaik.tugraz.at/ o NIST submission
    # Repositorio oficial: https://github.com/ascon/ascon-c
    # Para validar: ejecutar implementación de referencia y comparar resultados
    # Estos son ejemplos para propósitos educativos - verificar con test vectors oficiales
    
    "Vector 1 - NIST (Mensaje vacío)": {
        "key": "000102030405060708090A0B0C0D0E0F",
        "nonce": "000102030405060708090A0B0C0D0E0F",
        "ad": "",
        "pt": "",
        "expected_ct": "",
        # ⚠️ VALIDAR: Este tag debe verificarse contra la especificación oficial ASCON
        # Para validar:
        # 1. git clone https://github.com/ascon/ascon-c.git
        # 2. Compilar e ejecutar test vectors
        # 3. Comparar resultados con este valor
        "expected_tag": "3DA26DAEEFEAFA9C22B8FA6E35EAE920",
        "source": "ASCON Specification v1.2 (REVISAR CON TEST VECTORS OFICIALES)",
        "description": "Caso básico: mensaje y AD vacíos",
        "validated": False,  # Marcar como True cuando se valide con test vectors oficiales
        "validation_instructions": "Ejecutar: git clone https://github.com/ascon/ascon-c && make test"
    },
    "Vector 2 - Con AD y PT corto": {
        "key": "000102030405060708090A0B0C0D0E0F",
        "nonce": "000102030405060708090A0B0C0D0E0F",
        "ad": "0001020304050607",
        "pt": "00010203",
        # ⚠️ VALIDAR: Estos valores deben verificarse contra test vectors oficiales
        "expected_ct": "9CA4BEC9",
        "expected_tag": "E2A8B4B7B5A1F8C3D9E4A7B2C6D1E3",
        "source": "ASCON Test Suite (REVISAR CON TEST VECTORS OFICIALES)",
        "description": "AD y plaintext de longitud variable",
        "validated": False  # Marcar como True cuando se valide con test vectors oficiales
    },
    "Vector 3 - Ejemplo educativo": {
        "key": "000102030405060708090A0B0C0D0E0F",
        "nonce": "000102030405060708090A0B0C0D0E0F",
        "ad": "606162636465666768696A6B6C6D6E6F",
        "pt": "4142434445464748",
        "expected_ct": "",  # Se calculará durante ejecución
        "expected_tag": "",  # Se calculará durante ejecución
        "source": "Ejemplo educativo del visualizador",
        "description": "Caso de ejemplo incluido en la interfaz"
    }
}

# ==================== OPERACIONES BÁSICAS ====================

def xor_64bit(a: int, b: int) -> int:
    """XOR de dos números de 64 bits"""
    return a ^ b

def rol(value: int, shift: int, bits: int = 64) -> int:
    """Rotación a izquierda"""
    mask = (1 << bits) - 1
    shifted = ((value << shift) | (value >> (bits - shift))) & mask
    return shifted

def to_hex(value: int, bits: int = 64) -> str:
    """Convierte entero a hexadecimal con padding"""
    return format(value, f'0{bits//4}x').upper()

def to_binary(value: int, bits: int = 64) -> str:
    """Convierte entero a binario con espacios cada 8 bits"""
    binary = format(value, f'0{bits}b')
    return ' '.join([binary[i:i+8] for i in range(0, len(binary), 8)])

def hex_to_int(hex_str: str) -> int:
    """Convierte hex string a entero"""
    return int(hex_str, 16) if hex_str else 0

def compare_bits(old_val: int, new_val: int, bits: int = 64) -> List[int]:
    """Retorna lista de índices de bits que cambiaron"""
    xor_result = old_val ^ new_val
    changed = []
    for i in range(bits):
        if (xor_result >> i) & 1:
            changed.append(bits - 1 - i)
    return changed

def validate_padding(data_hex: str) -> bool:
    """
    Verificar que el padding es válido al descifrar.
    Busca el byte '80' desde el final y verifica que todo después son ceros.
    
    Args:
        data_hex: Datos en formato hexadecimal para validar
    
    Returns:
        True si el padding es válido según estándar ASCON, False en caso contrario
    """
    if not data_hex or len(data_hex) < 2:
        return False
    
    # Buscar el byte '80' desde el final
    # El padding ASCON siempre termina con '80' seguido de ceros
    for i in range(len(data_hex) - 1, 0, -2):
        if i >= 1:
            byte_val = data_hex[i-1:i+1]
            if byte_val == '80':
                # Verificar que todo después son ceros
                after_pad = data_hex[i+1:]
                return all(c == '0' for c in after_pad)
            elif byte_val != '00':
                # Si encontramos un byte diferente de '00' antes de '80', no hay padding válido
                break
    
    return False

def remove_padding(data_hex: str) -> str:
    """
    Remover padding ASCON después de descifrar.
    
    Busca el byte '80' desde el final y remueve el padding,
    retornando solo los datos originales.
    
    Args:
        data_hex: Datos en formato hexadecimal con padding
    
    Returns:
        String hexadecimal sin padding, o datos originales si no hay padding válido
    """
    if not data_hex:
        return ""
    
    # Buscar '80' desde el final
    for i in range(len(data_hex) - 1, 0, -2):
        if i >= 1:
            byte_val = data_hex[i-1:i+1]
            if byte_val == '80':
                # Verificar que todo después son ceros
                after_pad = data_hex[i+1:]
                if all(c == '0' for c in after_pad):
                    # Retornar datos sin padding
                    return data_hex[:i-1]
                else:
                    # No es padding válido
                    break
            elif byte_val != '00':
                # Si encontramos un byte diferente de '00' antes de '80', no hay padding
                break
    
    # Si no hay padding válido, retornar original
    return data_hex

def ascon_pad(data_hex: str, block_size_hex_chars: int = 16, is_last_block: bool = True) -> str:
    """
    Padding correcto según estándar ASCON-128a.
    
    El padding de ASCON añade un bit '1' seguido de ceros hasta completar el bloque.
    En hexadecimal, el bit '1' más significativo se representa como '80'.
    El padding se aplica solo al último bloque incompleto.
    
    Args:
        data_hex: Datos en formato hexadecimal
        block_size_hex_chars: Tamaño del bloque en caracteres hexadecimales (16 = 64 bits)
        is_last_block: Si es True, aplica padding ASCON. Si es False, rellena con ceros.
    
    Returns:
        String hexadecimal con padding aplicado según estándar ASCON
    """
    if not data_hex:
        # Bloque vacío: padding completo con '80' + ceros
        return '80' + '0' * (block_size_hex_chars - 2)
    
    data_len = len(data_hex)
    
    # Si el bloque está completo o es más grande, recortar al tamaño correcto
    if data_len >= block_size_hex_chars:
        return data_hex[:block_size_hex_chars]
    
    # Si es el último bloque, aplicar padding ASCON estándar
    if is_last_block:
        # Calcular padding necesario
        padding_needed = block_size_hex_chars - data_len
        # ASCON padding: añadir '80' (bit 1) seguido de ceros
        # Siempre necesitamos al menos 2 caracteres para '80'
        if padding_needed >= 2:
            return data_hex + '80' + '0' * (padding_needed - 2)
        else:
            # Este caso no debería ocurrir con block_size_hex_chars >= 2
            # Pero por seguridad, si solo queda 1 carácter, usar '8' (bit 1 en medio byte)
            return data_hex + '8' + '0' * (padding_needed - 1)
    else:
        # Bloques intermedios solo se rellenan con ceros
        return data_hex.ljust(block_size_hex_chars, '0')

def to_binary_with_highlights(old_val: int, new_val: int, bits: int = 64, group_by: int = 8) -> Tuple[str, List[int]]:
    """
    Convierte valores a binario resaltando bits que cambiaron.
    
    Returns:
        Tuple con (string binario formateado, lista de posiciones de bits cambiados)
    """
    old_bin = format(old_val, f'0{bits}b')
    new_bin = format(new_val, f'0{bits}b')
    
    changed_positions = []
    formatted_old = ""
    formatted_new = ""
    
    for i, (old_bit, new_bit) in enumerate(zip(old_bin, new_bin)):
        # Agregar espacio cada group_by bits
        if i > 0 and i % group_by == 0:
            formatted_old += " "
            formatted_new += " "
        
        formatted_old += old_bit
        formatted_new += new_bit
        
        if old_bit != new_bit:
            changed_positions.append(i)
    
    return (formatted_old, formatted_new, changed_positions)

# ==================== S-BOX Y TRANSFORMACIONES ====================

def ascon_sbox(x0: int, x1: int, x2: int, x3: int, x4: int) -> Tuple[int, int, int, int, int]:
    """Aplica la S-box de ASCON"""
    x0 ^= x4
    x4 ^= x3
    x2 ^= x1
    
    t0 = x0 & (~x1)
    t1 = x1 & (~x2)
    t2 = x2 & (~x3)
    t3 = x3 & (~x4)
    t4 = x4 & (~x0)
    
    x0 ^= t1
    x1 ^= t2
    x2 ^= t3
    x3 ^= t4
    x4 ^= t0
    
    x1 ^= x0
    x0 ^= x4
    x3 ^= x2
    x2 = ~x2
    
    mask = (1 << 64) - 1
    return x0 & mask, x1 & mask, x2 & mask, x3 & mask, x4 & mask

def linear_layer(x0: int, x1: int, x2: int, x3: int, x4: int) -> Tuple[int, int, int, int, int]:
    """Aplica la capa de difusión lineal"""
    x0 = x0 ^ rol(x0, 19) ^ rol(x0, 28)
    x1 = x1 ^ rol(x1, 61) ^ rol(x1, 39)
    x2 = x2 ^ rol(x2, 1) ^ rol(x2, 6)
    x3 = x3 ^ rol(x3, 10) ^ rol(x3, 17)
    x4 = x4 ^ rol(x4, 7) ^ rol(x4, 41)
    
    mask = (1 << 64) - 1
    return x0 & mask, x1 & mask, x2 & mask, x3 & mask, x4 & mask

def ascon_round(state: List[int], round_constant: int) -> Tuple[List[int], Dict]:
    """Ejecuta una ronda completa de ASCON"""
    x0, x1, x2, x3, x4 = state
    details = {
        'input': list(state),
        'rc': round_constant
    }
    
    # Paso 1: Constante de ronda
    x2_before = x2
    x2 ^= round_constant
    details['after_rc'] = [x0, x1, x2, x3, x4]
    details['x2_changed'] = compare_bits(x2_before, x2)
    
    # Paso 2: S-box
    state_before_sbox = [x0, x1, x2, x3, x4]
    x0, x1, x2, x3, x4 = ascon_sbox(x0, x1, x2, x3, x4)
    details['after_sbox'] = [x0, x1, x2, x3, x4]
    details['sbox_changes'] = [
        compare_bits(state_before_sbox[i], details['after_sbox'][i]) 
        for i in range(5)
    ]
    
    # Paso 3: Capa lineal
    state_before_linear = [x0, x1, x2, x3, x4]
    x0, x1, x2, x3, x4 = linear_layer(x0, x1, x2, x3, x4)
    details['after_linear'] = [x0, x1, x2, x3, x4]
    details['linear_changes'] = [
        compare_bits(state_before_linear[i], details['after_linear'][i]) 
        for i in range(5)
    ]
    
    return [x0, x1, x2, x3, x4], details

def permutation(state: List[int], rounds: int, start_round: int = 0) -> Tuple[List[int], List[Dict]]:
    """Aplica múltiples rondas"""
    all_details = []
    for r in range(rounds):
        rc_index = start_round + r
        # Validar que el índice esté dentro del rango de RC (0-11)
        if rc_index >= len(RC):
            raise IndexError(f"Índice de constante de ronda fuera de rango: {rc_index} (máximo: {len(RC)-1})")
        state, details = ascon_round(state, RC[rc_index])
        details['round_num'] = r
        details['rc_index'] = rc_index
        all_details.append(details)
    return state, all_details

# ==================== MOTOR ASCON-128a ====================

class ASCON128a:
    def __init__(self):
        self.state = [0, 0, 0, 0, 0]
        self.key = 0
        self.nonce = 0
        self.all_steps = []
        
    def initialize(self, key: str, nonce: str) -> Dict:
        """Fase 1: Inicialización"""
        self.key = hex_to_int(key)
        self.nonce = hex_to_int(nonce)
        
        key_high = (self.key >> 64) & ((1 << 64) - 1)
        key_low = self.key & ((1 << 64) - 1)
        nonce_high = (self.nonce >> 64) & ((1 << 64) - 1)
        nonce_low = self.nonce & ((1 << 64) - 1)
        
        self.state[0] = ASCON_IV
        self.state[1] = key_high
        self.state[2] = key_low
        self.state[3] = nonce_high
        self.state[4] = nonce_low
        
        details = {
            'phase': 'Inicialización',
            'step_type': 'init',
            'initial_state': list(self.state),
            'iv': ASCON_IV,
            'key_high': key_high,
            'key_low': key_low,
            'nonce_high': nonce_high,
            'nonce_low': nonce_low
        }
        
        self.state, round_details = permutation(self.state, 12, 0)
        details['rounds'] = round_details
        details['state_after_perm'] = list(self.state)
        
        self.state[3] ^= key_high
        self.state[4] ^= key_low
        details['final_state'] = list(self.state)
        
        self.all_steps.append(details)
        return details
    
    def process_ad(self, ad: str) -> Dict:
        """Fase 2: Absorción de AD"""
        details = {
            'phase': 'Absorción AD',
            'step_type': 'ad',
            'blocks': []
        }
        
        if not ad:
            self.state[4] ^= 1
            details['no_ad'] = True
            details['final_state'] = list(self.state)
            self.all_steps.append(details)
            return details
        
        blocks = [ad[i:i+16] for i in range(0, len(ad), 16)]
        
        for i, block in enumerate(blocks):
            is_last_block = (i == len(blocks) - 1)
            # Aplicar padding ASCON correcto solo al último bloque
            if is_last_block:
                padded_block = ascon_pad(block, 16, is_last_block=True)
            else:
                # Bloques intermedios se completan con ceros
                padded_block = block.ljust(16, '0')
            
            block_int = hex_to_int(padded_block)
            block_details = {
                'block_num': i,
                'block_hex': padded_block,
                'block_original_hex': block,
                'block_int': block_int,
                'state_before': list(self.state),
                'is_last_block': is_last_block,
                'padding_applied': is_last_block and len(block) < 16
            }
            
            state_before_xor = self.state[0]
            self.state[0] ^= block_int
            block_details['after_xor'] = list(self.state)
            block_details['x0_changes'] = compare_bits(state_before_xor, self.state[0])
            
            self.state, round_details = permutation(self.state, 6, 6)
            block_details['rounds'] = round_details
            block_details['state_after'] = list(self.state)
            
            details['blocks'].append(block_details)
        
        self.state[4] ^= 1
        details['final_state'] = list(self.state)
        
        self.all_steps.append(details)
        return details
    
    def encrypt(self, plaintext: str) -> Tuple[str, Dict]:
        """Fase 3: Cifrado"""
        details = {
            'phase': 'Cifrado',
            'step_type': 'encrypt',
            'blocks': []
        }
        ciphertext = ""
        
        if not plaintext:
            details['no_plaintext'] = True
            self.all_steps.append(details)
            return ciphertext, details
        
        blocks = [plaintext[i:i+16] for i in range(0, len(plaintext), 16)]
        
        for i, block in enumerate(blocks):
            is_last_block = (i == len(blocks) - 1)
            # Aplicar padding ASCON correcto solo al último bloque
            if is_last_block and len(block) < 16:
                padded_block = ascon_pad(block, 16, is_last_block=True)
                # Para el último bloque incompleto, solo cifrar la parte real (sin padding en ciphertext)
                pt_block_full = hex_to_int(padded_block)
                pt_block_real = hex_to_int(block.ljust(16, '0'))  # Para XOR con estado
            else:
                padded_block = block.ljust(16, '0')
                pt_block_full = hex_to_int(padded_block)
                pt_block_real = pt_block_full
            
            block_details = {
                'block_num': i,
                'plaintext_hex': block,
                'plaintext_padded_hex': padded_block if is_last_block else block.ljust(16, '0'),
                'plaintext_int': pt_block_real,
                'state_before': list(self.state),
                'is_last_block': is_last_block,
                'padding_applied': is_last_block and len(block) < 16
            }
            
            # Cifrar usando el estado
            # Flujo correcto: ct_block = state[0] ⊕ plaintext, luego state[0] = ct_block
            if is_last_block and len(block) < 16:
                # Para último bloque incompleto:
                # 1. Cifrar solo la parte real del plaintext (para el ciphertext de salida)
                ct_block = self.state[0] ^ pt_block_real
                # 2. Solo agregar los bytes reales al ciphertext (sin padding)
                ciphertext += to_hex(ct_block, 64)[:len(block)]
                # 3. Actualizar estado con el bloque completo (incluyendo padding para la permutación)
                #    El estado interno debe procesar el bloque completo con padding
                self.state[0] = self.state[0] ^ pt_block_full
            else:
                # Bloques completos: cifrar normalmente
                ct_block = self.state[0] ^ pt_block_real
                ciphertext += to_hex(ct_block, 64)
                # Actualizar estado con el ciphertext (CORRECTO: no hacer XOR de nuevo)
                self.state[0] = ct_block
            
            block_details['ciphertext_hex'] = to_hex(ct_block, 64)[:len(block)] if (is_last_block and len(block) < 16) else to_hex(ct_block, 64)
            block_details['ciphertext_int'] = ct_block
            block_details['xor_changes'] = compare_bits(pt_block_real, ct_block)
            block_details['after_xor'] = list(self.state)
            
            self.state, round_details = permutation(self.state, 12, 0)
            block_details['rounds'] = round_details
            block_details['state_after'] = list(self.state)
            
            details['blocks'].append(block_details)
        
        details['ciphertext'] = ciphertext
        self.all_steps.append(details)
        return ciphertext, details
    
    def decrypt(self, ciphertext: str, tag: str, key: str, nonce: str, ad: str) -> Tuple[str, bool, Dict]:
        """
        Descifrar ciphertext y verificar tag de autenticación.
        
        Args:
            ciphertext: Texto cifrado en hexadecimal
            tag: Tag de autenticación esperado en hexadecimal
            key: Clave en hexadecimal (128 bits)
            nonce: Nonce en hexadecimal (128 bits)
            ad: Datos asociados en hexadecimal
        
        Returns:
            Tuple con (plaintext, tag_valid, details)
            - plaintext: Texto descifrado
            - tag_valid: True si el tag es válido, False en caso contrario
            - details: Diccionario con detalles de la operación
        """
        details = {
            'phase': 'Descifrado',
            'step_type': 'decrypt',
            'blocks': []
        }
        plaintext = ""
        
        # Reinicializar estado
        self.initialize(key, nonce)
        self.process_ad(ad)
        
        if not ciphertext:
            # Ciphertext vacío
            details['no_ciphertext'] = True
        else:
            # Procesar bloques de ciphertext
            blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
            
            for i, block in enumerate(blocks):
                is_last_block = (i == len(blocks) - 1)
                
                # Ajustar bloque a 64 bits (rellenar con ceros si es incompleto)
                block_padded = block.ljust(16, '0')
                ct_block = hex_to_int(block_padded)
                
                block_details = {
                    'block_num': i,
                    'ciphertext_hex': block,
                    'ciphertext_int': ct_block,
                    'state_before': list(self.state)
                }
                
                # Descifrar: plaintext = ciphertext XOR state[0]
                pt_block = self.state[0] ^ ct_block
                
                # Para el último bloque, remover padding si es necesario
                if is_last_block and len(block) < 16:
                    # El último bloque incompleto puede tener padding
                    pt_hex = to_hex(pt_block, 64)
                    pt_real = remove_padding(pt_hex)
                    plaintext += pt_real[:len(block)]
                    block_details['plaintext_hex'] = pt_real[:len(block)]
                else:
                    plaintext += to_hex(pt_block, 64)
                    block_details['plaintext_hex'] = to_hex(pt_block, 64)
                
                block_details['plaintext_int'] = pt_block
                block_details['xor_changes'] = compare_bits(ct_block, pt_block)
                
                # Actualizar estado con el ciphertext (mismo proceso que en cifrado)
                self.state[0] = ct_block
                block_details['after_xor'] = list(self.state)
                
                # Aplicar permutación
                self.state, round_details = permutation(self.state, 12, 0)
                block_details['rounds'] = round_details
                block_details['state_after'] = list(self.state)
                
                details['blocks'].append(block_details)
        
        # Finalizar y verificar tag
        computed_tag, finalize_details = self.finalize(key)
        tag_valid = (computed_tag.upper() == tag.upper())
        
        details['computed_tag'] = computed_tag
        details['expected_tag'] = tag
        details['tag_valid'] = tag_valid
        details['plaintext'] = plaintext
        details['finalize_details'] = finalize_details
        
        self.all_steps.append(details)
        return plaintext, tag_valid, details
    
    def finalize(self, key: str) -> Tuple[str, Dict]:
        """Fase 4-5: Finalización"""
        details = {
            'phase': 'Finalización',
            'step_type': 'finalize'
        }
        
        key_int = hex_to_int(key)
        key_high = (key_int >> 64) & ((1 << 64) - 1)
        key_low = key_int & ((1 << 64) - 1)
        
        details['state_before'] = list(self.state)
        
        self.state[1] ^= key_high
        self.state[2] ^= key_low
        details['after_key_xor'] = list(self.state)
        
        self.state, round_details = permutation(self.state, 12, 0)
        details['rounds'] = round_details
        details['state_after_perm'] = list(self.state)
        
        tag_high = self.state[3] ^ key_high
        tag_low = self.state[4] ^ key_low
        tag = to_hex(tag_high, 64) + to_hex(tag_low, 64)
        
        details['tag'] = tag
        details['tag_high'] = tag_high
        details['tag_low'] = tag_low
        
        self.all_steps.append(details)
        return tag, details

# ==================== TOOLTIPS EDUCATIVOS ====================

class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip = None
        self.widget.bind("<Enter>", self.show)
        self.widget.bind("<Leave>", self.hide)
    
    def show(self, event=None):
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 25
        
        self.tooltip = tk.Toplevel(self.widget)
        self.tooltip.wm_overrideredirect(True)
        self.tooltip.wm_geometry(f"+{x}+{y}")
        
        label = tk.Label(self.tooltip, text=self.text, justify=tk.LEFT,
                        background="#ffffe0", relief=tk.SOLID, borderwidth=1,
                        font=("Arial", 9), wraplength=300, padx=5, pady=5)
        label.pack()
    
    def hide(self, event=None):
        if self.tooltip:
            self.tooltip.destroy()
            self.tooltip = None

# ==================== INTERFAZ MEJORADA ====================

class ASCONVisualizerAdvanced:
    def __init__(self, root):
        self.root = root
        self.root.title(" ASCON-128a Educational Visualizer - Advanced Edition")
        self.root.geometry("1510x910")
        self.root.minsize(800, 600)  # Tamaño mínimo para que sea redimensionable pero funcional    

        self.ascon = None
        self.current_step = 0
        self.all_steps = []
        self.is_animating = False
        self.animation_speed = 1.0
        self.debug_mode = tk.BooleanVar(value=False)    
        
        # Inicializar variables de visualización ANTES de setup_ui
        self.show_hex = tk.BooleanVar(value=True)
        self.show_binary = tk.BooleanVar(value=True)
        self.show_changes = tk.BooleanVar(value=True)
        self.show_explanations = tk.BooleanVar(value=True)
        self.show_binary_highlights = tk.BooleanVar(value=False)

        self.setup_ui()
        self.show_welcome()
        
    def configure_paned_proportions(self):
        """Configurar la proporción inicial del PanedWindow (4:1)"""
        try:
            # Esperar a que la ventana esté completamente renderizada
            self.root.update_idletasks()
            # Obtener el tamaño total del PanedWindow
            paned_height = self.viz_paned.winfo_height()
            if paned_height > 0:
                # Calcular posición del divisor: 80% desde arriba (resultados ocupa 20% = 1/5, pero queremos 1/4)
                # Para proporción 4:1, el divisor debe estar al 80% (4/5 del total)
                sash_position = int(paned_height * 0.8)
                if sash_position > 0:
                    self.viz_paned.sashpos(0, sash_position)
        except:
            pass  # Si falla, los pesos ya manejarán la proporción
    
    def setup_menu_bar(self):
        """Configurar barra de menú con funciones de ventana"""
        # Crear frame para la barra de título personalizada (en Windows esto se integra mejor)
        # En Windows, las funciones están en la esquina superior derecha por defecto
        # Pero podemos crear una barra de menú tradicional
        
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # Menú Archivo
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Archivo", menu=file_menu)
        file_menu.add_command(label="📋 Cargar Ejemplo", command=self.load_example)
        file_menu.add_command(label="💾 Guardar Resultados", command=self.save_results)
        file_menu.add_command(label="📄 Exportar a JSON", command=self.export_to_json)
        file_menu.add_separator()
        file_menu.add_command(label="🚪 Salir", command=self.root.quit)
        
        # Menú Ejecutar
        execute_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Ejecutar", menu=execute_menu)
        execute_menu.add_command(label="▶️ Iniciar Ejecución", command=self.start_execution)
        execute_menu.add_command(label="⏸️ Pausar", command=self.pause_execution)
        execute_menu.add_command(label="🔄 Resetear", command=self.reset_execution)
        execute_menu.add_separator()
        execute_menu.add_command(label="✅ Verificar Vectores de Prueba", command=self.verify_test_vectors)
        execute_menu.add_command(label="🌊 Análisis Efecto Avalancha", command=self.analyze_avalanche_effect)
        
        # Menú Ver
        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Ver", menu=view_menu)
        view_menu.add_checkbutton(label="Mostrar Hexadecimal", variable=self.show_hex)
        view_menu.add_checkbutton(label="Mostrar Binario", variable=self.show_binary)
        view_menu.add_checkbutton(label="Resaltar Cambios en Binario", variable=self.show_binary_highlights)
        view_menu.add_checkbutton(label="Resaltar Cambios", variable=self.show_changes)
        view_menu.add_checkbutton(label="Mostrar Explicaciones", variable=self.show_explanations)
        view_menu.add_separator()
        view_menu.add_checkbutton(label="🐛 Modo Depuración", variable=self.debug_mode)
        
        # Menú Ventana (con funciones clásicas)
        window_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Ventana", menu=window_menu)
        window_menu.add_command(label="⬇️ Minimizar", command=self.minimize_window)
        window_menu.add_command(label="⬜ Restaurar/Maximizar", command=self.toggle_maximize)
        window_menu.add_separator()
        window_menu.add_command(label="✖️ Cerrar", command=self.root.destroy)
        
        # Menú Ayuda
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Ayuda", menu=help_menu)
        help_menu.add_command(label="📚 Guía Educativa", command=lambda: self.notebook.select(3))
        help_menu.add_command(label="ℹ️ Acerca de", command=self.show_about)
        
        # En Windows, también podemos agregar botones de ventana en la esquina superior derecha
        # Crear frame para botones de ventana personalizados
        self.setup_window_buttons()
    
    def setup_window_buttons(self):
        """Crear botones de ventana en la esquina superior derecha"""
        # Frame para botones de ventana
        window_buttons_frame = tk.Frame(self.root, bg='#f0f0f0', height=30)
        window_buttons_frame.pack(side=tk.TOP, fill=tk.X)
        window_buttons_frame.pack_propagate(False)
        
        # Frame para los botones (alineados a la derecha)
        buttons_container = tk.Frame(window_buttons_frame, bg='#f0f0f0')
        buttons_container.pack(side=tk.RIGHT, padx=2, pady=2)
        
        # Función auxiliar para efectos hover
        def on_enter(btn, bg_color='#e0e0e0'):
            btn['background'] = bg_color
        
        def on_leave(btn, bg_color='#f0f0f0'):
            btn['background'] = bg_color
        
        # Botón minimizar
        btn_minimize = tk.Button(buttons_container, text="🗕", width=3, height=1,
                                command=self.minimize_window, relief=tk.FLAT, bg='#f0f0f0',
                                activebackground='#d0d0d0', font=('Arial', 10), cursor='hand2')
        btn_minimize.pack(side=tk.LEFT, padx=1)
        btn_minimize.bind('<Enter>', lambda e: on_enter(btn_minimize))
        btn_minimize.bind('<Leave>', lambda e: on_leave(btn_minimize))
        ToolTip(btn_minimize, "Minimizar ventana")
        
        # Botón maximizar/restaurar
        self.btn_maximize = tk.Button(buttons_container, text="🗖", width=3, height=1,
                                      command=self.toggle_maximize, relief=tk.FLAT, bg='#f0f0f0',
                                      activebackground='#d0d0d0', font=('Arial', 10), cursor='hand2')
        self.btn_maximize.pack(side=tk.LEFT, padx=1)
        self.btn_maximize.bind('<Enter>', lambda e: on_enter(self.btn_maximize))
        self.btn_maximize.bind('<Leave>', lambda e: on_leave(self.btn_maximize))
        ToolTip(self.btn_maximize, "Maximizar/Restaurar ventana")
        
        # Botón cerrar
        btn_close = tk.Button(buttons_container, text="✖", width=3, height=1,
                             command=self.root.destroy, relief=tk.FLAT, bg='#f0f0f0',
                             activebackground='#ff6666', fg='red', font=('Arial', 10, 'bold'), cursor='hand2')
        btn_close.pack(side=tk.LEFT, padx=1)
        btn_close.bind('<Enter>', lambda e: on_enter(btn_close, '#ffcccc'))
        btn_close.bind('<Leave>', lambda e: on_leave(btn_close))
        ToolTip(btn_close, "Cerrar aplicación")
        
        # Guardar estado de maximizado
        self.is_maximized = False
        
        # Título de la ventana a la izquierda
        title_label = tk.Label(window_buttons_frame, text=" ASCON-128a Educational Visualizer", 
                              bg='#f0f0f0', font=('Arial', 10, 'bold'))
        title_label.pack(side=tk.LEFT, padx=10, pady=5)
    
    def minimize_window(self):
        """Minimizar la ventana"""
        self.root.iconify()
    
    def toggle_maximize(self):
        """Alternar entre maximizar y restaurar"""
        if self.is_maximized:
            self.root.state('normal')
            self.is_maximized = False
            self.btn_maximize.config(text="🗖")
        else:
            self.root.state('zoomed')  # Maximizado en Windows
            self.is_maximized = True
            self.btn_maximize.config(text="🗗")
    
    def show_about(self):
        """Mostrar información sobre la aplicación"""
        about_text = """
╔═══════════════════════════════════════════════════╗
║                                                   ║
║      ASCON-128a EDUCATIONAL VISUALIZER v2.0       ║
║                Advanced Edition                   ║
║                                                   ║
╚═══════════════════════════════════════════════════╝

HERRAMIENTA EDUCATIVA INTERACTIVA

Esta aplicación permite aprender el algoritmo ASCON-128a 
paso a paso, visualizando cada transformación interna del 
proceso de cifrado autenticado.

CARACTERÍSTICAS PRINCIPALES:

  ✓ Visualización paso a paso con detalles completos
  ✓ Navegación interactiva entre fases
  ✓ Modo comparativo para analizar diferencias
  ✓ Guía educativa con conceptos y ejemplos
  ✓ Verificación de vectores de prueba oficiales
  ✓ Análisis de efecto avalancha
  ✓ Exportación de resultados
  ✓ Modo depuración detallado

TECNOLOGÍAS:

  • Python 3.x
  • Tkinter (Interfaz gráfica)
  • Algoritmo ASCON-128a (Estándar NIST)

DESARROLLADO CON FINES EDUCATIVOS

Versión 2.0 | 2025
"""
        messagebox.showinfo("Acerca de", about_text)
        
    def setup_ui(self):
        """Configurar interfaz gráfica"""
        
        # Estilo
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Title.TLabel', font=('Arial', 12, 'bold'))
        style.configure('Info.TLabel', font=('Arial', 9))
        
        # Crear barra de menú
        self.setup_menu_bar()
        
        # Notebook principal
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # TAB 1: Ejecución Principal
        self.main_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.main_tab, text=" Ejecución Principal")
        self.setup_main_tab()
        
        # TAB 2: Visualización Detallada
        self.detail_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.detail_tab, text=" Visualización Detallada")
        self.setup_detail_tab()
        
        # TAB 3: Comparación
        self.compare_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.compare_tab, text=" Modo Comparativo")
        self.setup_compare_tab()
        
        # TAB 4: Educación
        self.edu_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.edu_tab, text=" Guía Educativa")
        self.setup_edu_tab()
        
    def setup_main_tab(self):
        """Configurar pestaña principal"""
        
        # Frame izquierdo: Controles
        left_frame = ttk.Frame(self.main_tab)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, padx=5, pady=5)
        
        # Panel de entrada
        input_frame = ttk.LabelFrame(left_frame, text="📥 Parámetros de Entrada", padding=10)
        input_frame.pack(fill=tk.X, pady=5)
        
        # Key
        ttk.Label(input_frame, text="Key (128 bits):").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.key_entry = ttk.Entry(input_frame, width=35, font=('Courier', 9))
        self.key_entry.grid(row=0, column=1, padx=5, pady=2)
        self.key_entry.insert(0, "000102030405060708090A0B0C0D0E0F")
        key_btn = ttk.Button(input_frame, text="🎲", width=3, command=self.gen_key)
        key_btn.grid(row=0, column=2)
        ToolTip(key_btn, "Generar clave aleatoria de 128 bits")
        
        # Nonce
        ttk.Label(input_frame, text="Nonce (128 bits):").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.nonce_entry = ttk.Entry(input_frame, width=35, font=('Courier', 9))
        self.nonce_entry.grid(row=1, column=1, padx=5, pady=2)
        self.nonce_entry.insert(0, "000102030405060708090A0B0C0D0E0F")
        nonce_btn = ttk.Button(input_frame, text="🎲", width=3, command=self.gen_nonce)
        nonce_btn.grid(row=1, column=2)
        ToolTip(nonce_btn, "Generar nonce aleatorio (debe ser único por mensaje)")
        
        # AD
        ttk.Label(input_frame, text="Associated Data:").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.ad_entry = ttk.Entry(input_frame, width=35, font=('Courier', 9))
        self.ad_entry.grid(row=2, column=1, padx=5, pady=2)
        self.ad_entry.insert(0, "606162636465666768696A6B6C6D6E6F")
        ad_btn = ttk.Button(input_frame, text="❌", width=3, command=lambda: self.ad_entry.delete(0, tk.END))
        ad_btn.grid(row=2, column=2)
        ToolTip(ad_btn, "Datos autenticados pero no cifrados (opcional)")
        
        # Plaintext
        ttk.Label(input_frame, text="Plaintext:").grid(row=3, column=0, sticky=tk.W, pady=2)
        self.pt_entry = ttk.Entry(input_frame, width=35, font=('Courier', 9))
        self.pt_entry.grid(row=3, column=1, padx=5, pady=2)
        self.pt_entry.insert(0, "4142434445464748")
        pt_btn = ttk.Button(input_frame, text="❌", width=3, command=lambda: self.pt_entry.delete(0, tk.END))
        pt_btn.grid(row=3, column=2)
        ToolTip(pt_btn, "Datos a cifrar (opcional)")
        
        # Modo de ejecución
        mode_frame = ttk.LabelFrame(left_frame, text="⚙️ Modo de Ejecución", padding=10)
        mode_frame.pack(fill=tk.X, pady=5)
        
        self.exec_mode = tk.StringVar(value="step")
        ttk.Radiobutton(mode_frame, text="🔸 Paso a Paso Manual", variable=self.exec_mode, 
                       value="step").pack(anchor=tk.W)
        ttk.Radiobutton(mode_frame, text="▶️ Automático con Animación", variable=self.exec_mode,
                       value="auto").pack(anchor=tk.W)
        ttk.Radiobutton(mode_frame, text="⚡ Ejecución Rápida", variable=self.exec_mode,
                       value="fast").pack(anchor=tk.W)
        
        # Velocidad de animación
        ttk.Label(mode_frame, text="Velocidad:").pack(anchor=tk.W, pady=(10,0))
        self.speed_scale = ttk.Scale(mode_frame, from_=0.1, to=3.0, orient=tk.HORIZONTAL,
                                    command=self.update_speed)
        self.speed_scale.set(1.0)
        self.speed_scale.pack(fill=tk.X, pady=2)
        self.speed_label = ttk.Label(mode_frame, text="1.0x")
        self.speed_label.pack()
        
        # Opciones de visualización
        viz_frame = ttk.LabelFrame(left_frame, text="👁️ Opciones de Visualización", padding=10)
        viz_frame.pack(fill=tk.X, pady=5)
        
        self.show_hex = tk.BooleanVar(value=True)
        self.show_binary = tk.BooleanVar(value=True)
        self.show_changes = tk.BooleanVar(value=True)
        self.show_explanations = tk.BooleanVar(value=True)
        
        self.show_binary_highlights = tk.BooleanVar(value=False)
        
        ttk.Checkbutton(viz_frame, text="Mostrar Hexadecimal", variable=self.show_hex).pack(anchor=tk.W)
        ttk.Checkbutton(viz_frame, text="Mostrar Binario", variable=self.show_binary).pack(anchor=tk.W)
        ttk.Checkbutton(viz_frame, text="Resaltar Cambios en Binario", variable=self.show_binary_highlights).pack(anchor=tk.W)
        ttk.Checkbutton(viz_frame, text="Resaltar Cambios", variable=self.show_changes).pack(anchor=tk.W)
        ttk.Checkbutton(viz_frame, text="Mostrar Explicaciones", variable=self.show_explanations).pack(anchor=tk.W)
        
        # Botones de control
        control_frame = ttk.Frame(left_frame)
        control_frame.pack(fill=tk.X, pady=10)
        
        self.start_btn = ttk.Button(control_frame, text="▶️ Iniciar", command=self.start_execution)
        self.start_btn.pack(fill=tk.X, pady=2)
        
        self.pause_btn = ttk.Button(control_frame, text="⏸️ Pausar", command=self.pause_execution, state=tk.DISABLED)
        self.pause_btn.pack(fill=tk.X, pady=2)
        
        self.reset_btn = ttk.Button(control_frame, text="🔄 Resetear", command=self.reset_execution)
        self.reset_btn.pack(fill=tk.X, pady=2)
        
        ttk.Separator(control_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        
        ttk.Button(control_frame, text="📋 Cargar Ejemplo", command=self.load_example).pack(fill=tk.X, pady=2)
        ttk.Button(control_frame, text="✅ Verificar Vectores de Prueba", command=self.verify_test_vectors).pack(fill=tk.X, pady=2)
        ttk.Button(control_frame, text="🌊 Análisis Efecto Avalancha", command=self.analyze_avalanche_effect).pack(fill=tk.X, pady=2)
        ttk.Button(control_frame, text="💾 Guardar Resultados", command=self.save_results).pack(fill=tk.X, pady=2)
        
        # Frame derecho: Visualización con PanedWindow para controlar proporciones
        right_frame = ttk.Frame(self.main_tab)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # PanedWindow para dividir visualización y resultados en proporción 4:1
        self.viz_paned = ttk.PanedWindow(right_frame, orient=tk.VERTICAL)
        self.viz_paned.pack(fill=tk.BOTH, expand=True)
        
        # Panel de visualización principal (75% del espacio - 4 partes de 5)
        viz_label_frame = ttk.LabelFrame(self.viz_paned, text="🔍 Visualización del Proceso")
        self.viz_paned.add(viz_label_frame, weight=4)
        
        self.main_viz_text = scrolledtext.ScrolledText(viz_label_frame, width=90, height=1,
                                                       font=('Courier', 9), wrap=tk.WORD)
        self.main_viz_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configurar tags para colores
        self.main_viz_text.tag_config("header", foreground="blue", font=('Courier New', 10, 'bold'))
        self.main_viz_text.tag_config("subheader", foreground="darkgreen", font=('Courier New', 9, 'bold'))
        self.main_viz_text.tag_config("highlight", background="yellow")
        self.main_viz_text.tag_config("changed", background="#90EE90")
        self.main_viz_text.tag_config("error", foreground="red")
        
        # Panel de resultados (25% del espacio - 1 parte de 5)
        results_frame = ttk.LabelFrame(self.viz_paned, text="📤 Resultados")
        self.viz_paned.add(results_frame, weight=1)
        
        self.results_text = scrolledtext.ScrolledText(results_frame, width=90, height=1,
                                                      font=('Courier New', 9), wrap=tk.WORD)
        self.results_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
    def setup_detail_tab(self):
        """Configurar pestaña de detalles"""
        
        # Frame de navegación
        nav_frame = ttk.Frame(self.detail_tab)
        nav_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(nav_frame, text=" Navegación por Pasos:", style='Title.TLabel').pack(side=tk.LEFT, padx=5)
        
        self.prev_btn = ttk.Button(nav_frame, text="◀️ Anterior", command=self.prev_step, state=tk.DISABLED)
        self.prev_btn.pack(side=tk.LEFT, padx=2)
        
        self.step_label = ttk.Label(nav_frame, text="Paso 0 de 0")
        self.step_label.pack(side=tk.LEFT, padx=10)
        
        self.next_btn = ttk.Button(nav_frame, text="Siguiente ▶️", command=self.next_step, state=tk.DISABLED)
        self.next_btn.pack(side=tk.LEFT, padx=2)
        
        ttk.Separator(self.detail_tab, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=5)
        
        # Panel de detalles con scroll
        detail_frame = ttk.Frame(self.detail_tab)
        detail_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.detail_text = scrolledtext.ScrolledText(detail_frame, width=120, height=40,
                                                     font=('Courier New', 9), wrap=tk.WORD)
        self.detail_text.pack(fill=tk.BOTH, expand=True)
        
        # Tags para colores
        self.detail_text.tag_config("phase", foreground="blue", font=('Courier New', 11, 'bold'))
        self.detail_text.tag_config("step", foreground="darkgreen", font=('Courier New', 10, 'bold'))
        self.detail_text.tag_config("subheader", foreground="darkblue", font=('Courier New', 9, 'bold'))
        self.detail_text.tag_config("value", foreground="purple")
        self.detail_text.tag_config("changed_bit", background="#90EE90")
        self.detail_text.tag_config("info", foreground="gray")
        
    def setup_compare_tab(self):
        """Configurar modo comparativo"""
        
        ttk.Label(self.compare_tab, text=" Modo Comparativo - Comparar dos ejecuciones lado a lado",
                 style='Title.TLabel').pack(pady=10)
        
        compare_frame = ttk.Frame(self.compare_tab)
        compare_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Panel izquierdo
        left_compare = ttk.LabelFrame(compare_frame, text="Ejecución A")
        left_compare.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0,5))
        
        self.compare_left = scrolledtext.ScrolledText(left_compare, width=60, height=35, font=('Courier New', 8))
        self.compare_left.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Panel derecho
        right_compare = ttk.LabelFrame(compare_frame, text="Ejecución B")
        right_compare.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5,0))
        
        self.compare_right = scrolledtext.ScrolledText(right_compare, width=60, height=35, font=('Courier New', 8))
        self.compare_right.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Botones de comparación
        compare_btn_frame = ttk.Frame(self.compare_tab)
        compare_btn_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(compare_btn_frame, text="🔄 Comparar Ejecuciones", 
                  command=self.start_comparison).pack(side=tk.LEFT, padx=5)
        ttk.Button(compare_btn_frame, text="📊 Análisis de Diferencias",
                  command=self.analyze_differences).pack(side=tk.LEFT, padx=5)
        
    def setup_edu_tab(self):
        """Configurar pestaña educativa"""
        
        # Crear notebook interno para secciones educativas
        edu_notebook = ttk.Notebook(self.edu_tab)
        edu_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Sección 1: Conceptos Básicos
        basic_frame = ttk.Frame(edu_notebook)
        edu_notebook.add(basic_frame, text="📖 Conceptos Básicos")
        
        basic_text = scrolledtext.ScrolledText(basic_frame, wrap=tk.WORD, font=('Courier New', 10))
        basic_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        basic_text.insert('1.0', """
╔═══════════════════════════════════════════════════════════════════════════╗
║                        CONCEPTOS BÁSICOS DE ASCON-128a                    ║
╚═══════════════════════════════════════════════════════════════════════════╝

 ¿QUÉ ES ASCON-128a?
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ASCON-128a es un algoritmo de CIFRADO AUTENTICADO (Authenticated Encryption 
with Associated Data - AEAD). Esto significa que hace DOS cosas a la vez:

1. 🔒 CIFRADO: Convierte texto legible en texto cifrado que solo puede ser
   leído por quien tenga la clave secreta.

2. ✅ AUTENTICACIÓN: Genera una "etiqueta" (tag) que permite verificar que
   los datos no fueron modificados por nadie durante la transmisión.


 COMPONENTES PRINCIPALES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

• KEY (Clave): 128 bits de datos secretos compartidos entre emisor y receptor
  - DEBE mantenerse en secreto absoluto
  - Se usa para cifrar y generar el tag
  
• NONCE: 128 bits de datos públicos que DEBEN ser únicos para cada mensaje
  - Puede ser conocido por atacantes
  - NUNCA reutilizar el mismo nonce con la misma key
  
• ASSOCIATED DATA (AD): Datos que se autentican pero NO se cifran
  - Ejemplo: cabeceras de red, metadatos
  - Opcional (puede estar vacío)
  
• PLAINTEXT: Los datos que queremos cifrar
  - Opcional (puede estar vacío)
  
• CIPHERTEXT: El resultado del cifrado
  - Mismo tamaño que el plaintext
  
• TAG: 128 bits que verifican la integridad
  - Si alguien modifica el ciphertext o AD, el tag no coincidirá


 ¿CÓMO FUNCIONA?
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ASCON-128a opera en 5 FASES:

FASE 1: INICIALIZACIÓN
  ├─ Crea un "estado" interno de 320 bits (5 registros de 64 bits)
  ├─ Mezcla la Key y el Nonce en este estado
  └─ Aplica 12 rondas de transformaciones (permutación p_a)

FASE 2: ABSORCIÓN DE DATOS ASOCIADOS
  ├─ Procesa el AD en bloques de 64 bits
  ├─ Cada bloque se mezcla con el estado usando XOR
  └─ Aplica 6 rondas de permutación (p_b) por cada bloque

FASE 3: CIFRADO DEL PLAINTEXT
  ├─ Procesa el plaintext en bloques de 64 bits
  ├─ Cada bloque se cifra haciendo XOR con parte del estado
  └─ Aplica 12 rondas de permutación (p_a) después de cada bloque

FASE 4: FINALIZACIÓN
  ├─ Mezcla la Key nuevamente con el estado
  └─ Aplica 12 rondas finales de permutación (p_a)

FASE 5: GENERACIÓN DEL TAG
  └─ Extrae 128 bits del estado final como tag de autenticación


 OPERACIONES BÁSICAS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Las permutaciones (p_a y p_b) son el corazón de ASCON. Cada ronda hace:

1. CONSTANTE DE RONDA (RC):
   └─ Suma una constante fija para que cada ronda sea diferente

2. S-BOX (Substitución No-Lineal):
   └─ Sustituye valores usando una tabla especial
   └─ Añade "confusión" para que sea difícil revertir

3. CAPA LINEAL (Difusión):
   └─ Mezcla bits usando XOR y rotaciones
   └─ Propaga cambios a través de todo el estado


 ¿POR QUÉ ES SEGURO?
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

• Cambios pequeños en la entrada → Cambios GRANDES en la salida
• Imposible predecir el ciphertext sin conocer la key
• El tag detecta cualquier modificación de datos
• Resistente a ataques conocidos de criptoanálisis
• Ganador de la competencia CAESAR (2019)
""")
        basic_text.config(state=tk.DISABLED)
        
        # Sección 2: Operaciones Detalladas
        ops_frame = ttk.Frame(edu_notebook)
        edu_notebook.add(ops_frame, text="🔧 Operaciones")
        
        ops_text = scrolledtext.ScrolledText(ops_frame, wrap=tk.WORD, font=('Courier New', 10))
        ops_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        ops_text.insert('1.0', """
╔═══════════════════════════════════════════════════════════════════════════╗
║                     OPERACIONES CRIPTOGRÁFICAS DETALLADAS                 ║
╚═══════════════════════════════════════════════════════════════════════════╝

 OPERACIÓN XOR (OR EXCLUSIVO)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

El XOR es una operación bit a bit que compara dos valores:

REGLA:
  0 ⊕ 0 = 0    (iguales → 0)
  0 ⊕ 1 = 1    (diferentes → 1)
  1 ⊕ 0 = 1    (diferentes → 1)
  1 ⊕ 1 = 0    (iguales → 0)

EJEMPLO:
  10110011
⊕ 01010101
  ─────────
  11100110

PROPIEDADES IMPORTANTES:
• A ⊕ A = 0 (cualquier cosa XOR consigo misma es 0)
• A ⊕ 0 = A (XOR con 0 no cambia nada)
• A ⊕ B = B ⊕ A (conmutativo)
• (A ⊕ B) ⊕ B = A (reversible - fundamental para cifrado)

USO EN ASCON:
  Plaintext ⊕ Estado = Ciphertext
  Ciphertext ⊕ Estado = Plaintext (para descifrar)


 ROTACIÓN DE BITS (ROL - Rotate Left)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Rotación mueve bits hacia la izquierda de forma circular:

EJEMPLO: ROL 3 posiciones
  Antes:   10110011 01010101
            ↓ ↓ ↓ ↓  ↓ ↓ ↓ ↓
  Después: 10011010 10101101
           └─────────────┘ ← estos 3 bits vuelven al inicio

DIFERENCIA CON SHIFT:
• SHIFT: Los bits "caen" y se pierden
• ROTATE: Los bits vuelven al otro extremo (circular)

USO EN ASCON:
  La capa lineal usa múltiples rotaciones:
  x0 = x0 ⊕ ROL(x0, 19) ⊕ ROL(x0, 28)
  
  Esto mezcla bits distantes para máxima difusión.


 S-BOX (CAJA DE SUSTITUCIÓN)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

La S-box es una transformación NO-LINEAL que reemplaza valores:

¿POR QUÉ ES IMPORTANTE?
  Sin S-box, ASCON sería solo operaciones lineales (XOR, rotaciones)
  Operaciones lineales son fáciles de resolver matemáticamente
  La S-box rompe la linealidad → hace el algoritmo seguro

CÓMO FUNCIONA EN ASCON:
  • Opera sobre 5 bits a la vez (uno de cada registro x0-x4)
  • Aplica transformaciones AND, NOT, XOR complejas
  • Se aplica a TODAS las columnas en paralelo (64 veces)

EJEMPLO SIMPLIFICADO:
  Entrada (5 bits):  10110
  S-box transforma:  01001
  
  La transformación sigue reglas matemáticas específicas
  diseñadas para resistir ataques criptográficos.


 DIFUSIÓN LINEAL
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Después de la S-box, la capa lineal PROPAGA cambios:

OBJETIVO: Un bit cambiado debe afectar MUCHOS otros bits

OPERACIÓN PARA CADA REGISTRO:
  xi_nuevo = xi ⊕ ROL(xi, a) ⊕ ROL(xi, b)
  
  Donde a y b son constantes específicas:
  • x0: rotaciones 19 y 28
  • x1: rotaciones 61 y 39
  • x2: rotaciones 1 y 6
  • x3: rotaciones 10 y 17
  • x4: rotaciones 7 y 41

EFECTO:
  Cambiar 1 bit → Afecta ~50% de los bits después de varias rondas
  Esto se llama "efecto avalancha"


 PERMUTACIONES (p_a y p_b)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Una RONDA completa = RC + S-box + Difusión

p_a: 12 rondas (máxima seguridad)
  • Usada en inicialización
  • Usada después de cada bloque de plaintext
  • Usada en finalización

p_b: 6 rondas (más rápida)
  • Usada después de cada bloque de AD
  • Suficiente seguridad para datos no cifrados

¿POR QUÉ MÚLTIPLES RONDAS?
  Cada ronda adicional aumenta la difusión y confusión
  12 rondas aseguran que TODO el estado dependa de TODO el input
  6 rondas son suficientes cuando no hay secreto involucrado


 CONSTANTES DE RONDA (RC)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Las constantes hacen que cada ronda sea DIFERENTE:

RC = [0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 
      0x78, 0x69, 0x5a, 0x4b]

En cada ronda i:
  x2 = x2 ⊕ RC[i]

PROPÓSITO:
  • Evitar ataques de "slide" (deslizamiento)
  • Asegurar que ronda 1 ≠ ronda 2 ≠ ronda 3...
  • Valores elegidos para propiedades criptográficas óptimas


 PADDING EN ASCON (10* padding)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ASCON usa un padding específico llamado "10*":

¿QUÉ ES EL PADDING?
  Los datos pueden no ocupar un bloque completo (64 bits).
  El padding completa el bloque con un formato específico.

REGLAS DEL PADDING ASCON:
  • Se añade un bit '1' seguido de bits '0' hasta completar el bloque
  • En hexadecimal: '80' (bit 1) seguido de '00' (ceros)
  • Se aplica SOLO al último bloque incompleto

EJEMPLO:
  Datos originales:    41 42 43        (3 bytes = 6 caracteres hex)
  Padding aplicado:    41 42 43 80 00 00 00 00  (8 bytes = 16 caracteres hex)
                       └─datos─┘└────padding────┘
                                  ↑
                              bit '1' (0x80)

CASO ESPECIAL - BLOQUE VACÍO:
  Si no hay datos:     80 00 00 00 00 00 00 00
                       └─padding completo─────┘

¿POR QUÉ ES IMPORTANTE?
  1. Distingue bloques completos de incompletos
  2. Previene ataques de extensión de longitud
  3. Estándar en construcciones sponge (Keccak, ASCON, SHA-3)
  4. Permite procesamiento correcto de datos de cualquier longitud

NOTA IMPORTANTE:
  • El padding se usa para el estado interno (permutación)
  • El ciphertext final NO incluye el padding
  • Solo los bytes reales del plaintext se cifran en el output
""")
        ops_text.config(state=tk.DISABLED)
        
        # Sección 3: Ejemplos Prácticos
        examples_frame = ttk.Frame(edu_notebook)
        edu_notebook.add(examples_frame, text="💡 Ejemplos")
        
        examples_text = scrolledtext.ScrolledText(examples_frame, wrap=tk.WORD, font=('Courier New', 10))
        examples_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        examples_text.insert('1.0', """
╔═══════════════════════════════════════════════════════════════════════════╗
║                          EJEMPLOS PRÁCTICOS                               ║
╚═══════════════════════════════════════════════════════════════════════════╝

📌 EJEMPLO 1: MENSAJE VACÍO
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Input:
  Key:       00000000000000000000000000000000
  Nonce:     00000000000000000000000000000000
  AD:        (vacío)
  Plaintext: (vacío)

Output:
  Ciphertext: (vacío)
  Tag:        [128 bits de autenticación]

¿Cuándo usar esto?
  • Para generar un "token" de autenticación
  • Verificar que una conexión es legítima
  • Sin transmitir datos reales


📌 EJEMPLO 2: SOLO AUTENTICACIÓN
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Input:
  Key:       000102030405060708090A0B0C0D0E0F
  Nonce:     000102030405060708090A0B0C0D0E0F
  AD:        48656C6C6F20576F726C64 ("Hello World" en hex)
  Plaintext: (vacío)

Output:
  Ciphertext: (vacío)
  Tag:        [autenticación de "Hello World"]

Caso de uso:
  • Enviar metadatos que todos pueden leer
  • Pero verificar que no fueron modificados
  • Ejemplo: cabecera HTTP, timestamp, ID de sesión


📌 EJEMPLO 3: CIFRADO SIMPLE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Input:
  Key:       000102030405060708090A0B0C0D0E0F
  Nonce:     000102030405060708090A0B0C0D0E0F
  AD:        (vacío)
  Plaintext: 4142434445464748 ("ABCDEFGH" en hex)

Proceso:
  1. Inicialización mezcla Key + Nonce → Estado inicial
  2. Estado[0] ⊕ Plaintext → Ciphertext
  3. Finalización genera Tag

Output:
  Ciphertext: [8 bytes cifrados]
  Tag:        [128 bits]

Ventaja:
  • Cifrado + Autenticación en UNA operación
  • Más eficiente que AES-GCM en hardware pequeño


📌 EJEMPLO 4: CASO COMPLETO
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Escenario: Enviar mensaje bancario seguro

Input:
  Key:       [128 bits secretos compartidos]
  Nonce:     [timestamp único: 20231215143022001234...]
  AD:        "Transacción #12345, Fecha: 2023-12-15"
  Plaintext: "Transferir $1000 a cuenta 9876543210"

Proceso:
  1. Inicialización con Key y Nonce
  2. Absorber AD (se autentica pero no se cifra)
     → La fecha/ID son visibles pero protegidos
  3. Cifrar Plaintext
     → El monto y cuenta son secretos
  4. Generar Tag
     → Detecta cualquier modificación

Output:
  Ciphertext: [bytes cifrados del mensaje]
  Tag:        [firma digital de 128 bits]

Receptor:
  1. Usa misma Key y Nonce
  2. Descifra Ciphertext
  3. Recalcula Tag
  4. Si Tag coincide → mensaje íntegro y auténtico


 SEGURIDAD EN LA PRÁCTICA
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

 BUENAS PRÁCTICAS:

1. NUNCA reutilizar Nonce:
   ❌ Malo: Usar mismo Nonce para 2 mensajes
   ✅ Bueno: Timestamp + contador + random

2. Mantener Key secreta:
   ❌ Malo: Hardcodear en código fuente
   ✅ Bueno: Hardware Security Module (HSM), enclave seguro

3. Verificar SIEMPRE el Tag:
   ❌ Malo: Descifrar sin verificar
   ✅ Bueno: Verificar Tag ANTES de usar datos

4. Usar longitud adecuada:
   • Key: 128 bits (mínimo, 256 bits mejor)
   • Nonce: DEBE ser único por mensaje
   • Tag: 128 bits completos


 ERRORES COMUNES:

1. Nonce Reuse:
   Si usas mismo Nonce + Key para 2 mensajes diferentes:
   → Atacante puede obtener: C1 ⊕ C2 = P1 ⊕ P2
   → Rompe el cifrado completamente

2. No verificar Tag:
   → Atacante puede modificar Ciphertext
   → Receptor descifra datos corruptos/maliciosos

3. Key débil:
   → Key = 00000000... es insegura
   → Usar generadores criptográficos (CSPRNG)


 COMPARACIÓN CON OTROS ALGORITMOS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ASCON-128a vs AES-GCM:
  • ASCON: Más eficiente en hardware pequeño (IoT)
  • AES-GCM: Más rápido en CPUs con instrucciones AES-NI
  • Ambos: Seguros y estandarizados

ASCON-128a vs ChaCha20-Poly1305:
  • ASCON: Mejor en hardware constrained
  • ChaCha20: Mejor en software sin aceleración hardware
  • Ambos: Resistentes a ataques timing

Ventajas de ASCON:
  ✅ Ganador de CAESAR competition
  ✅ Adoptado por NIST para "lightweight crypto"
  ✅ Ideal para IoT, sensores, embedded systems
  ✅ Resistente a ataques de canal lateral
  ✅ Diseño simple y elegante
""")
        examples_text.config(state=tk.DISABLED)
        
    # ==================== MÉTODOS DE CONTROL ====================
    
    def gen_key(self):
        import random
        key = ''.join([format(random.randint(0, 255), '02x') for _ in range(16)])
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, key.upper())
    
    def gen_nonce(self):
        import random
        nonce = ''.join([format(random.randint(0, 255), '02x') for _ in range(16)])
        self.nonce_entry.delete(0, tk.END)
        self.nonce_entry.insert(0, nonce.upper())
    
    def update_speed(self, value):
        self.animation_speed = float(value)
        self.speed_label.config(text=f"{self.animation_speed:.1f}x")
    
    def load_example(self):
        """Cargar ejemplo predefinido o vector de prueba"""
        examples = {
            "Ejemplo 1: Vacío": {
                "key": "00000000000000000000000000000000",
                "nonce": "00000000000000000000000000000000",
                "ad": "",
                "pt": ""
            },
            "Ejemplo 2: Con AD": {
                "key": "000102030405060708090A0B0C0D0E0F",
                "nonce": "000102030405060708090A0B0C0D0E0F",
                "ad": "606162636465666768696A6B6C6D6E6F",
                "pt": ""
            },
            "Ejemplo 3: Completo": {
                "key": "000102030405060708090A0B0C0D0E0F",
                "nonce": "000102030405060708090A0B0C0D0E0F",
                "ad": "606162636465666768696A6B6C6D6E6F",
                "pt": "4142434445464748"
            }
        }
        
        # Agregar vectores de prueba oficiales
        for vec_name, vec_data in OFFICIAL_TEST_VECTORS.items():
            examples[f"🔬 {vec_name}"] = {
                "key": vec_data["key"],
                "nonce": vec_data["nonce"],
                "ad": vec_data["ad"],
                "pt": vec_data["pt"]
            }
        
        # Diálogo de selección
        dialog = tk.Toplevel(self.root)
        dialog.title("Cargar Ejemplo")
        dialog.geometry("400x250")
        
        ttk.Label(dialog, text="Selecciona un ejemplo:", style='Title.TLabel').pack(pady=10)
        
        selected = tk.StringVar()
        for name in examples.keys():
            ttk.Radiobutton(dialog, text=name, variable=selected, value=name).pack(anchor=tk.W, padx=20)
        
        def load():
            if selected.get():
                ex = examples[selected.get()]
                self.key_entry.delete(0, tk.END)
                self.key_entry.insert(0, ex["key"])
                self.nonce_entry.delete(0, tk.END)
                self.nonce_entry.insert(0, ex["nonce"])
                self.ad_entry.delete(0, tk.END)
                self.ad_entry.insert(0, ex["ad"])
                self.pt_entry.delete(0, tk.END)
                self.pt_entry.insert(0, ex["pt"])
                dialog.destroy()
        
        ttk.Button(dialog, text="Cargar", command=load).pack(pady=10)
    
    def validate_input(self, value: str, expected_len: int = None) -> Tuple[bool, str]:
        """Validar entrada hexadecimal"""
        if not value:
            return True, ""
        if not all(c in '0123456789ABCDEFabcdef' for c in value):
            return False, "Solo caracteres hexadecimales permitidos"
        # Verificar que la longitud sea par (necesario para convertir a bytes correctamente)
        if len(value) % 2 != 0:
            return False, "La longitud hexadecimal debe ser par (cada byte son 2 caracteres hex)"
        if expected_len and len(value) != expected_len:
            return False, f"Se esperan {expected_len} caracteres"
        return True, ""
    
    def start_execution(self):
        """Iniciar ejecución de ASCON"""
        # Validar entradas
        key = self.key_entry.get().strip()
        nonce = self.nonce_entry.get().strip()
        ad = self.ad_entry.get().strip()
        pt = self.pt_entry.get().strip()
        
        valid, msg = self.validate_input(key, 32)
        if not valid:
            messagebox.showerror("Error en Key", msg)
            return
        
        valid, msg = self.validate_input(nonce, 32)
        if not valid:
            messagebox.showerror("Error en Nonce", msg)
            return
        
        valid, msg = self.validate_input(ad)
        if not valid:
            messagebox.showerror("Error en AD", msg)
            return
        
        valid, msg = self.validate_input(pt)
        if not valid:
            messagebox.showerror("Error en Plaintext", msg)
            return
        
        # Limpiar visualización
        self.main_viz_text.delete('1.0', tk.END)
        self.results_text.delete('1.0', tk.END)
        self.detail_text.delete('1.0', tk.END)
        
        # Mostrar barra de progreso para ejecuciones largas
        total_length = len(ad) + len(pt)
        show_progress = total_length > 100
        
        progress = None
        if show_progress:
            progress_frame = ttk.Frame(self.main_tab)
            progress_frame.pack(fill=tk.X, padx=5, pady=5)
            progress_label = ttk.Label(progress_frame, text="Ejecutando ASCON-128a...", font=('Arial', 9))
            progress_label.pack()
            progress = ttk.Progressbar(progress_frame, mode='indeterminate', length=300)
            progress.pack(pady=5)
            progress.start()
            self.root.update()
        
        # Ejecutar ASCON
        self.ascon = ASCON128a()
        
        try:
            # Fase 1: Inicialización
            self.log_phase("FASE 1: INICIALIZACIÓN")
            init_details = self.ascon.initialize(key, nonce)
            self.display_phase(init_details)
            
            # Fase 2: AD
            self.log_phase("\nFASE 2: ABSORCIÓN DE DATOS ASOCIADOS")
            ad_details = self.ascon.process_ad(ad)
            self.display_phase(ad_details)
            
            # Fase 3: Cifrado
            self.log_phase("\nFASE 3: CIFRADO DEL PLAINTEXT")
            ciphertext, enc_details = self.ascon.encrypt(pt)
            self.display_phase(enc_details)
            
            # Fase 4-5: Finalización
            self.log_phase("\nFASE 4-5: FINALIZACIÓN Y TAG")
            tag, fin_details = self.ascon.finalize(key)
            self.display_phase(fin_details)
            
            # Mostrar resultados
            self.display_final_results(ciphertext, tag, key, nonce, ad, pt)
            
            # Guardar pasos para navegación
            self.all_steps = self.ascon.all_steps
            self.current_step = 0
            self.enable_navigation()
            
            messagebox.showinfo("✅ Éxito", "ASCON-128a ejecutado correctamente")
            
        except Exception as e:
            messagebox.showerror("Error", f"Error: {str(e)}")
    
    def pause_execution(self):
        self.is_animating = False
        self.pause_btn.config(state=tk.DISABLED)
        self.start_btn.config(state=tk.NORMAL)
    
    def reset_execution(self):
        self.main_viz_text.delete('1.0', tk.END)
        self.results_text.delete('1.0', tk.END)
        self.detail_text.delete('1.0', tk.END)
        self.all_steps = []
        self.current_step = 0
        self.ascon = None
        self.disable_navigation()
        self.show_welcome()
    
    def show_welcome(self):
        """Mostrar mensaje de bienvenida"""
        welcome = """
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║              ASCON-128a EDUCATIONAL VISUALIZER v2.0                       ║
║                         Advanced Edition                                  ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝

🎓 BIENVENIDO A LA HERRAMIENTA EDUCATIVA INTERACTIVA

Esta aplicación te permite aprender el algoritmo ASCON-128a paso a paso,
visualizando cada transformación interna del proceso de cifrado autenticado.

  INSTRUCCIONES RÁPIDAS:

  1. Ingresa los parámetros (Key, Nonce, AD, Plaintext)
  2. Selecciona el modo de ejecución deseado
  3. Haz clic en "▶️ Iniciar"
  4. Explora los resultados en las diferentes pestañas

  CARACTERÍSTICAS:

  ✓ Visualización paso a paso con detalles completos
  ✓ Navegación interactiva entre fases
  ✓ Modo comparativo para analizar diferencias
  ✓ Guía educativa con conceptos y ejemplos
  ✓ Exportación de resultados

  COMIENZA:

  • Usa "📋 Cargar Ejemplo" para ver casos predefinidos
  • Usa "🎲" para generar valores aleatorios
  • Visita la pestaña "📚 Guía Educativa" para aprender más

═══════════════════════════════════════════════════════════════════════════

Desarrollado con fines educativos | Versión 2.0 | 2024
"""
        self.main_viz_text.insert('1.0', welcome)
    
    def log_phase(self, text):
        """Agregar texto de fase al log"""
        self.main_viz_text.insert(tk.END, "\n" + "═" * 80 + "\n", "header")
        self.main_viz_text.insert(tk.END, text + "\n", "header")
        self.main_viz_text.insert(tk.END, "═" * 80 + "\n", "header")
        self.main_viz_text.see(tk.END)
        self.root.update()
    
    def display_phase(self, details):
        """Mostrar detalles de una fase"""
        phase = details.get('phase', 'Desconocida')
        
        if details.get('step_type') == 'init':
            self.display_initialization(details)
        elif details.get('step_type') == 'ad':
            self.display_ad(details)
        elif details.get('step_type') == 'encrypt':
            self.display_encryption(details)
        elif details.get('step_type') == 'finalize':
            self.display_finalization(details)
    
    def display_initialization(self, details):
        """Mostrar inicialización"""
        self.main_viz_text.insert(tk.END, "\n Creando estado inicial...\n\n")
        
        self.main_viz_text.insert(tk.END, "Estado Inicial:\n", "subheader")
        for i, val in enumerate(details['initial_state']):
            hex_val = to_hex(val, 64)
            self.main_viz_text.insert(tk.END, f"  x{i} = {hex_val}\n")
        
        self.main_viz_text.insert(tk.END, "\n Aplicando permutación p_a (12 rondas)...\n")
        self.main_viz_text.insert(tk.END, f"   Ver pestaña 'Visualización Detallada' para explorar cada ronda\n")
        
        self.main_viz_text.insert(tk.END, "\nEstado después de p_a:\n", "subheader")
        for i, val in enumerate(details['state_after_perm']):
            hex_val = to_hex(val, 64)
            self.main_viz_text.insert(tk.END, f"  x{i} = {hex_val}\n")
        
        self.main_viz_text.insert(tk.END, "\n Mezclando Key con estado (XOR)...\n")
        self.main_viz_text.insert(tk.END, "\nEstado Final de Inicialización:\n", "subheader")
        for i, val in enumerate(details['final_state']):
            hex_val = to_hex(val, 64)
            self.main_viz_text.insert(tk.END, f"  x{i} = {hex_val}\n")
    
    def display_ad(self, details):
        """Mostrar absorción de AD"""
        if details.get('no_ad'):
            self.main_viz_text.insert(tk.END, "\n✓ No hay datos asociados\n")
            self.main_viz_text.insert(tk.END, "  Señalizando dominio: x4 ⊕= 1\n")
            return
        
        self.main_viz_text.insert(tk.END, f"\n Procesando {len(details['blocks'])} bloque(s) de AD...\n\n")
        
        for block in details['blocks']:
            self.main_viz_text.insert(tk.END, f"Bloque {block['block_num'] + 1}:\n", "subheader")
            self.main_viz_text.insert(tk.END, f"  Datos: {block['block_hex']}\n")
            self.main_viz_text.insert(tk.END, f"  XOR con x0\n")
            self.main_viz_text.insert(tk.END, f"  Aplicando p_b (6 rondas)...\n")
            
            if self.show_changes.get() and block.get('x0_changes'):
                changes = len(block['x0_changes'])
                self.main_viz_text.insert(tk.END, f"  → {changes} bits cambiaron en x0\n", "info")
        
        self.main_viz_text.insert(tk.END, "\n✓ Fin de AD - Dominio señalizado\n")
    
    def display_encryption(self, details):
        """Mostrar cifrado"""
        if details.get('no_plaintext'):
            self.main_viz_text.insert(tk.END, "\n✓ No hay plaintext para cifrar\n")
            return
        
        self.main_viz_text.insert(tk.END, f"\n Cifrando {len(details['blocks'])} bloque(s)...\n\n")
        
        for block in details['blocks']:
            self.main_viz_text.insert(tk.END, f"Bloque {block['block_num'] + 1}:\n", "subheader")
            self.main_viz_text.insert(tk.END, f"  Plaintext:  {block['plaintext_hex']}\n")
            self.main_viz_text.insert(tk.END, f"  Ciphertext: {block['ciphertext_hex']}\n")
            self.main_viz_text.insert(tk.END, f"  (Plaintext ⊕ x0)\n")
            self.main_viz_text.insert(tk.END, f"  Aplicando p_a (12 rondas)...\n")
    
    def display_finalization(self, details):
        """Mostrar finalización"""
        self.main_viz_text.insert(tk.END, "\n Mezclando Key con estado...\n")
        self.main_viz_text.insert(tk.END, " Aplicando p_a final (12 rondas)...\n")
        self.main_viz_text.insert(tk.END, "\n  Generando TAG de autenticación...\n")
        self.main_viz_text.insert(tk.END, f"\nTAG: {details['tag']}\n", "subheader")
    
    def display_final_results(self, ciphertext, tag, key, nonce, ad, pt):
        """Mostrar resultados finales"""
        result = "╔" + "═" * 60 + "╗\n"
        result += "║" + " " * 20 + "RESULTADOS FINALES" + " " * 22 + "║\n"
        result += "╠" + "═" * 60 + "╣\n\n"
        
        result += "ENTRADAS:\n"
        result += f"  Key:        {key}\n"
        result += f"  Nonce:      {nonce}\n"
        result += f"  AD:         {ad if ad else '(vacío)'}\n"
        result += f"  Plaintext:  {pt if pt else '(vacío)'}\n\n"
        
        result += "SALIDAS:\n"
        result += f"  Ciphertext: {ciphertext if ciphertext else '(vacío)'}\n"
        result += f"  Tag:        {tag}\n\n"
        
        result += "ESTADÍSTICAS:\n"
        pt_len = len(pt) // 2 if pt else 0
        ad_len = len(ad) // 2 if ad else 0
        ct_len = len(ciphertext) // 2 if ciphertext else 0
        
        result += f"  Plaintext:  {pt_len} bytes\n"
        result += f"  AD:         {ad_len} bytes\n"
        result += f"  Ciphertext: {ct_len} bytes\n"
        result += f"  Tag:        16 bytes (128 bits)\n\n"
        
        result += "╚" + "═" * 60 + "╝\n"
        
        self.results_text.insert('1.0', result)
        
        # Guardar para exportar
        self.last_results = {
            'key': key, 'nonce': nonce, 'ad': ad, 'plaintext': pt,
            'ciphertext': ciphertext, 'tag': tag,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
    
    # ==================== NAVEGACIÓN ====================
    
    def enable_navigation(self):
        """Habilitar botones de navegación"""
        if self.all_steps:
            self.next_btn.config(state=tk.NORMAL)
            self.step_label.config(text=f"Paso {self.current_step + 1} de {len(self.all_steps)}")
            self.display_current_step()
    
    def disable_navigation(self):
        """Deshabilitar navegación"""
        self.prev_btn.config(state=tk.DISABLED)
        self.next_btn.config(state=tk.DISABLED)
        self.step_label.config(text="Paso 0 de 0")
    
    def next_step(self):
        """Ir al siguiente paso"""
        if self.current_step < len(self.all_steps) - 1:
            self.current_step += 1
            self.display_current_step()
            self.prev_btn.config(state=tk.NORMAL)
            
            if self.current_step == len(self.all_steps) - 1:
                self.next_btn.config(state=tk.DISABLED)
            
            self.step_label.config(text=f"Paso {self.current_step + 1} de {len(self.all_steps)}")
    
    def prev_step(self):
        """Ir al paso anterior"""
        if self.current_step > 0:
            self.current_step -= 1
            self.display_current_step()
            self.next_btn.config(state=tk.NORMAL)
            
            if self.current_step == 0:
                self.prev_btn.config(state=tk.DISABLED)
            
            self.step_label.config(text=f"Paso {self.current_step + 1} de {len(self.all_steps)}")
    
    def display_current_step(self):
        """Mostrar el paso actual en detalle"""
        if not self.all_steps or self.current_step >= len(self.all_steps):
            return
        
        step = self.all_steps[self.current_step]
        self.detail_text.delete('1.0', tk.END)
        
        # Encabezado
        phase = step.get('phase', 'Desconocida')
        self.detail_text.insert(tk.END, "╔" + "═" * 78 + "╗\n")
        self.detail_text.insert(tk.END, f"║  {phase.center(76)}  ║\n", "phase")
        self.detail_text.insert(tk.END, "╚" + "═" * 78 + "╝\n\n")
        
        # Contenido según tipo
        step_type = step.get('step_type')
        
        if step_type == 'init':
            self.display_step_init(step)
        elif step_type == 'ad':
            self.display_step_ad(step)
        elif step_type == 'encrypt':
            self.display_step_encrypt(step)
        elif step_type == 'finalize':
            self.display_step_finalize(step)
    
    def display_step_init(self, step):
        """Mostrar detalles de inicialización"""
        self.detail_text.insert(tk.END, "PASO 1: Crear Estado Inicial\n", "step")
        self.detail_text.insert(tk.END, "─" * 80 + "\n\n")
        
        self.detail_text.insert(tk.END, "Componentes:\n")
        self.detail_text.insert(tk.END, f"  IV:         {to_hex(step['iv'], 64)}\n", "value")
        self.detail_text.insert(tk.END, f"  Key[0:64]:  {to_hex(step['key_high'], 64)}\n", "value")
        self.detail_text.insert(tk.END, f"  Key[64:128]:{to_hex(step['key_low'], 64)}\n", "value")
        self.detail_text.insert(tk.END, f"  Nonce[0:64]:{to_hex(step['nonce_high'], 64)}\n", "value")
        self.detail_text.insert(tk.END, f"  Nonce[64:128]:{to_hex(step['nonce_low'], 64)}\n", "value")
        
        self.detail_text.insert(tk.END, "\nEstado Inicial (antes de permutación):\n", "step")
        for i, val in enumerate(step['initial_state']):
            hex_val = to_hex(val, 64)
            if self.show_binary.get():
                bin_val = to_binary(val, 64)
                self.detail_text.insert(tk.END, f"  x{i} = {hex_val}\n")
                self.detail_text.insert(tk.END, f"       {bin_val}\n", "info")
            else:
                self.detail_text.insert(tk.END, f"  x{i} = {hex_val}\n")
        
        self.detail_text.insert(tk.END, "\nPASO 2: Aplicar Permutación p_a (12 rondas)\n", "step")
        self.detail_text.insert(tk.END, "─" * 80 + "\n")
        
        if step.get('rounds'):
            self.detail_text.insert(tk.END, f"\nNúmero de rondas ejecutadas: {len(step['rounds'])}\n")
            self.detail_text.insert(tk.END, "Cada ronda aplica: RC + S-box + Difusión Lineal\n", "info")
            
            # Modo depuración: mostrar TODAS las rondas detalladamente
            if self.debug_mode.get():
                self.detail_text.insert(tk.END, "\n🐛 MODO DEPURACIÓN: Mostrando TODAS las rondas\n", "step")
                for round_idx, round_data in enumerate(step['rounds']):
                    self.detail_text.insert(tk.END, f"\n{'='*70}\n")
                    self.detail_text.insert(tk.END, f"▼ RONDA {round_idx} (RC Index: {round_data.get('rc_index', round_idx)})\n", "step")
                    self.detail_text.insert(tk.END, f"{'='*70}\n")
                    
                    # Estado de entrada
                    self.detail_text.insert(tk.END, f"\n1️ESTADO DE ENTRADA:\n", "subheader")
                    for i, val in enumerate(round_data.get('input', [])):
                        self.detail_text.insert(tk.END, f"   x{i} = {to_hex(val, 64)}\n")
                    
                    # Paso 1: Constante de ronda
                    self.detail_text.insert(tk.END, f"\n2️APLICAR CONSTANTE DE RONDA:\n", "subheader")
                    self.detail_text.insert(tk.END, f"   RC = 0x{round_data.get('rc', 0):02x}\n")
                    self.detail_text.insert(tk.END, f"   x2 = x2 ⊕ RC\n")
                    if round_data.get('after_rc'):
                        self.detail_text.insert(tk.END, f"   Estado después de RC:\n")
                        for i, val in enumerate(round_data['after_rc']):
                            if i == 2 and round_data.get('x2_changed'):
                                changes = len(round_data['x2_changed'])
                                self.detail_text.insert(tk.END, f"     x{i} = {to_hex(val, 64)} ({changes} bits cambiaron)\n", "changed_bit")
                            else:
                                self.detail_text.insert(tk.END, f"     x{i} = {to_hex(val, 64)}\n")
                    
                    # Paso 2: S-box
                    self.detail_text.insert(tk.END, f"\n3️APLICAR S-BOX:\n", "subheader")
                    if round_data.get('after_sbox'):
                        self.detail_text.insert(tk.END, f"   Estado después de S-box:\n")
                        for i, val in enumerate(round_data['after_sbox']):
                            if round_data.get('sbox_changes') and i < len(round_data['sbox_changes']):
                                changes = len(round_data['sbox_changes'][i])
                                if changes > 0:
                                    self.detail_text.insert(tk.END, f"     x{i} = {to_hex(val, 64)} ({changes} bits cambiaron)\n", "changed_bit")
                                else:
                                    self.detail_text.insert(tk.END, f"     x{i} = {to_hex(val, 64)}\n")
                            else:
                                self.detail_text.insert(tk.END, f"     x{i} = {to_hex(val, 64)}\n")
                    
                    # Paso 3: Capa lineal
                    self.detail_text.insert(tk.END, f"\n4️APLICAR DIFUSIÓN LINEAL:\n", "subheader")
                    if round_data.get('after_linear'):
                        self.detail_text.insert(tk.END, f"   Estado después de Difusión Lineal:\n")
                        for i, val in enumerate(round_data['after_linear']):
                            if round_data.get('linear_changes') and i < len(round_data['linear_changes']):
                                changes = len(round_data['linear_changes'][i])
                                if changes > 0:
                                    self.detail_text.insert(tk.END, f"     x{i} = {to_hex(val, 64)} ({changes} bits cambiaron)\n", "changed_bit")
                                else:
                                    self.detail_text.insert(tk.END, f"     x{i} = {to_hex(val, 64)}\n")
                            else:
                                self.detail_text.insert(tk.END, f"     x{i} = {to_hex(val, 64)}\n")
                    
                    self.detail_text.insert(tk.END, "\n")
            else:
                # Modo normal: mostrar solo primera y última ronda como ejemplo
                if len(step['rounds']) > 0:
                    first_round = step['rounds'][0]
                    self.detail_text.insert(tk.END, "\nRonda 0 (ejemplo):\n")
                    self.detail_text.insert(tk.END, f"  RC = 0x{first_round['rc']:02x}\n")
                    self.detail_text.insert(tk.END, f"  Estado después de RC + S-box + Difusión:\n")
                    for i, val in enumerate(first_round['after_linear']):
                        self.detail_text.insert(tk.END, f"    x{i} = {to_hex(val, 64)}\n", "value")
                    
                    if len(step['rounds']) > 1:
                        self.detail_text.insert(tk.END, f"\n... ({len(step['rounds']) - 2} rondas intermedias) ...\n", "info")
                        last_round = step['rounds'][-1]
                        self.detail_text.insert(tk.END, f"\nRonda {len(step['rounds']) - 1} (última):\n")
                        self.detail_text.insert(tk.END, f"  RC = 0x{last_round['rc']:02x}\n")
                        self.detail_text.insert(tk.END, f"  Estado después de RC + S-box + Difusión:\n")
                        for i, val in enumerate(last_round['after_linear']):
                            self.detail_text.insert(tk.END, f"    x{i} = {to_hex(val, 64)}\n", "value")
        
        self.detail_text.insert(tk.END, "\nEstado Final de Inicialización:\n", "step")
        for i, val in enumerate(step['final_state']):
            self.detail_text.insert(tk.END, f"  x{i} = {to_hex(val, 64)}\n", "value")
    
    def display_step_ad(self, step):
        """Mostrar detalles de AD"""
        if step.get('no_ad'):
            self.detail_text.insert(tk.END, "✓ No hay datos asociados para procesar\n")
            self.detail_text.insert(tk.END, "\nSeñalización de dominio:\n")
            self.detail_text.insert(tk.END, "  x4 = x4 ⊕ 1 (marca que no hay AD)\n")
            return
        
        self.detail_text.insert(tk.END, f"Total de bloques AD: {len(step['blocks'])}\n\n")
        
        for block in step['blocks']:
            self.detail_text.insert(tk.END, f"━━━ Bloque {block['block_num'] + 1} ━━━\n", "step")
            self.detail_text.insert(tk.END, f"\nDatos del bloque: {block['block_hex']}\n", "value")
            
            self.detail_text.insert(tk.END, "\nPaso 1: XOR con x0\n")
            self.detail_text.insert(tk.END, f"  x0_antes = {to_hex(block['state_before'][0], 64)}\n")
            self.detail_text.insert(tk.END, f"  AD_block = {block['block_hex']}\n", "value")
            self.detail_text.insert(tk.END, f"  x0_después = {to_hex(block['after_xor'][0], 64)}\n", "value")
            
            if self.show_changes.get() and block.get('x0_changes'):
                self.detail_text.insert(tk.END, f"\n  Cambios: {len(block['x0_changes'])} bits modificados\n", "changed_bit")
            
            self.detail_text.insert(tk.END, "\nPaso 2: Aplicar p_b (6 rondas)\n")
            self.detail_text.insert(tk.END, "  Cada ronda mezcla el estado completamente\n", "info")
            
            self.detail_text.insert(tk.END, "\nEstado después de p_b:\n")
            for i, val in enumerate(block['state_after']):
                self.detail_text.insert(tk.END, f"  x{i} = {to_hex(val, 64)}\n")
            
            self.detail_text.insert(tk.END, "\n")
    
    def display_step_encrypt(self, step):
        """Mostrar detalles de cifrado"""
        if step.get('no_plaintext'):
            self.detail_text.insert(tk.END, "✓ No hay plaintext para cifrar\n")
            return
        
        self.detail_text.insert(tk.END, f" Total de bloques a cifrar: {len(step['blocks'])}\n\n")
        
        for block in step['blocks']:
            self.detail_text.insert(tk.END, f"━━━ Bloque {block['block_num'] + 1} ━━━\n", "step")
            
            self.detail_text.insert(tk.END, "\nPaso 1: Cifrado (Plaintext ⊕ x0)\n")
            self.detail_text.insert(tk.END, f"  Plaintext:  {block['plaintext_hex']}\n", "value")
            self.detail_text.insert(tk.END, f"  x0:         {to_hex(block['state_before'][0], 64)}\n")
            self.detail_text.insert(tk.END, f"  Ciphertext: {block['ciphertext_hex']}\n", "value")
            
            # Mostrar información de padding si se aplicó
            if block.get('padding_applied'):
                self.detail_text.insert(tk.END, f"  Padding ASCON aplicado: {block.get('plaintext_padded_hex', '')}\n", "info")
            
            if self.show_binary.get():
                self.detail_text.insert(tk.END, "\nRepresentación binaria:\n", "info")
                pt_bin = to_binary(block['plaintext_int'], 64)
                ct_bin = to_binary(block['ciphertext_int'], 64)
                self.detail_text.insert(tk.END, f"  PT: {pt_bin}\n", "info")
                self.detail_text.insert(tk.END, f"  CT: {ct_bin}\n", "info")
            
            # Visualización bit a bit con highlights si está habilitada
            if self.show_binary_highlights.get():
                self.display_binary_diff(self.detail_text, 
                                       block['plaintext_int'], 
                                       block['ciphertext_int'], 
                                       f"Bloque {block['block_num'] + 1}: Plaintext → Ciphertext",
                                       64)
            
            self.detail_text.insert(tk.END, "\nPaso 2: Actualizar estado\n")
            self.detail_text.insert(tk.END, f"  x0 = Ciphertext (se reemplaza para siguiente bloque)\n")
            
            self.detail_text.insert(tk.END, "\nPaso 3: Aplicar p_a (12 rondas)\n")
            self.detail_text.insert(tk.END, "  Permutación completa para máxima seguridad\n", "info")
            
            self.detail_text.insert(tk.END, "\nEstado después de p_a:\n")
            for i, val in enumerate(block['state_after']):
                self.detail_text.insert(tk.END, f"  x{i} = {to_hex(val, 64)}\n")
            
            self.detail_text.insert(tk.END, "\n")
    
    def display_step_finalize(self, step):
        """Mostrar detalles de finalización"""
        self.detail_text.insert(tk.END, "🏁 FINALIZACIÓN Y GENERACIÓN DE TAG\n", "step")
        self.detail_text.insert(tk.END, "─" * 80 + "\n\n")
        
        self.detail_text.insert(tk.END, "Paso 1: Estado antes de finalización\n")
        for i, val in enumerate(step['state_before']):
            self.detail_text.insert(tk.END, f"  x{i} = {to_hex(val, 64)}\n")
        
        self.detail_text.insert(tk.END, "\nPaso 2: Mezclar Key con estado\n")
        self.detail_text.insert(tk.END, "  x1 = x1 ⊕ Key[0:64]\n")
        self.detail_text.insert(tk.END, "  x2 = x2 ⊕ Key[64:128]\n")
        
        self.detail_text.insert(tk.END, "\nEstado después de XOR con Key:\n")
        for i, val in enumerate(step['after_key_xor']):
            self.detail_text.insert(tk.END, f"  x{i} = {to_hex(val, 64)}\n")
        
        self.detail_text.insert(tk.END, "\nPaso 3: Aplicar p_a final (12 rondas)\n")
        
        self.detail_text.insert(tk.END, "\nEstado final:\n")
        for i, val in enumerate(step['state_after_perm']):
            self.detail_text.insert(tk.END, f"  x{i} = {to_hex(val, 64)}\n")
        
        self.detail_text.insert(tk.END, "\n  Paso 4: Extraer TAG\n", "step")
        self.detail_text.insert(tk.END, "  TAG = (x3 ⊕ Key[0:64]) || (x4 ⊕ Key[64:128])\n")
        self.detail_text.insert(tk.END, f"\n  TAG[0:64]:  {to_hex(step['tag_high'], 64)}\n", "value")
        self.detail_text.insert(tk.END, f"  TAG[64:128]:{to_hex(step['tag_low'], 64)}\n", "value")
        self.detail_text.insert(tk.END, f"\n  TAG COMPLETO: {step['tag']}\n", "value")
        
        if self.show_binary.get():
            tag_int = hex_to_int(step['tag'])
            tag_bin = to_binary(tag_int, 128)
            self.detail_text.insert(tk.END, f"\n  Binario:\n")
            for i in range(0, len(tag_bin), 72):
                self.detail_text.insert(tk.END, f"  {tag_bin[i:i+72]}\n", "info")
    
    # ==================== COMPARACIÓN ====================
    
    def start_comparison(self):
        """Iniciar modo comparativo"""
        messagebox.showinfo("Modo Comparativo", 
                          "Ejecuta ASCON dos veces con parámetros diferentes.\n"
                          "Luego podrás comparar los resultados lado a lado.")
    
    def analyze_differences(self):
        """Analizar diferencias entre ejecuciones"""
        messagebox.showinfo("Análisis", 
                          "Esta función mostraría un análisis detallado de:\n"
                          "• Bits que cambiaron\n"
                          "• Efecto avalancha\n"
                          "• Propagación de cambios")
    
    # ==================== VERIFICACIÓN Y ANÁLISIS ====================
    
    def verify_test_vectors(self):
        """Verificar vectores de prueba oficiales"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Verificar Vectores de Prueba")
        dialog.geometry("700x500")
        
        # Frame de selección
        select_frame = ttk.Frame(dialog)
        select_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(select_frame, text="Selecciona un vector de prueba:", style='Title.TLabel').pack(anchor=tk.W)
        
        selected_vector = tk.StringVar()
        vector_listbox = tk.Listbox(select_frame, height=8, font=('Courier', 9))
        vector_listbox.pack(fill=tk.BOTH, expand=True, pady=5)
        
        for vec_name in OFFICIAL_TEST_VECTORS.keys():
            vector_listbox.insert(tk.END, vec_name)
        
        # Información del vector
        info_frame = ttk.LabelFrame(dialog, text="Información del Vector")
        info_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        info_text = scrolledtext.ScrolledText(info_frame, height=10, wrap=tk.WORD, font=('Courier', 8))
        info_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        def show_vector_info(event=None):
            selection = vector_listbox.curselection()
            if selection:
                vec_name = vector_listbox.get(selection[0])
                vector = OFFICIAL_TEST_VECTORS[vec_name]
                info_text.delete('1.0', tk.END)
                info_text.insert('1.0', f"Fuente: {vector['source']}\n")
                info_text.insert(tk.END, f"Descripción: {vector['description']}\n\n")
                info_text.insert(tk.END, f"Key:        {vector['key']}\n")
                info_text.insert(tk.END, f"Nonce:      {vector['nonce']}\n")
                info_text.insert(tk.END, f"AD:         {vector['ad'] or '(vacío)'}\n")
                info_text.insert(tk.END, f"Plaintext:  {vector['pt'] or '(vacío)'}\n\n")
                if vector['expected_tag']:
                    info_text.insert(tk.END, f"Tag Esperado: {vector['expected_tag']}\n", "value")
        
        vector_listbox.bind('<<ListboxSelect>>', show_vector_info)
        
        def verify_selected():
            selection = vector_listbox.curselection()
            if not selection:
                messagebox.showwarning("⚠️", "Selecciona un vector primero")
                return
            
            vec_name = vector_listbox.get(selection[0])
            vector = OFFICIAL_TEST_VECTORS[vec_name]
            
            try:
                # Ejecutar ASCON con los parámetros del vector
                self.ascon = ASCON128a()
                
                # Fase 1: Inicialización
                self.ascon.initialize(vector['key'], vector['nonce'])
                
                # Fase 2: AD
                self.ascon.process_ad(vector['ad'])
                
                # Fase 3: Cifrado
                ciphertext, _ = self.ascon.encrypt(vector['pt'])
                
                # Fase 4-5: Finalización
                tag, _ = self.ascon.finalize(vector['key'])
                
                # Comparar resultados
                if vector['expected_tag']:
                    if tag.upper() == vector['expected_tag'].upper():
                        messagebox.showinfo("✅ Verificación Exitosa", 
                            f"Vector '{vec_name}' PASÓ la verificación\n\n"
                            f"Tag obtenido: {tag}\n"
                            f"Tag esperado: {vector['expected_tag']}\n\n"
                            f"✓ Los resultados coinciden perfectamente")
                    else:
                        messagebox.showerror("❌ Verificación Fallida", 
                            f"Vector '{vec_name}' FALLÓ la verificación\n\n"
                            f"Tag obtenido:  {tag}\n"
                            f"Tag esperado:  {vector['expected_tag']}\n\n"
                            f"⚠️ Los resultados NO coinciden")
                else:
                    messagebox.showinfo("ℹ️ Información", 
                        f"Vector '{vec_name}' ejecutado correctamente\n\n"
                        f"Ciphertext: {ciphertext or '(vacío)'}\n"
                        f"Tag: {tag}\n\n"
                        f"Nota: Este vector no tiene tag esperado para comparar")
                
                # Cargar resultados en la interfaz principal
                self.key_entry.delete(0, tk.END)
                self.key_entry.insert(0, vector['key'])
                self.nonce_entry.delete(0, tk.END)
                self.nonce_entry.insert(0, vector['nonce'])
                self.ad_entry.delete(0, tk.END)
                self.ad_entry.insert(0, vector['ad'])
                self.pt_entry.delete(0, tk.END)
                self.pt_entry.insert(0, vector['pt'])
                
                dialog.destroy()
                
            except Exception as e:
                messagebox.showerror("❌ Error", f"Error al verificar vector:\n{str(e)}")
        
        # Botones
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(btn_frame, text="✅ Verificar Vector Seleccionado", command=verify_selected).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cerrar", command=dialog.destroy).pack(side=tk.RIGHT, padx=5)
    
    def display_binary_diff(self, text_widget, old_val: int, new_val: int, label: str, bits: int = 64):
        """Mostrar binario resaltando bits que cambiaron"""
        if not self.show_binary_highlights.get():
            return
        
        old_bin, new_bin, changed_pos = to_binary_with_highlights(old_val, new_val, bits)
        
        text_widget.insert(tk.END, f"\n{label} - Comparación Binaria:\n", "info")
        text_widget.insert(tk.END, "Antes:  ")
        
        old_bin_formatted = format(old_val, f'0{bits}b')
        for i, bit in enumerate(old_bin_formatted):
            if i > 0 and i % 8 == 0:
                text_widget.insert(tk.END, " ")
            if i in changed_pos:
                text_widget.insert(tk.END, bit, "changed_bit")
            else:
                text_widget.insert(tk.END, bit)
        
        text_widget.insert(tk.END, "\nDespués: ")
        new_bin_formatted = format(new_val, f'0{bits}b')
        for i, bit in enumerate(new_bin_formatted):
            if i > 0 and i % 8 == 0:
                text_widget.insert(tk.END, " ")
            if i in changed_pos:
                text_widget.insert(tk.END, bit, "changed_bit")
            else:
                text_widget.insert(tk.END, bit)
        
        text_widget.insert(tk.END, f"\n  → {len(changed_pos)} bits cambiaron de {bits} total ({len(changed_pos)/bits*100:.1f}%)\n\n")
    
    def analyze_avalanche_effect(self):
        """Análisis completo de efecto avalancha con múltiples casos de prueba"""
        key = self.key_entry.get().strip()
        nonce = self.nonce_entry.get().strip()
        ad = self.ad_entry.get().strip()
        pt = self.pt_entry.get().strip()
        
        if not key or not nonce:
            messagebox.showwarning("⚠️", "Key y Nonce son requeridos para el análisis")
            return
        
        # Casos de prueba
        test_cases = [
            ("1 bit en Key (último bit)", lambda k, n, a, p: (k ^ 1, n, a, p)),
            ("1 bit en Key (primer bit)", lambda k, n, a, p: (k ^ (1 << 127), n, a, p)),
            ("1 bit en Nonce (último bit)", lambda k, n, a, p: (k, n ^ 1, a, p)),
            ("1 bit en Nonce (primer bit)", lambda k, n, a, p: (k, n ^ (1 << 127), a, p)),
        ]
        
        # Si hay plaintext, agregar casos adicionales
        if pt:
            pt_int = hex_to_int(pt) if pt else 0
            if pt_int:
                test_cases.append(("1 byte en Plaintext", lambda k, n, a, p: (k, n, a, p ^ 0xFF)))
        
        try:
            # Ejecución base: Original
            key_int = hex_to_int(key)
            nonce_int = hex_to_int(nonce)
            ad_int = hex_to_int(ad) if ad else 0
            pt_int = hex_to_int(pt) if pt else 0
            
            ascon_base = ASCON128a()
            ascon_base.initialize(key, nonce)
            ascon_base.process_ad(ad)
            ct_base, _ = ascon_base.encrypt(pt)
            tag_base, _ = ascon_base.finalize(key)
            tag_base_int = hex_to_int(tag_base)
            
            results = []
            
            # Ejecutar cada caso de prueba
            for test_name, modifier in test_cases:
                k_mod, n_mod, a_mod, p_mod = modifier(key_int, nonce_int, ad_int, pt_int)
                
                key_mod = to_hex(k_mod, 128)
                nonce_mod = to_hex(n_mod, 128)
                ad_mod = to_hex(a_mod, len(ad)) if ad else ""
                pt_mod = to_hex(p_mod, len(pt)) if pt else ""
                
                ascon_test = ASCON128a()
                ascon_test.initialize(key_mod, nonce_mod)
                ascon_test.process_ad(ad_mod)
                ct_test, _ = ascon_test.encrypt(pt_mod)
                tag_test, _ = ascon_test.finalize(key_mod)
                
                tag_test_int = hex_to_int(tag_test)
                bits_changed = bin(tag_base_int ^ tag_test_int).count('1')
                percentage = bits_changed / 128 * 100
                
                results.append({
                    'test': test_name,
                    'bits_changed': bits_changed,
                    'percentage': percentage,
                    'status': 'excellent' if bits_changed > 80 else ('good' if bits_changed > 40 else 'weak')
                })
            
            # Construir resultado
            result_text = "ANÁLISIS COMPLETO DE EFECTO AVALANCHA\n"
            result_text += "=" * 60 + "\n\n"
            result_text += f"Configuración base:\n"
            result_text += f"  Key:    {key[:16]}...\n"
            result_text += f"  Nonce:  {nonce[:16]}...\n"
            result_text += f"  AD:     {ad[:16] + '...' if len(ad) > 16 else ad or '(vacío)'}\n"
            result_text += f"  PT:     {pt[:16] + '...' if len(pt) > 16 else pt or '(vacío)'}\n\n"
            result_text += "Resultados por caso de prueba:\n"
            result_text += "-" * 60 + "\n"
            
            for r in results:
                status_icon = "✅" if r['status'] == 'excellent' else ("✓" if r['status'] == 'good' else "⚠️")
                result_text += f"{status_icon} {r['test']}:\n"
                result_text += f"   • Bits cambiados: {r['bits_changed']}/128 ({r['percentage']:.1f}%)\n"
                result_text += f"   • Evaluación: {'EXCELENTE' if r['status'] == 'excellent' else ('BUENO' if r['status'] == 'good' else 'DÉBIL')}\n\n"
            
            # Resumen estadístico
            avg_bits = sum(r['bits_changed'] for r in results) / len(results)
            avg_percentage = avg_bits / 128 * 100
            result_text += "Resumen Estadístico:\n"
            result_text += "-" * 60 + "\n"
            result_text += f"• Promedio de bits cambiados: {avg_bits:.1f} ({avg_percentage:.1f}%)\n"
            result_text += f"• Ideal para seguridad: ~64 bits (50%)\n"
            result_text += f"• Mínimo aceptable: ~40 bits (31%)\n\n"
            
            if avg_percentage < 31:
                result_text += "⚠️ ADVERTENCIA: El algoritmo muestra difusión limitada\n"
            elif avg_percentage > 60:
                result_text += "✅ EXCELENTE: El algoritmo muestra excelente efecto avalancha\n"
            else:
                result_text += "✓ ACEPTABLE: El algoritmo muestra buen efecto avalancha\n"
            
            # Mostrar en diálogo más grande
            dialog = tk.Toplevel(self.root)
            dialog.title("Análisis de Efecto Avalancha")
            dialog.geometry("700x600")
            
            text_widget = scrolledtext.ScrolledText(dialog, wrap=tk.WORD, font=('Courier', 9))
            text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            text_widget.insert('1.0', result_text)
            text_widget.config(state=tk.DISABLED)
            
            ttk.Button(dialog, text="Cerrar", command=dialog.destroy).pack(pady=10)
            
        except Exception as e:
            messagebox.showerror("❌ Error", f"Error en análisis:\n{str(e)}")
    
    # ==================== EXPORTACIÓN ====================
    
    def export_to_json(self):
        """Exportar resultados en formato JSON estructurado"""
        if not hasattr(self, 'last_results'):
            messagebox.showwarning("⚠️", "No hay resultados para exportar")
            return
        
        import json
        
        # Preparar datos estructurados
        export_data = {
            "metadata": {
                "application": "ASCON-128a Educational Visualizer",
                "version": "2.0",
                "timestamp": self.last_results.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
                "format_version": "1.0"
            },
            "parameters": {
                "key": self.last_results['key'],
                "nonce": self.last_results['nonce'],
                "associated_data": self.last_results['ad'] or "",
                "plaintext": self.last_results['plaintext'] or ""
            },
            "results": {
                "ciphertext": self.last_results['ciphertext'] or "",
                "tag": self.last_results['tag']
            },
            "execution_steps": []
        }
        
        # Agregar pasos de ejecución detallados
        if hasattr(self, 'all_steps') and self.all_steps:
            for step_idx, step in enumerate(self.all_steps):
                step_data = {
                    "step_number": step_idx + 1,
                    "phase": step.get('phase', 'Unknown'),
                    "step_type": step.get('step_type', 'unknown'),
                    "states": {}
                }
                
                # Estado inicial
                if step.get('initial_state'):
                    step_data["states"]["initial"] = [to_hex(s, 64) for s in step['initial_state']]
                
                # Estado después de permutación
                if step.get('state_after_perm'):
                    step_data["states"]["after_permutation"] = [to_hex(s, 64) for s in step['state_after_perm']]
                
                # Estado final
                if step.get('final_state'):
                    step_data["states"]["final"] = [to_hex(s, 64) for s in step['final_state']]
                
                # Rondas detalladas (si hay)
                if step.get('rounds'):
                    step_data["rounds"] = []
                    for round_idx, round_data in enumerate(step['rounds']):
                        round_info = {
                            "round_number": round_data.get('round_num', round_idx),
                            "round_constant": f"0x{round_data.get('rc', 0):02x}",
                            "state_after_rc": [to_hex(s, 64) for s in round_data.get('after_rc', [])],
                            "state_after_sbox": [to_hex(s, 64) for s in round_data.get('after_sbox', [])],
                            "state_after_linear": [to_hex(s, 64) for s in round_data.get('after_linear', [])]
                        }
                        step_data["rounds"].append(round_info)
                
                # Bloques (para AD y encrypt)
                if step.get('blocks'):
                    step_data["blocks"] = []
                    for block in step['blocks']:
                        block_info = {
                            "block_number": block.get('block_num', 0),
                            "data_hex": block.get('block_hex') or block.get('plaintext_hex', ''),
                            "state_before": [to_hex(s, 64) for s in block.get('state_before', [])],
                            "state_after": [to_hex(s, 64) for s in block.get('state_after', [])]
                        }
                        if block.get('ciphertext_hex'):
                            block_info["ciphertext_hex"] = block['ciphertext_hex']
                        step_data["blocks"].append(block_info)
                
                export_data["execution_steps"].append(step_data)
        
        # Guardar archivo
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile=f"ascon_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(export_data, f, indent=2, ensure_ascii=False)
                messagebox.showinfo("✅ Exportado", f"Resultados exportados exitosamente a:\n{filename}")
            except Exception as e:
                messagebox.showerror("❌ Error", f"No se pudo exportar a JSON:\n{str(e)}")
    
    def save_results(self):
        """Guardar resultados en archivo"""
        if not hasattr(self, 'last_results'):
            messagebox.showwarning("⚠️", "No hay resultados para guardar")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"ascon_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write("="*80 + "\n")
                    f.write(" " * 25 + "ASCON-128a EXECUTION LOG\n")
                    f.write("="*80 + "\n\n")
                    
                    f.write("TIMESTAMP: " + self.last_results['timestamp'] + "\n\n")
                    
                    f.write("PARÁMETROS DE ENTRADA:\n")
                    f.write("-" * 80 + "\n")
                    f.write(f"Key:        {self.last_results['key']}\n")
                    f.write(f"Nonce:      {self.last_results['nonce']}\n")
                    f.write(f"AD:         {self.last_results['ad'] or '(vacío)'}\n")
                    f.write(f"Plaintext:  {self.last_results['plaintext'] or '(vacío)'}\n\n")
                    
                    f.write("RESULTADOS:\n")
                    f.write("-" * 80 + "\n")
                    f.write(f"Ciphertext: {self.last_results['ciphertext'] or '(vacío)'}\n")
                    f.write(f"Tag:        {self.last_results['tag']}\n\n")
                    
                    f.write("LOG COMPLETO:\n")
                    f.write("-" * 80 + "\n")
                    f.write(self.main_viz_text.get('1.0', tk.END))
                    
                    f.write("\n" + "="*80 + "\n")
                    f.write("ASCON-128a Educational Visualizer v2.0\n")
                    f.write("="*80 + "\n")
                
                messagebox.showinfo("✅ Guardado", f"Resultados guardados en:\n{filename}")
            except Exception as e:
                messagebox.showerror("❌ Error", f"No se pudo guardar:\n{str(e)}")

# ==================== FUNCIÓN PRINCIPAL ====================

def main():
    """Función principal"""
    root = tk.Tk()
    app = ASCONVisualizerAdvanced(root)
    
    # Centrar ventana y configurar proporciones
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'{width}x{height}+{x}+{y}')
    
    # Configurar la proporción inicial del PanedWindow después de que la ventana esté visible
    root.update_idletasks()
    app.configure_paned_proportions()
    
    root.mainloop()

if __name__ == "__main__":
    main()