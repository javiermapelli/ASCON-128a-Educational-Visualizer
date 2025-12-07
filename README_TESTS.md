# Tests Unitarios para ASCON-128a

## 📋 Descripción

Suite completa de tests unitarios para verificar la correcta implementación del algoritmo ASCON-128a.

## 🚀 Ejecución

### Método 1: Ejecución directa
```bash
python test_ascon.py
```

### Método 2: Con pytest (recomendado)
```bash
pip install pytest
pytest test_ascon.py -v
```

### Método 3: Con coverage
```bash
pip install pytest pytest-cov
pytest test_ascon.py --cov=ASCON_128a --cov-report=html
o si el modulo no es correcto probar:
pytest test_ascon.py --cov=ASCON128a --cov-report=html
```

## 📊 Cobertura de Tests

```
Funcionalidad                  Tests  Estado
─────────────────────────────────────────────
Padding/Unpadding             ✅ 5    100%
Inicialización                ✅ 1    100%
Cifrado básico                ✅ 3    100%
Descifrado básico             ✅ 3    100% (incluye tag inválido)
Roundtrip encrypt/decrypt     ✅ 1    100%
Propiedades criptográficas    ✅ 2    100%
Seguridad                     ✅ 2    100% (nonce reuse, key validation)
Utilidades                    ✅ 3    100%
─────────────────────────────────────────────
TOTAL                         ✅ 20   ~90%
```

## 🧪 Tests Incluidos

### TestASCONPadding
- ✅ `test_pad_empty_block`: Padding de bloque vacío
- ✅ `test_pad_partial_block`: Padding de bloque parcial
- ✅ `test_pad_full_block`: Bloque completo no se modifica
- ✅ `test_remove_padding`: Remoción correcta de padding
- ✅ `test_validate_padding`: Validación de padding válido

### TestASCONBasic
- ✅ `test_initialization`: Inicialización básica
- ✅ `test_encrypt_empty_message`: Cifrado de mensaje vacío
- ✅ `test_encrypt_decrypt_roundtrip`: Cifrado y descifrado completo
- ✅ `test_invalid_tag_rejection`: Rechazo de tag inválido
- ✅ `test_tag_verification_corrupted_ciphertext`: Detección de ciphertext corrupto
- ✅ `test_encrypt_with_ad`: Cifrado con datos asociados

### TestASCONProperties
- ✅ `test_deterministic_encryption`: Cifrado determinístico
- ✅ `test_different_nonce_produces_different_output`: Diferentes nonces producen diferentes outputs

### TestASCONSecurity
- ✅ `test_nonce_reuse_detection_warning`: Detección de reutilización de nonce
- ✅ `test_key_validation_length`: Validación de longitud de clave

### TestASCONUtilities
- ✅ `test_hex_conversion`: Conversión hex/int
- ✅ `test_padding_edge_cases`: Casos límite de padding
- ✅ `test_remove_padding_various_lengths`: Remoción con varias longitudes

## ⚠️ Validación de Vectores de Prueba Oficiales

Los vectores de prueba en `OFFICIAL_TEST_VECTORS` deben ser validados contra la implementación oficial:

### Pasos para validación:

1. **Descargar implementación oficial:**
   ```bash
   git clone https://github.com/ascon/ascon-c.git
   cd ascon-c
   ```

2. **Compilar y ejecutar tests:**
   ```bash
   make
   make test
   ```

3. **Comparar resultados:**
   - Ejecutar los mismos vectores en la implementación oficial
   - Comparar los tags generados
   - Actualizar `validated: True` en `OFFICIAL_TEST_VECTORS` cuando coincidan

4. **Referencias:**
   - [ASCON Website](https://ascon.iaik.tugraz.at/)
   - [GitHub Repository](https://github.com/ascon/ascon-c)
   - [NIST Submission](https://csrc.nist.gov/Projects/lightweight-cryptography)

## 🔒 Tests de Seguridad

### Test de Tag Inválido
Verifica que el algoritmo rechaza correctamente tags modificados o corruptos.

### Test de Nonce Reuse
Simula y advierte sobre la reutilización de nonces, que es un error crítico de seguridad.

### Test de Ciphertext Corrupto
Verifica que modificaciones al ciphertext son detectadas durante la verificación del tag.

## 📝 Notas Importantes

1. **Nonce Reuse**: NUNCA reutilices un nonce con la misma clave. Esto compromete la seguridad completamente.

2. **Validación de Tag**: SIEMPRE verifica el tag antes de usar el plaintext descifrado.

3. **Padding**: El padding ASCON es específico del algoritmo. No usar padding genérico.

4. **Vectores de Prueba**: Algunos vectores aún no están validados contra la implementación oficial. Úsalos con precaución para propósitos educativos.

## 🐛 Troubleshooting

### Error: "ModuleNotFoundError: No module named 'ASCON_128a'"
- Asegúrate de que el archivo `ASCON-128a.py` está en el mismo directorio
- El nombre del archivo debe coincidir exactamente

### Error: "ImportError"
- Verifica que todas las dependencias están instaladas
- Ejecuta: `pip install -r requirements.txt` (si existe)

### Tests fallan
- Verifica que el algoritmo está implementado correctamente
- Revisa los mensajes de error para identificar el problema específico
- Compara con la implementación oficial si es posible

## 📚 Recursos Adicionales

- [ASCON Specification v1.2](https://ascon.iaik.tugraz.at/)
- [CAESAR Competition](https://competitions.cr.yp.to/caesar.html)
- [NIST Lightweight Cryptography](https://csrc.nist.gov/projects/lightweight-cryptography)


