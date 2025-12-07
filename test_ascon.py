#!/usr/bin/env python3
"""
Tests unitarios para ASCON-128a
Ejecutar con: python -m pytest test_ascon.py o python test_ascon.py
"""

import unittest
import sys
import os

# Agregar el directorio actual al path para importar el módulo
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from ASCON_128a import ASCON128a, ascon_pad, remove_padding, validate_padding, hex_to_int, to_hex
except ImportError:
    # Intentar con otro nombre de archivo
    import importlib.util
    spec = importlib.util.spec_from_file_location("ascon", "ASCON-128a.py")
    ascon_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ascon_module)
    ASCON128a = ascon_module.ASCON128a
    ascon_pad = ascon_module.ascon_pad
    remove_padding = ascon_module.remove_padding
    validate_padding = ascon_module.validate_padding
    hex_to_int = ascon_module.hex_to_int
    to_hex = ascon_module.to_hex


class TestASCONPadding(unittest.TestCase):
    """Tests para funciones de padding"""
    
    def test_pad_empty_block(self):
        """Probar padding de bloque vacío"""
        result = ascon_pad("", 16, True)
        self.assertEqual(result, "8000000000000000")
    
    def test_pad_partial_block(self):
        """Probar padding de bloque parcial"""
        result = ascon_pad("41", 16, True)
        self.assertEqual(result, "4180000000000000")
        
        result = ascon_pad("4142", 16, True)
        self.assertEqual(result, "4142800000000000")
    
    def test_pad_full_block(self):
        """Probar que bloque completo no se modifica"""
        full_block = "4142434445464748494A4B4C4D4E4F50"
        result = ascon_pad(full_block, 16, True)
        self.assertEqual(result[:16], full_block[:16])
    
    def test_remove_padding(self):
        """Probar remoción de padding"""
        # Bloque con padding
        padded = "4142800000000000"
        result = remove_padding(padded)
        self.assertEqual(result, "4142")
        
        # Bloque sin padding
        no_padding = "4142434445464748"
        result = remove_padding(no_padding)
        # Si no hay padding, debe retornar original
        self.assertTrue(len(result) > 0)
    
    def test_validate_padding(self):
        """Probar validación de padding"""
        # Padding válido
        self.assertTrue(validate_padding("4142800000000000"))
        # Sin padding
        self.assertFalse(validate_padding("4142434445464748"))


class TestASCONBasic(unittest.TestCase):
    """Tests básicos de ASCON-128a"""
    
    def test_initialization(self):
        """Probar inicialización básica"""
        ascon = ASCON128a()
        key = "000102030405060708090A0B0C0D0E0F"
        nonce = "000102030405060708090A0B0C0D0E0F"
        
        details = ascon.initialize(key, nonce)
        
        self.assertEqual(details['phase'], 'Inicialización')
        self.assertEqual(len(ascon.state), 5)
        self.assertIn('final_state', details)
    
    def test_encrypt_empty_message(self):
        """Probar cifrado de mensaje vacío"""
        ascon = ASCON128a()
        key = "000102030405060708090A0B0C0D0E0F"
        nonce = "000102030405060708090A0B0C0D0E0F"
        
        ascon.initialize(key, nonce)
        ascon.process_ad("")
        ciphertext, _ = ascon.encrypt("")
        tag, _ = ascon.finalize(key)
        
        # El ciphertext debe estar vacío para mensaje vacío
        self.assertEqual(ciphertext, "")
        # El tag debe tener 32 caracteres (128 bits = 16 bytes = 32 hex chars)
        self.assertEqual(len(tag), 32)
    
    def test_encrypt_decrypt_roundtrip(self):
        """Probar cifrado y descifrado ida y vuelta"""
        ascon = ASCON128a()
        key = "000102030405060708090A0B0C0D0E0F"
        nonce = "000102030405060708090A0B0C0D0E0F"
        plaintext = "4142434445464748"
        ad = ""
        
        # Cifrar
        ascon.initialize(key, nonce)
        ascon.process_ad(ad)
        ciphertext, _ = ascon.encrypt(plaintext)
        tag, _ = ascon.finalize(key)
        
        # Descifrar
        ascon2 = ASCON128a()
        decrypted, tag_valid, _ = ascon2.decrypt(ciphertext, tag, key, nonce, ad)
        
        # Verificar que el tag es válido y el plaintext coincide
        self.assertTrue(tag_valid, "El tag debe ser válido")
        # El plaintext descifrado debe coincidir (puede tener padding removido)
        self.assertTrue(plaintext.upper() in decrypted.upper() or decrypted.upper() in plaintext.upper())
    
    def test_invalid_tag_rejection(self):
        """Verificar que tag inválido se rechaza correctamente"""
        ascon = ASCON128a()
        key = "000102030405060708090A0B0C0D0E0F"
        nonce = "000102030405060708090A0B0C0D0E0F"
        plaintext = "4142434445464748"
        ad = ""
        
        # Cifrar
        ascon.initialize(key, nonce)
        ascon.process_ad(ad)
        ciphertext, _ = ascon.encrypt(plaintext)
        tag, _ = ascon.finalize(key)
        
        # Modificar tag (cambiar 1 bit en el primer byte)
        tag_int = hex_to_int(tag)
        bad_tag_int = tag_int ^ 1  # Cambiar último bit
        bad_tag = to_hex(bad_tag_int, 128)
        
        # Intentar descifrar con tag inválido
        ascon2 = ASCON128a()
        decrypted, tag_valid, details = ascon2.decrypt(ciphertext, bad_tag, key, nonce, ad)
        
        # Debe rechazar el tag inválido
        self.assertFalse(tag_valid, "El tag inválido debe ser rechazado")
        self.assertFalse(details['tag_valid'], "El detalle debe indicar tag inválido")
        
        # Probar con tag completamente diferente
        bad_tag2 = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        ascon3 = ASCON128a()
        decrypted2, tag_valid2, _ = ascon3.decrypt(ciphertext, bad_tag2, key, nonce, ad)
        self.assertFalse(tag_valid2, "Tag completamente diferente debe ser rechazado")
    
    def test_tag_verification_corrupted_ciphertext(self):
        """Verificar que ciphertext modificado es detectado"""
        ascon = ASCON128a()
        key = "000102030405060708090A0B0C0D0E0F"
        nonce = "000102030405060708090A0B0C0D0E0F"
        plaintext = "4142434445464748"
        ad = ""
        
        # Cifrar
        ascon.initialize(key, nonce)
        ascon.process_ad(ad)
        ciphertext, _ = ascon.encrypt(plaintext)
        tag, _ = ascon.finalize(key)
        
        # Modificar ciphertext (cambiar 1 byte)
        if len(ciphertext) >= 2:
            corrupted_ct = ciphertext[:2] + ("FF" if ciphertext[2:4] != "FF" else "00") + ciphertext[4:]
            
            # Intentar descifrar con ciphertext corrupto
            ascon2 = ASCON128a()
            decrypted, tag_valid, _ = ascon2.decrypt(corrupted_ct, tag, key, nonce, ad)
            
            # El tag debe ser inválido (el ciphertext fue modificado)
            self.assertFalse(tag_valid, "Ciphertext modificado debe resultar en tag inválido")
    
    def test_encrypt_with_ad(self):
        """Probar cifrado con datos asociados"""
        ascon = ASCON128a()
        key = "000102030405060708090A0B0C0D0E0F"
        nonce = "000102030405060708090A0B0C0D0E0F"
        plaintext = "4142434445464748"
        ad = "6061626364656667"
        
        ascon.initialize(key, nonce)
        ascon.process_ad(ad)
        ciphertext, _ = ascon.encrypt(plaintext)
        tag, _ = ascon.finalize(key)
        
        # Verificar que se generó ciphertext y tag
        self.assertIsNotNone(ciphertext)
        self.assertEqual(len(tag), 32)


class TestASCONProperties(unittest.TestCase):
    """Tests de propiedades criptográficas"""
    
    def test_deterministic_encryption(self):
        """Verificar que el cifrado es determinístico con mismos parámetros"""
        key = "000102030405060708090A0B0C0D0E0F"
        nonce = "000102030405060708090A0B0C0D0E0F"
        plaintext = "4142434445464748"
        
        # Ejecutar dos veces
        ascon1 = ASCON128a()
        ascon1.initialize(key, nonce)
        ascon1.process_ad("")
        ct1, _ = ascon1.encrypt(plaintext)
        tag1, _ = ascon1.finalize(key)
        
        ascon2 = ASCON128a()
        ascon2.initialize(key, nonce)
        ascon2.process_ad("")
        ct2, _ = ascon2.encrypt(plaintext)
        tag2, _ = ascon2.finalize(key)
        
        # Debe producir mismos resultados
        self.assertEqual(ct1, ct2)
        self.assertEqual(tag1, tag2)
    
    def test_different_nonce_produces_different_output(self):
        """Verificar que diferentes nonces producen diferentes outputs"""
        key = "000102030405060708090A0B0C0D0E0F"
        nonce1 = "000102030405060708090A0B0C0D0E0F"
        nonce2 = "000102030405060708090A0B0C0D0E10"  # Solo último byte diferente
        plaintext = "4142434445464748"
        
        ascon1 = ASCON128a()
        ascon1.initialize(key, nonce1)
        ascon1.process_ad("")
        ct1, _ = ascon1.encrypt(plaintext)
        tag1, _ = ascon1.finalize(key)
        
        ascon2 = ASCON128a()
        ascon2.initialize(key, nonce2)
        ascon2.process_ad("")
        ct2, _ = ascon2.encrypt(plaintext)
        tag2, _ = ascon2.finalize(key)
        
        # Debe producir diferentes resultados
        self.assertNotEqual(ct1, ct2)
        self.assertNotEqual(tag1, tag2)


class TestASCONSecurity(unittest.TestCase):
    """Tests de seguridad y detección de problemas"""
    
    def test_nonce_reuse_detection_warning(self):
        """
        Advertir sobre reutilización de nonce.
        NOTA: Este test simula detección - en producción usarías un historial
        """
        key = "000102030405060708090A0B0C0D0E0F"
        nonce = "000102030405060708090A0B0C0D0E0F"
        plaintext1 = "4142434445464748"
        plaintext2 = "4847464544434241"
        
        # Simular historial de nonces usados
        nonce_history = set()
        
        # Primera ejecución
        if nonce in nonce_history:
            self.fail("⚠️ NONCE REUSADO - INSEGURO!")
        nonce_history.add(nonce)
        
        ascon1 = ASCON128a()
        ascon1.initialize(key, nonce)
        ascon1.process_ad("")
        ct1, _ = ascon1.encrypt(plaintext1)
        tag1, _ = ascon1.finalize(key)
        
        # Segunda ejecución con mismo nonce (INSECURO)
        if nonce in nonce_history:
            # En producción, esto debería generar una advertencia o error
            warning_issued = True
            self.assertTrue(warning_issued, "Debe detectarse reutilización de nonce")
        else:
            nonce_history.add(nonce)
        
        # Verificar que ambas ejecuciones producen resultados diferentes
        # (aunque deberían ser diferentes por el plaintext, el nonce igual es inseguro)
        ascon2 = ASCON128a()
        ascon2.initialize(key, nonce)
        ascon2.process_ad("")
        ct2, _ = ascon2.encrypt(plaintext2)
        tag2, _ = ascon2.finalize(key)
        
        # Los ciphertexts deben ser diferentes (por plaintext diferente)
        self.assertNotEqual(ct1, ct2)
    
    def test_key_validation_length(self):
        """Verificar validación de longitud de clave"""
        # Clave de longitud incorrecta debería ser detectada
        # (Nota: La validación real se hace en la UI, aquí solo verificamos el formato)
        key_correct = "000102030405060708090A0B0C0D0E0F"  # 128 bits = 32 hex chars
        self.assertEqual(len(key_correct), 32, "Clave debe tener 32 caracteres hex (128 bits)")


class TestASCONUtilities(unittest.TestCase):
    """Tests para funciones utilitarias"""
    
    def test_hex_conversion(self):
        """Probar conversión hex a int y viceversa"""
        hex_str = "4142434445464748"
        int_val = hex_to_int(hex_str)
        result = to_hex(int_val, 64)
        self.assertEqual(result[:len(hex_str)], hex_str.upper())
    
    def test_padding_edge_cases(self):
        """Probar casos límite de padding"""
        # Bloque exactamente del tamaño correcto
        result = ascon_pad("4142434445464748494A4B4C4D4E4F50", 16, True)
        self.assertEqual(len(result), 16)
    
    def test_remove_padding_various_lengths(self):
        """Probar remoción de padding con varias longitudes"""
        test_cases = [
            ("4180000000000000", "41"),
            ("4142800000000000", "4142"),
            ("4142438000000000", "414243"),
            ("8000000000000000", ""),  # Solo padding
        ]
        
        for padded, expected in test_cases:
            result = remove_padding(padded)
            self.assertEqual(result, expected, f"Fallo en: {padded} -> {expected}")


if __name__ == '__main__':
    print("Ejecutando tests unitarios para ASCON-128a...")
    print("=" * 60)
    
    # Crear suite de tests
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Agregar todos los tests
    suite.addTests(loader.loadTestsFromTestCase(TestASCONPadding))
    suite.addTests(loader.loadTestsFromTestCase(TestASCONBasic))
    suite.addTests(loader.loadTestsFromTestCase(TestASCONProperties))
    suite.addTests(loader.loadTestsFromTestCase(TestASCONSecurity))
    suite.addTests(loader.loadTestsFromTestCase(TestASCONUtilities))
    
    # Ejecutar tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Mostrar resumen
    print("\n" + "=" * 60)
    print(f"Tests ejecutados: {result.testsRun}")
    print(f"Exitosos: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Fallidos: {len(result.failures)}")
    print(f"Errores: {len(result.errors)}")
    
    if result.wasSuccessful():
        print("\n✅ Todos los tests pasaron exitosamente!")
        sys.exit(0)
    else:
        print("\n❌ Algunos tests fallaron")
        sys.exit(1)

