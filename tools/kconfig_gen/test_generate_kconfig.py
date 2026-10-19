# SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
"""Regression checks for Zephyr Kconfig scalar configuration generation."""
import unittest
import xml.etree.ElementTree as ET
import generate_kconfig as generator


class ScalarConfigurationTest(unittest.TestCase):
    def test_initializer_lists_and_enum_constants_are_not_settings(self):
        settings = generator.collect_all_settings(ET.parse(generator.CATALOG_XML).getroot())
        ids = {item.id for item in settings}
        for name in ('NOXTLS_MEM_BUCKET_COUNTS', 'NOXTLS_MEM_BUCKET_SIZES',
                     'NOXTLS_STATIC_ALLOCATOR_MODE_LEGACY',
                     'NOXTLS_STATIC_ALLOCATOR_MODE_BUCKETS',
                     'NOXTLS_STATIC_ALLOCATOR_MODE_HYBRID'):
            self.assertNotIn(name, ids)

    def test_all_scalar_integer_defaults_are_valid(self):
        settings = generator.collect_all_settings(ET.parse(generator.CATALOG_XML).getroot())
        for item in settings:
            if item.type == 'integer':
                with self.subTest(setting=item.id):
                    self.assertTrue(generator.parse_int_default(item.default).isdigit())

    def test_static_allocator_mode_remains_configurable(self):
        text = generator.generate_kconfig(ET.parse(generator.CATALOG_XML).getroot(), 'test')
        self.assertIn('config NOXTLS_STATIC_ALLOCATOR_MODE\n', text)
        self.assertIn('range 0 2', text)
        self.assertEqual(generator.parse_int_default('NOXTLS_STATIC_ALLOCATOR_MODE_HYBRID'), '2')

    def test_cc13xx_acceleration_controls_the_built_provider(self):
        settings = generator.collect_all_settings(ET.parse(generator.CATALOG_XML).getroot())
        text = generator.generate_cmake(settings, 'zephyr', 'test')
        for suffix in ('HW_ACCEL', 'AES_ACCEL', 'P256_ACCEL', 'X25519_ACCEL'):
            name = 'NOXTLS_FEATURE_CC13XX_' + suffix
            with self.subTest(feature=name):
                self.assertIn(name, {item.id for item in settings})
                self.assertIn('noxtls_zephyr_map_bool(CONFIG_' + name +
                              ' ' + name.replace('NOXTLS_', 'NOXTLS_CFG_', 1) + ')', text)
                self.assertNotIn('zephyr_compile_definitions(' + name + '=', text)


if __name__ == '__main__':
    unittest.main()
