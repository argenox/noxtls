/* Test-only profile: override the linked software library's feature definitions. */
#ifndef NOXv_CCM_TEST_CONFIG_H
#define NOXv_CCM_TEST_CONFIG_H
#ifndef CCM_TEST_GATE_ON
#error "The CCM regression must select its expected accelerator gate"
#endif
#undef NOXTLS_FEATURE_NOXV_HW_ACCEL
#define NOXTLS_FEATURE_NOXV_HW_ACCEL 1
#undef NOXTLS_FEATURE_NOXV_CCM_ACCEL
#define NOXTLS_FEATURE_NOXV_CCM_ACCEL CCM_TEST_GATE_ON
#endif
