#define WIN32_LEAN_AND_MEAN
#include <windows.h>

/* lld fills the load-config offsets for the ARM64X dynamic relocations. */
const IMAGE_LOAD_CONFIG_DIRECTORY64 _load_config_used = {
    .Size = sizeof(IMAGE_LOAD_CONFIG_DIRECTORY64)
};
