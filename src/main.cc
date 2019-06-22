#include <Zydis/Zydis.h>

#include "meow_hook/detour.h"

bool hook(int)
{
    return false;
}

int main()
{
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);

    meow_hook::detour<bool(int)> detour(0x0, hook);

    return 0;
}
