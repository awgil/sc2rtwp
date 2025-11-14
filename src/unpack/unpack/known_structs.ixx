export module unpack.known_structs;

import common;

// real definitions are in header file, so that we can import it into IDA
export
{
#define CHECK_SIZE(struct, size) static_assert(sizeof(struct) == size)
#include "known_structs.h"
#undef CHECK_SIZE
}
