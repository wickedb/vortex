#include <vx_spawn2.h>
#include "common.h"

// Never launched: this regression moves data only through the command
// processor. The build expects a kernel.
__kernel void kernel_main(kernel_arg_t* __UNIFORM__ arg) {
	(void)arg;
}
