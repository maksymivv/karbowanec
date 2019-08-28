include_directories(include)

set (YESPOWER_SRC
  "include/yespower.h"
  "include/sysendian.h"
  "insecure_memzero.h"
  "sha256.h"
  "sha256.c"
  "yespower-platform.c"
  "yespower-opt.c"
)

add_library (yespower STATIC ${YESPOWER_SRC})
set_target_properties(yespower PROPERTIES LINKER_LANGUAGE C)