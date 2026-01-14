cmd_libbb/hash_md5_sha256_x86-32_shaNI.o := gcc -m32 -Wp,-MD,libbb/.hash_md5_sha256_x86-32_shaNI.o.d  -std=gnu99 -Iinclude -Ilibbb  -include include/autoconf.h -D_GNU_SOURCE -DNDEBUG  -DBB_VER='"1.36.1"' -malign-data=abi -Wall -Wshadow -Wwrite-strings -Wundef -Wstrict-prototypes -Wunused -Wunused-parameter -Wunused-function -Wunused-value -Wmissing-prototypes -Wmissing-declarations -Wno-format-security -Wdeclaration-after-statement -Wold-style-definition -finline-limit=0 -fno-builtin-strlen -fomit-frame-pointer -ffunction-sections -fdata-sections -fno-guess-branch-probability -funsigned-char -falign-functions=1 -falign-jumps=1 -falign-labels=1 -falign-loops=1 -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-builtin-printf -Oz -fno-stack-protector -U_FORTIFY_SOURCE -mno-sse -mno-mmx -mno-sse2       -c -o libbb/hash_md5_sha256_x86-32_shaNI.o libbb/hash_md5_sha256_x86-32_shaNI.S

deps_libbb/hash_md5_sha256_x86-32_shaNI.o := \
  libbb/hash_md5_sha256_x86-32_shaNI.S \
    $(wildcard include/config/sha256/hwaccel.h) \
  /usr/include/stdc-predef.h \

libbb/hash_md5_sha256_x86-32_shaNI.o: $(deps_libbb/hash_md5_sha256_x86-32_shaNI.o)

$(deps_libbb/hash_md5_sha256_x86-32_shaNI.o):
