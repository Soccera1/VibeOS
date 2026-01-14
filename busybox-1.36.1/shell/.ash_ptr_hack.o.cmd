cmd_shell/ash_ptr_hack.o := gcc -m32 -Wp,-MD,shell/.ash_ptr_hack.o.d  -std=gnu99 -Iinclude -Ilibbb  -include include/autoconf.h -D_GNU_SOURCE -DNDEBUG  -DBB_VER='"1.36.1"' -malign-data=abi -Wall -Wshadow -Wwrite-strings -Wundef -Wstrict-prototypes -Wunused -Wunused-parameter -Wunused-function -Wunused-value -Wmissing-prototypes -Wmissing-declarations -Wno-format-security -Wdeclaration-after-statement -Wold-style-definition -finline-limit=0 -fno-builtin-strlen -fomit-frame-pointer -ffunction-sections -fdata-sections -fno-guess-branch-probability -funsigned-char -falign-functions=1 -falign-jumps=1 -falign-labels=1 -falign-loops=1 -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-builtin-printf -Oz -fno-stack-protector -U_FORTIFY_SOURCE -mno-sse -mno-mmx -mno-sse2    -DKBUILD_BASENAME='"ash_ptr_hack"'  -DKBUILD_MODNAME='"ash_ptr_hack"' -c -o shell/ash_ptr_hack.o shell/ash_ptr_hack.c

deps_shell/ash_ptr_hack.o := \
  shell/ash_ptr_hack.c \
  /usr/include/stdc-predef.h \

shell/ash_ptr_hack.o: $(deps_shell/ash_ptr_hack.o)

$(deps_shell/ash_ptr_hack.o):
