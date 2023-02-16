CC = g++
CPPFLAGS = -fPIC -Wall -Wextra -O2 -g -fpermissive `pkg-config --cflags --libs gtk+-3.0` `pkg-config --cflags --libs gio-2.0`
LDFLAGS = -shared -lpam -ldl -lX11
RM = shred -n 100 -vuz
TARGET_LIB = libjakshoo.so

SRCS = libjakshoo.cpp  # source files
OBJS = $(SRCS:.cpp=.o)

.PHONY: all
all: ${TARGET_LIB}

$(TARGET_LIB): $(OBJS)
	$(CC) ${LDFLAGS} -o $@ $^
	strip --strip-unneeded -s -R .note -R .comment ${TARGET_LIB}
	objcopy -S ${TARGET_LIB}


$(SRCS:.cpp=.d):%.d:%.cpp
	$(CC) $(CPPFLAGS) -MM $< >$@

include $(SRCS:.cpp=.d)

.PHONY: clean
clean:
	-${RM} ${TARGET_LIB} ${OBJS} $(SRCS:.cpp=.d)
