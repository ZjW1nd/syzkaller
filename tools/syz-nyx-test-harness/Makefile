CXX := x86_64-w64-mingw32-g++

CXXFLAGS ?= -O2 -Wall -Wextra -I. -static -std=c++17
LDFLAGS ?= -lntdll -lpsapi -static

TARGET ?= syz_nyx_test_harness.exe

all: $(TARGET)

$(TARGET): main.cpp nyx_api.h
	$(CXX) $(CXXFLAGS) -o $@ main.cpp $(LDFLAGS)

clean:
	rm -f $(TARGET)
