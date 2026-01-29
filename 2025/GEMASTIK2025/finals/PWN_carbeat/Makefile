CXX := g++
CXXFLAGS := -std=c++17 -Wall -Wextra

MYBINI_SRCS := mybini.cpp

.PHONY: all clean

all: mybini

mybini: $(MYBINI_SRCS)
	$(CXX) $(CXXFLAGS) $< -o $@

clean:
	rm -f mybini *.o