# 컴파일러 설정
CXX = g++

# 컴파일러 플래그 설정
CXXFLAGS = -Wall -Wextra -O2 -std=c++17 -I/usr/local/include/pcapplusplus -I.

# 링커 플래그 설정 (순서 조정)
LDFLAGS = -lPcap++ -lPacket++ -lCommon++ -lpcap -lpthread -lsqlite3

# 최종 타겟 설정
TARGET = NetworkProtecter

# 소스 파일과 헤더 파일 찾기
SOURCES = $(wildcard firewall.cpp)
HEADERS = $(wildcard firewall.hpp)
OBJECTS = $(SOURCES:.cpp=.o)

# 기본 타겟 설정
all: $(TARGET)
	@echo "Build successful!"
	@$(MAKE) clean

# 최종 실행 파일 생성 규칙
$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) || (echo "Build failed!"; exit 1)

# 소스 파일을 오브젝트 파일로 컴파일
%.o: %.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) -c $< -o $@ || (echo "Compilation failed on $<"; exit 1)

# 'make clean'을 실행할 때 오브젝트 파일 제거
clean:
	rm -f $(OBJECTS)
