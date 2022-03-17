CXX=g++
CXXFLAGS=-std=c++11 

redfat.bin: redfat.bin.cpp
	$(CXX) $(CXXFLAGS) -o redfat.bin -O2 redfat.bin.cpp 
	strip redfat.bin

RedFatPlugin.so: RedFatPlugin.cpp
	$(CXX) $(CXXFLAGS) -fPIC -shared -o RedFatPlugin.so RedFatPlugin.cpp \
        -I E9PATCH/src/e9tool/ -O2
	strip RedFatPlugin.so

redfat-rt: redfat-rt.cpp
	E9PATCH/e9compile.sh redfat-rt.cpp -std=c++11 -I runtime/ \
        -I E9PATCH/src/e9patch/ -I E9PATCH/examples/ -Os -fno-exceptions

clean:
	rm -f redfat.bin RedFatPlugin.so redfat-rt e9patch e9tool

