cd ./openssl 
make clean
export CC="${BUILD_TOOLS}/usr/bin/clang -fembed-bitcode -mmacosx-version-min=10.7"
./Configure no-asm darwin64-x86_64-cc 
make
cp *.a ../
cp ./include/openssl/*.h ../
