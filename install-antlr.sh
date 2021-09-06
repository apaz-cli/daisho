# Install Antlr4 jar
if [ ! -f "/usr/local/lib/antlr4-complete.jar" ]; then
  curl -L "https://www.antlr.org/download/antlr4-cpp-runtime-4.9.2-source.zip" -o "/usr/local/lib/antlr4-complete.jar"
fi

# Install the Antlr4 cpp runtime if necesary 
if [ ! -d "/usr/local/include/antlr4-runtime" ]; then

  # Install necessary packages
  packagesNeeded='uuid-dev pkg-config cmake'
  if   [ -x "$(command -v apk)" ];     then sudo apk add --no-cache $packagesNeeded
  elif [ -x "$(command -v apt-get)" ]; then sudo apt-get install $packagesNeeded
  elif [ -x "$(command -v dnf)" ];     then sudo dnf install $packagesNeeded
  elif [ -x "$(command -v zypper)" ];  then sudo zypper install $packagesNeeded
  else echo "FAILED TO INSTALL PACKAGE: Package manager not found. You must manually install: $packagesNeeded">&2; exit 1;
  fi

  # Download the cpp runtime
  mkdir antlrcpp && cd antlrcpp
  curl -L "https://www.antlr.org/download/antlr4-cpp-runtime-4.9.2-source.zip" -o "antlr-cpp-runtime.zip"
  unzip antlr-cpp-runtime.zip 

  # Build it
  mkdir build run && cd build
  cmake ..
  DESTDIR=../run make install -j 8

  # Install it
  cd ../run/usr/local/include
  sudo cp -r antlr4-runtime /usr/local/include
  cd ../lib
  sudo cp * /usr/local/lib
  sudo ldconfig

  # Clean up
  cd ../../../../..
  rm -rf antlrcpp
fi


cd src/antlr/
./build
cp 
