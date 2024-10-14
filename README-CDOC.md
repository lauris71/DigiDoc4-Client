# Digidoc client + libcdoc

This is a temporary development version that links statically with libcdoc development version.

1. Clone libcdoc repository

        cd client
        git clone git@github.com:open-eid/libcdoc.git
        cd libcdoc
        cmake -B build -S .
        cmake --build build

2. Build DigiDoc client the normal way
