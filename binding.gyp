{
    "targets": [
        {
            "target_name": "equihashverify",
            "dependencies": [

            ],
            "sources": [
                "support/cleanse.cpp",
                "uint256.cpp",
                "arith_uint256.cpp",
                "random.cpp",
                "util.cpp",
                "utilstrencodings.cpp",
                "crypto/equihash.cpp",
                "beam/core/difficulty.cpp",
                "beam/core/uintBig.cpp",
                "beam/utility/common.cpp",
                "crypto/blake/sse/blake2b.cpp",
                "equihashverify.cc"
            ],
            "include_dirs": [
                "<!(node -e \"require('nan')\")",
                ".",
                "/usr/include",
                "/usr/include/boost",
            ],
            "libararies": [
                "/usr/lib/x86_64-linux-gnu"
            ],
            "defines": [
                "HAVE_DECL_STRNLEN=1",
                "HAVE_BYTESWAP_H=1"
            ],
            "cflags_cc": [
                "-std=c++11",
                "-Wl,--whole-archive",
                "-fPIC",
                "-fexceptions"

            ],
            "link_settings": {
                "libraries": [
                    "-Wl,-rpath,./build/Release/",
                    "-lboost_system",
                    "-lsodium"
                ]
            },
            'conditions': [
                ['OS=="mac"', {
                    'xcode_settings': {
                        'GCC_ENABLE_CPP_EXCEPTIONS': 'YES'
                    }
                }]
            ]
        }
    ]
}
