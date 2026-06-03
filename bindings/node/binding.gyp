{
  "variables": {
    "android_ndk_path": ""
  },
  "targets": [
    {
      "target_name": "vaultine",
      "sources": ["src/vaultine.cc"],
      "include_dirs": [
        "<!@(node -p \"require('node:path').relative('.', process.cwd() + '/../../include')\")"
      ],
      "libraries": ["-lssm"],
      "conditions": [
        ["OS=='linux' or OS=='android'", {
          "library_dirs": ["/data/data/com.termux/files/home/Projetos/Cpp/build/src"],
          "ldflags": ["-Wl,-rpath,$ORIGIN/../../../build/src"]
        }]
      ],
      "defines": ["NAPI_VERSION=9"],
      "cflags!": ["-fno-exceptions"],
      "cflags_cc!": ["-fno-exceptions"]
    }
  ]
}
