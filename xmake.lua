set_project("elanfp")
set_version("0.1.0")

add_rules("mode.debug", "mode.release")
set_defaultmode("release")
set_languages("c11")
set_warnings("allextra")
set_toolset("ld", "gcc")
set_toolset("sh", "gcc")

add_requires("libusb", {system = true})

-- driver, matcher and storage
target("elanfp-core")
    set_kind("static")
    add_files("src/elan.c", "src/match.c", "src/store.c")
    add_headerfiles("src/*.h")
    add_includedirs("src", {public = true})
    add_cflags("-fPIC")
    add_packages("libusb")
    add_syslinks("m", {public = true})

target("elanfp")
    set_kind("binary")
    add_deps("elanfp-core")
    add_files("src/image.c", "src/main.c")
    add_packages("libusb")
