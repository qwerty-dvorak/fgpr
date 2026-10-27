set_project("elanfp")
set_version("0.1.0")

add_rules("mode.debug", "mode.release")
set_defaultmode("release")
set_languages("c11")
set_warnings("allextra")
set_toolset("ld", "gcc")
set_toolset("sh", "gcc")

add_requires("libusb", {system = true})

-- driver, matcher and storage, shared by the tool and the PAM module
target("elanfp-core")
    set_kind("static")
    add_files("src/elan.c", "src/auth.c", "src/match.c", "src/store.c")
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

-- PAM module: only pam_sm_* are exported
target("pam_elanfp")
    set_kind("shared")
    set_prefixname("")
    set_symbols("hidden")
    add_deps("elanfp-core")
    add_files("src/pam_elanfp.c")
    add_packages("libusb")
    add_syslinks("pam")

-- Experimental local software authenticator for browser WebAuthn.
-- OpenSSL 3 libcrypto provides randomness, SHA-256, EC keys and ES256.
target("elanfp-fido")
    set_kind("binary")
    add_deps("elanfp-core")
    add_files("src/fido/*.c")
    add_packages("libusb")
    add_syslinks("crypto")

target("test-fido")
    set_kind("binary")
    set_default(false)
    add_files("tests/fido.c", "src/fido/ctap.c", "src/fido/cbor.c",
              "src/fido/credential.c")
    add_includedirs("src/fido")
    add_syslinks("crypto")
