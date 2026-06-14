// core.cpp
#include "core.h"
#include <sodium.h>
#include <cstring> // std::memcmp
#include <iostream>
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace cyph {

static constexpr const unsigned char MAGIC[8] = {'M','Y','C','Y','P','H','S','3'};
static constexpr std::uint8_t ALGO_VER = 1;
static constexpr std::size_t SALT_LEN = crypto_pwhash_SALTBYTES;
static constexpr std::size_t CHUNK = 1u << 20;

static bool has_ext(const std::string& path, const std::string& ext) {
    if (path.size() < ext.size()) return false;
    return path.compare(path.size() - ext.size(), ext.size(), ext) == 0;
}

static std::string ensure_ext(std::string out, const std::string& ext) {
    if (!has_ext(out, ext)) out += ext;
    return out;
}

std::string ensure_cyph_ext(std::string out) { return ensure_ext(std::move(out), EXT_CYPH); }
std::string ensure_cyphkey_ext(std::string out) { return ensure_ext(std::move(out), EXT_CYPHKEY); }

static void ensure_dir_exists(const fs::path& dir) {
    std::error_code ec;
    fs::create_directories(dir, ec);
    if (ec) throw std::runtime_error("Failed to create directory: " + dir.string());
}

static std::vector<unsigned char> read_file_bytes(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot open for reading: " + path);

    f.seekg(0, std::ios::end);
    std::streamoff n = f.tellg();
    f.seekg(0, std::ios::beg);
    if (n < 0) throw std::runtime_error("Failed to stat: " + path);

    std::vector<unsigned char> buf(static_cast<std::size_t>(n));
    if (n > 0) {
        f.read(reinterpret_cast<char*>(buf.data()), n);
        if (!f) throw std::runtime_error("Failed to read: " + path);
    }
    return buf;
}

static void secure_wipe(std::vector<unsigned char>& v) {
    if (!v.empty()) sodium_memzero(v.data(), v.size());
    v.clear();
    v.shrink_to_fit();
}

struct ContainerHeader {
    std::uint8_t algo_ver = 0;
    std::uint8_t flags = 0;
    unsigned long long opslimit = 0;
    unsigned long long memlimit_u64 = 0;
    unsigned char salt[SALT_LEN]{};
    unsigned char ss_header[crypto_secretstream_xchacha20poly1305_HEADERBYTES]{};
};

static void write_container_header(std::ofstream& out, const ContainerHeader& h) {
    out.write(reinterpret_cast<const char*>(MAGIC), sizeof(MAGIC));
    out.put(static_cast<char>(h.algo_ver));
    out.put(static_cast<char>(h.flags));
    out.write(reinterpret_cast<const char*>(&h.opslimit), sizeof(h.opslimit));
    out.write(reinterpret_cast<const char*>(&h.memlimit_u64), sizeof(h.memlimit_u64));
    out.write(reinterpret_cast<const char*>(h.salt), sizeof(h.salt));
    out.write(reinterpret_cast<const char*>(h.ss_header), sizeof(h.ss_header));
    if (!out) throw std::runtime_error("Failed to write header");
}

static ContainerHeader read_container_header(std::ifstream& in, const std::string& path_for_err) {
    ContainerHeader h{};
    unsigned char magic[sizeof(MAGIC)];

    in.read(reinterpret_cast<char*>(magic), sizeof(magic));
    if (!in) throw std::runtime_error("Invalid/corrupt file header: " + path_for_err);

    if (sodium_memcmp(magic, MAGIC, sizeof(MAGIC)) != 0) {
        throw std::runtime_error("Bad magic/version: " + path_for_err);
    }

    int av = in.get();
    int fl = in.get();
    if (av == EOF || fl == EOF) throw std::runtime_error("Corrupt header: " + path_for_err);
    h.algo_ver = static_cast<std::uint8_t>(av);
    h.flags = static_cast<std::uint8_t>(fl);

    in.read(reinterpret_cast<char*>(&h.opslimit), sizeof(h.opslimit));
    in.read(reinterpret_cast<char*>(&h.memlimit_u64), sizeof(h.memlimit_u64));
    in.read(reinterpret_cast<char*>(h.salt), sizeof(h.salt));
    in.read(reinterpret_cast<char*>(h.ss_header), sizeof(h.ss_header));
    if (!in) throw std::runtime_error("Invalid/corrupt file header: " + path_for_err);

    if (h.algo_ver != ALGO_VER) {
        throw std::runtime_error("Unsupported algo version in file: " + path_for_err);
    }

    return h;
}

static KdfParams kdf_from_header(const ContainerHeader& h) {
    KdfParams k{h.opslimit, static_cast<std::size_t>(h.memlimit_u64)};
    if (k.memlimit == 0 || k.opslimit == 0) throw std::runtime_error("Corrupt KDF params in header");
    return k;
}

KdfParams kdf_params_for_level(int level) {
    if (level < 0) level = 0;
    if (level > 2) level = 2;

    switch (level) {
        case 0:
            return {crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE};
        case 1:
            return {crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE};
        case 2:
        default:
            return {crypto_pwhash_OPSLIMIT_SENSITIVE, crypto_pwhash_MEMLIMIT_SENSITIVE};
    }
}

static void derive_key(unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES],
                       const unsigned char salt[SALT_LEN],
                       const std::vector<unsigned char>& key_material,
                       const KdfParams& kdf) {
    if (key_material.empty()) throw std::runtime_error("Key material is empty");

    const char* pw = reinterpret_cast<const char*>(key_material.data());
    const std::size_t pwlen = key_material.size();

    if (crypto_pwhash(key, crypto_secretstream_xchacha20poly1305_KEYBYTES,
                      pw, pwlen, salt,
                      kdf.opslimit, kdf.memlimit,
                      crypto_pwhash_ALG_DEFAULT) != 0) {
        throw std::runtime_error("crypto_pwhash failed (OOM?)");
    }
}

void encrypt_file_stream(const std::string& in_path,
                         const std::string& out_path,
                         const std::vector<unsigned char>& key_material,
                         const KdfParams& kdf,
                         std::uint8_t flags,
                         const std::string& meta_name) {
    std::ifstream in(in_path, std::ios::binary);
    if (!in) throw std::runtime_error("Cannot open input: " + in_path);

    fs::path outp(out_path);
    if (!outp.parent_path().empty()) ensure_dir_exists(outp.parent_path());

    std::ofstream out(out_path, std::ios::binary | std::ios::trunc);
    if (!out) throw std::runtime_error("Cannot open output: " + out_path);

    ContainerHeader h{};
    h.algo_ver = ALGO_VER;
    h.flags = flags;
    h.opslimit = kdf.opslimit;
    h.memlimit_u64 = static_cast<unsigned long long>(kdf.memlimit);
    randombytes_buf(h.salt, sizeof h.salt);

    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    derive_key(key, h.salt, key_material, kdf);

    crypto_secretstream_xchacha20poly1305_state st;
    if (crypto_secretstream_xchacha20poly1305_init_push(&st, h.ss_header, key) != 0) {
        sodium_memzero(key, sizeof key);
        throw std::runtime_error("secretstream init_push failed");
    }

    write_container_header(out, h);

    std::vector<unsigned char> meta(meta_name.begin(), meta_name.end());
    std::vector<unsigned char> meta_ct(meta.size() + crypto_secretstream_xchacha20poly1305_ABYTES);
    unsigned long long meta_ct_len = 0;

    if (crypto_secretstream_xchacha20poly1305_push(
            &st, meta_ct.data(), &meta_ct_len,
            meta.data(), meta.size(),
            nullptr, 0,
            crypto_secretstream_xchacha20poly1305_TAG_MESSAGE) != 0) {
        sodium_memzero(key, sizeof key);
        throw std::runtime_error("secretstream push(meta) failed");
    }

    meta_ct.resize(static_cast<std::size_t>(meta_ct_len));
    std::uint32_t L = static_cast<std::uint32_t>(meta_ct.size());
    out.write(reinterpret_cast<const char*>(&L), sizeof(L));
    out.write(reinterpret_cast<const char*>(meta_ct.data()),
              static_cast<std::streamsize>(meta_ct.size()));
    if (!out) {
        sodium_memzero(key, sizeof key);
        throw std::runtime_error("Failed to write meta frame: " + out_path);
    }

    std::vector<unsigned char> buf(CHUNK);
    std::vector<unsigned char> ct(CHUNK + crypto_secretstream_xchacha20poly1305_ABYTES);

    while (true) {
        in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
        std::streamsize got = in.gcount();
        if (got < 0) got = 0;

        const bool eof = in.eof();
        unsigned char tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL
                                : crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;

        unsigned long long ct_len = 0;
        if (crypto_secretstream_xchacha20poly1305_push(
                &st, ct.data(), &ct_len,
                buf.data(), static_cast<std::size_t>(got),
                nullptr, 0,
                tag) != 0) {
            sodium_memzero(key, sizeof key);
            throw std::runtime_error("secretstream push(data) failed");
        }

        std::uint32_t len32 = static_cast<std::uint32_t>(ct_len);
        out.write(reinterpret_cast<const char*>(&len32), sizeof(len32));
        out.write(reinterpret_cast<const char*>(ct.data()), static_cast<std::streamsize>(ct_len));
        if (!out) {
            sodium_memzero(key, sizeof key);
            throw std::runtime_error("Failed to write ciphertext frame");
        }

        if (eof) break;
    }

    sodium_memzero(key, sizeof key);
}

std::string read_restored_name_quick(const std::string& enc_in,
                                    const std::vector<unsigned char>& key_material) {
    std::ifstream in(enc_in, std::ios::binary);
    if (!in) throw std::runtime_error("Cannot open input: " + enc_in);

    ContainerHeader h = read_container_header(in, enc_in);
    KdfParams kdf = kdf_from_header(h);

    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    derive_key(key, h.salt, key_material, kdf);

    crypto_secretstream_xchacha20poly1305_state st;
    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, h.ss_header, key) != 0) {
        sodium_memzero(key, sizeof key);
        throw std::runtime_error("secretstream init_pull failed");
    }

    std::uint32_t len32 = 0;
    in.read(reinterpret_cast<char*>(&len32), sizeof(len32));
    if (!in) {
        sodium_memzero(key, sizeof key);
        throw std::runtime_error("Missing meta frame");
    }

    std::vector<unsigned char> meta_ct(len32);
    in.read(reinterpret_cast<char*>(meta_ct.data()),
            static_cast<std::streamsize>(meta_ct.size()));
    if (!in) {
        sodium_memzero(key, sizeof key);
        throw std::runtime_error("Corrupt meta frame");
    }

    std::vector<unsigned char> meta_pt(meta_ct.size());
    unsigned long long meta_pt_len = 0;
    unsigned char tag = 0;

    if (crypto_secretstream_xchacha20poly1305_pull(
            &st, meta_pt.data(), &meta_pt_len,
            &tag,
            meta_ct.data(), meta_ct.size(),
            nullptr, 0) != 0) {
        sodium_memzero(key, sizeof key);
        throw std::runtime_error("Wrong key or corrupt file (meta)");
    }

    meta_pt.resize(static_cast<std::size_t>(meta_pt_len));
    std::string restored(reinterpret_cast<const char*>(meta_pt.data()), meta_pt.size());
    sodium_memzero(key, sizeof key);
    return restored;
}

static void write_stdout(const unsigned char* p, std::size_t n) {
    std::cout.write(reinterpret_cast<const char*>(p), static_cast<std::streamsize>(n));
    if (!std::cout) throw std::runtime_error("Failed to write to stdout");
}

void decrypt_file_stream(const std::string& enc_path,
                         const std::string& out_path_or_empty,
                         const std::vector<unsigned char>& key_material,
                         bool to_stdout,
                         bool write_file) {
    std::ifstream in(enc_path, std::ios::binary);
    if (!in) throw std::runtime_error("Cannot open input: " + enc_path);

    ContainerHeader h = read_container_header(in, enc_path);
    KdfParams kdf = kdf_from_header(h);

    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    derive_key(key, h.salt, key_material, kdf);

    crypto_secretstream_xchacha20poly1305_state st;
    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, h.ss_header, key) != 0) {
        sodium_memzero(key, sizeof key);
        throw std::runtime_error("secretstream init_pull failed");
    }

    auto read_frame = [&](std::vector<unsigned char>& frame) -> bool {
        std::uint32_t len32 = 0;
        in.read(reinterpret_cast<char*>(&len32), sizeof(len32));
        if (!in) return false;
        frame.resize(len32);
        in.read(reinterpret_cast<char*>(frame.data()), static_cast<std::streamsize>(len32));
        if (!in) throw std::runtime_error("Corrupt ciphertext frame");
        return true;
    };

    std::vector<unsigned char> meta_ct;
    if (!read_frame(meta_ct)) {
        sodium_memzero(key, sizeof key);
        throw std::runtime_error("Missing meta frame");
    }

    std::vector<unsigned char> meta_pt(meta_ct.size());
    unsigned long long meta_pt_len = 0;
    unsigned char meta_tag = 0;
    if (crypto_secretstream_xchacha20poly1305_pull(
            &st, meta_pt.data(), &meta_pt_len, &meta_tag,
            meta_ct.data(), meta_ct.size(),
            nullptr, 0) != 0) {
        sodium_memzero(key, sizeof key);
        throw std::runtime_error("Wrong key or corrupt file (meta)");
    }

    std::ofstream out;
    if (write_file && !out_path_or_empty.empty()) {
        fs::path outp(out_path_or_empty);
        if (!outp.parent_path().empty()) ensure_dir_exists(outp.parent_path());
        out.open(out_path_or_empty, std::ios::binary | std::ios::trunc);
        if (!out) {
            sodium_memzero(key, sizeof key);
            throw std::runtime_error("Cannot open output: " + out_path_or_empty);
        }
    }

    std::vector<unsigned char> ct;
    std::vector<unsigned char> pt(CHUNK + crypto_secretstream_xchacha20poly1305_ABYTES);

    bool done = false;
    while (!done) {
        if (!read_frame(ct)) break;

        unsigned long long pt_len = 0;
        unsigned char tag = 0;

        if (crypto_secretstream_xchacha20poly1305_pull(
                &st,
                pt.data(), &pt_len,
                &tag,
                ct.data(), ct.size(),
                nullptr, 0) != 0) {
            sodium_memzero(key, sizeof key);
            throw std::runtime_error("Wrong key or corrupt file (data)");
        }

        if (pt_len > 0) {
            if (to_stdout) write_stdout(pt.data(), static_cast<std::size_t>(pt_len));
            if (write_file && out) {
                out.write(reinterpret_cast<const char*>(pt.data()),
                          static_cast<std::streamsize>(pt_len));
                if (!out) {
                    sodium_memzero(key, sizeof key);
                    throw std::runtime_error("Failed to write output file");
                }
            }
        }

        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) done = true;
    }

    if (!done) {
        sodium_memzero(key, sizeof key);
        throw std::runtime_error("Corrupt file: missing FINAL tag");
    }

    sodium_memzero(key, sizeof key);
}

std::vector<unsigned char> decrypt_payload_to_bytes(const std::string& enc_path,
                                                   const std::vector<unsigned char>& key_material) {
    std::ifstream in(enc_path, std::ios::binary);
    if (!in) throw std::runtime_error("Cannot open input: " + enc_path);

    ContainerHeader h = read_container_header(in, enc_path);
    KdfParams kdf = kdf_from_header(h);

    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    derive_key(key, h.salt, key_material, kdf);

    crypto_secretstream_xchacha20poly1305_state st;
    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, h.ss_header, key) != 0) {
        sodium_memzero(key, sizeof key);
        throw std::runtime_error("secretstream init_pull failed");
    }

    auto read_frame = [&](std::vector<unsigned char>& frame) -> bool {
        std::uint32_t len32 = 0;
        in.read(reinterpret_cast<char*>(&len32), sizeof(len32));
        if (!in) return false;
        frame.resize(len32);
        in.read(reinterpret_cast<char*>(frame.data()), static_cast<std::streamsize>(len32));
        if (!in) throw std::runtime_error("Corrupt ciphertext frame");
        return true;
    };

    std::vector<unsigned char> meta_ct;
    if (!read_frame(meta_ct)) {
        sodium_memzero(key, sizeof key);
        throw std::runtime_error("Missing meta frame");
    }

    std::vector<unsigned char> meta_pt(meta_ct.size());
    unsigned long long meta_pt_len = 0;
    unsigned char meta_tag = 0;
    if (crypto_secretstream_xchacha20poly1305_pull(
            &st, meta_pt.data(), &meta_pt_len, &meta_tag,
            meta_ct.data(), meta_ct.size(),
            nullptr, 0) != 0) {
        sodium_memzero(key, sizeof key);
        throw std::runtime_error("Wrong key or corrupt file (meta)");
    }

    std::vector<unsigned char> out_bytes;
    std::vector<unsigned char> ct;
    std::vector<unsigned char> pt(CHUNK + crypto_secretstream_xchacha20poly1305_ABYTES);

    bool done = false;
    while (!done) {
        if (!read_frame(ct)) break;

        unsigned long long pt_len = 0;
        unsigned char tag = 0;

        if (crypto_secretstream_xchacha20poly1305_pull(
                &st,
                pt.data(), &pt_len,
                &tag,
                ct.data(), ct.size(),
                nullptr, 0) != 0) {
            sodium_memzero(key, sizeof key);
            throw std::runtime_error("Wrong key or corrupt file (data)");
        }

        if (pt_len > 0) {
            const std::size_t old = out_bytes.size();
            out_bytes.resize(old + static_cast<std::size_t>(pt_len));
            std::memcpy(out_bytes.data() + old, pt.data(), static_cast<std::size_t>(pt_len));
        }

        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) done = true;
    }

    if (!done) {
        sodium_memzero(key, sizeof key);
        throw std::runtime_error("Corrupt file: missing FINAL tag");
    }

    sodium_memzero(key, sizeof key);
    return out_bytes;
}

void create_cyphkey_file(const std::string& input_keyfile,
                         const std::string& out_name_or_path,
                         const std::vector<unsigned char>& master_key_material,
                         const KdfParams& kdf) {
    std::vector<unsigned char> plain = read_file_bytes(input_keyfile);
    std::string out_path = ensure_cyphkey_ext(out_name_or_path);

    fs::path outp(out_path);
    if (!outp.parent_path().empty()) ensure_dir_exists(outp.parent_path());

    std::ofstream out(out_path, std::ios::binary | std::ios::trunc);
    if (!out) throw std::runtime_error("Cannot open output: " + out_path);

    ContainerHeader h{};
    h.algo_ver = ALGO_VER;
    h.flags = 0;
    h.opslimit = kdf.opslimit;
    h.memlimit_u64 = static_cast<unsigned long long>(kdf.memlimit);
    randombytes_buf(h.salt, sizeof h.salt);

    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    derive_key(key, h.salt, master_key_material, kdf);

    crypto_secretstream_xchacha20poly1305_state st;
    if (crypto_secretstream_xchacha20poly1305_init_push(&st, h.ss_header, key) != 0) {
        sodium_memzero(key, sizeof key);
        throw std::runtime_error("secretstream init_push failed");
    }

    write_container_header(out, h);

    const std::string meta_name = "cyphkey";
    std::vector<unsigned char> meta(meta_name.begin(), meta_name.end());
    std::vector<unsigned char> meta_ct(meta.size() + crypto_secretstream_xchacha20poly1305_ABYTES);
    unsigned long long meta_ct_len = 0;

    if (crypto_secretstream_xchacha20poly1305_push(
            &st, meta_ct.data(), &meta_ct_len,
            meta.data(), meta.size(),
            nullptr, 0,
            crypto_secretstream_xchacha20poly1305_TAG_MESSAGE) != 0) {
        sodium_memzero(key, sizeof key);
        throw std::runtime_error("secretstream push(meta) failed");
    }

    meta_ct.resize(static_cast<std::size_t>(meta_ct_len));
    std::uint32_t L = static_cast<std::uint32_t>(meta_ct.size());
    out.write(reinterpret_cast<const char*>(&L), sizeof(L));
    out.write(reinterpret_cast<const char*>(meta_ct.data()),
              static_cast<std::streamsize>(meta_ct.size()));
    if (!out) {
        sodium_memzero(key, sizeof key);
        throw std::runtime_error("Failed to write meta frame: " + out_path);
    }

    std::vector<unsigned char> ct(CHUNK + crypto_secretstream_xchacha20poly1305_ABYTES);
    std::size_t off = 0;

    while (off < plain.size()) {
        std::size_t take = std::min<std::size_t>(CHUNK, plain.size() - off);
        unsigned char tag = ((off + take) == plain.size())
                                ? crypto_secretstream_xchacha20poly1305_TAG_FINAL
                                : crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;

        unsigned long long ct_len = 0;
        if (crypto_secretstream_xchacha20poly1305_push(
                &st, ct.data(), &ct_len,
                plain.data() + off, take,
                nullptr, 0,
                tag) != 0) {
            sodium_memzero(key, sizeof key);
            throw std::runtime_error("secretstream push(data) failed");
        }

        std::uint32_t len32 = static_cast<std::uint32_t>(ct_len);
        out.write(reinterpret_cast<const char*>(&len32), sizeof(len32));
        out.write(reinterpret_cast<const char*>(ct.data()), static_cast<std::streamsize>(ct_len));
        if (!out) {
            sodium_memzero(key, sizeof key);
            throw std::runtime_error("Failed to write ciphertext frame");
        }

        off += take;
    }

    if (plain.empty()) {
        unsigned long long ct_len = 0;
        if (crypto_secretstream_xchacha20poly1305_push(
                &st, ct.data(), &ct_len,
                nullptr, 0,
                nullptr, 0,
                crypto_secretstream_xchacha20poly1305_TAG_FINAL) != 0) {
            sodium_memzero(key, sizeof key);
            throw std::runtime_error("secretstream push(final-empty) failed");
        }
        std::uint32_t len32 = static_cast<std::uint32_t>(ct_len);
        out.write(reinterpret_cast<const char*>(&len32), sizeof(len32));
        out.write(reinterpret_cast<const char*>(ct.data()), static_cast<std::streamsize>(ct_len));
        if (!out) {
            sodium_memzero(key, sizeof key);
            throw std::runtime_error("Failed to write ciphertext frame");
        }
    }

    sodium_memzero(key, sizeof key);
    secure_wipe(plain);
}

void create_cyphkey_from_bytes(const std::vector<unsigned char>& plain,
                               const std::string& out_name_or_path,
                               const std::vector<unsigned char>& password_key_material,
                               const KdfParams& kdf,
                               const std::string& meta_name) {
    std::string out_path = ensure_cyphkey_ext(out_name_or_path);

    fs::path outp(out_path);
    if (!outp.parent_path().empty()) ensure_dir_exists(outp.parent_path());

    std::ofstream out(out_path, std::ios::binary | std::ios::trunc);
    if (!out) throw std::runtime_error("Cannot open output: " + out_path);

    ContainerHeader h{};
    h.algo_ver = ALGO_VER;
    h.flags = 0;
    h.opslimit = kdf.opslimit;
    h.memlimit_u64 = static_cast<unsigned long long>(kdf.memlimit);
    randombytes_buf(h.salt, sizeof h.salt);

    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    derive_key(key, h.salt, password_key_material, kdf);

    crypto_secretstream_xchacha20poly1305_state st;
    if (crypto_secretstream_xchacha20poly1305_init_push(&st, h.ss_header, key) != 0) {
        sodium_memzero(key, sizeof key);
        throw std::runtime_error("secretstream init_push failed");
    }

    write_container_header(out, h);

    std::vector<unsigned char> meta(meta_name.begin(), meta_name.end());
    std::vector<unsigned char> meta_ct(meta.size() + crypto_secretstream_xchacha20poly1305_ABYTES);
    unsigned long long meta_ct_len = 0;

    if (crypto_secretstream_xchacha20poly1305_push(
            &st, meta_ct.data(), &meta_ct_len,
            meta.data(), meta.size(),
            nullptr, 0,
            crypto_secretstream_xchacha20poly1305_TAG_MESSAGE) != 0) {
        sodium_memzero(key, sizeof key);
        throw std::runtime_error("secretstream push(meta) failed");
    }

    meta_ct.resize(static_cast<std::size_t>(meta_ct_len));
    std::uint32_t L = static_cast<std::uint32_t>(meta_ct.size());
    out.write(reinterpret_cast<const char*>(&L), sizeof(L));
    out.write(reinterpret_cast<const char*>(meta_ct.data()),
              static_cast<std::streamsize>(meta_ct.size()));
    if (!out) {
        sodium_memzero(key, sizeof key);
        throw std::runtime_error("Failed to write meta frame: " + out_path);
    }

    std::vector<unsigned char> ct(CHUNK + crypto_secretstream_xchacha20poly1305_ABYTES);
    std::size_t off = 0;

    while (off < plain.size()) {
        std::size_t take = std::min<std::size_t>(CHUNK, plain.size() - off);
        unsigned char tag = ((off + take) == plain.size())
                                ? crypto_secretstream_xchacha20poly1305_TAG_FINAL
                                : crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;

        unsigned long long ct_len = 0;
        if (crypto_secretstream_xchacha20poly1305_push(
                &st, ct.data(), &ct_len,
                plain.data() + off, take,
                nullptr, 0,
                tag) != 0) {
            sodium_memzero(key, sizeof key);
            throw std::runtime_error("secretstream push(data) failed");
        }

        std::uint32_t len32 = static_cast<std::uint32_t>(ct_len);
        out.write(reinterpret_cast<const char*>(&len32), sizeof(len32));
        out.write(reinterpret_cast<const char*>(ct.data()), static_cast<std::streamsize>(ct_len));
        if (!out) {
            sodium_memzero(key, sizeof key);
            throw std::runtime_error("Failed to write ciphertext frame");
        }

        off += take;
    }

    if (plain.empty()) {
        unsigned long long ct_len = 0;
        if (crypto_secretstream_xchacha20poly1305_push(
                &st, ct.data(), &ct_len,
                nullptr, 0,
                nullptr, 0,
                crypto_secretstream_xchacha20poly1305_TAG_FINAL) != 0) {
            sodium_memzero(key, sizeof key);
            throw std::runtime_error("secretstream push(final-empty) failed");
        }
        std::uint32_t len32 = static_cast<std::uint32_t>(ct_len);
        out.write(reinterpret_cast<const char*>(&len32), sizeof(len32));
        out.write(reinterpret_cast<const char*>(ct.data()), static_cast<std::streamsize>(ct_len));
        if (!out) {
            sodium_memzero(key, sizeof key);
            throw std::runtime_error("Failed to write ciphertext frame");
        }
    }

    sodium_memzero(key, sizeof key);
}

static const char* FP_WORDS[500] = {
"apple","river","stone","light","forest","silver","garden","cloud","ocean","sunset","field","mountain","flower","meadow","shadow","wind","rain","thunder","spark","ember","leaf","branch","valley","island","harbor",
"planet","star","comet","galaxy","orbit","grove","lake","bridge","castle","tower","village","desert","canyon","prairie","glacier","tundra","reef","lagoon","harvest","orchard","cottage","path","trail","stream","water",
"earth","metal","crystal","pebble","granite","marble","sand","cliff","ridge","shore","coast","bay","fjord","delta","plain","hill","wood","breeze","storm","frost","flame","smoke","cloudy","sunrise","twilight",
"morning","evening","midnight","noon","spring","summer","autumn","winter","north","south","east","west","circle","square","triangle","spiral","arrow","spear","shield","sword","anchor","compass","signal","beacon","lantern",
"feather","cotton","linen","silk","canvas","thread","needle","button","pocket","collar","sleeve","ribbon","fabric","gold","copper","iron","nickel","bronze","steel","ruby","pearl","amber","jade","topaz","opal",
"coffee","tea","cocoa","bread","butter","honey","sugar","salt","pepper","spice","olive","berry","cherry","melon","lemon","lime","peach","plum","grape","mango","papaya","guava","fig","date","apricot",
"eagle","falcon","sparrow","robin","raven","otter","beaver","badger","fox","wolf","tiger","lion","panda","koala","lemur","zebra","horse","camel","yak","whale","dolphin","seal","coral","shark","trout",
"alpha","bravo","charlie","delta","echo","foxtrot","golf","hotel","india","juliet","kilo","lima","oscar","nectar","romeo","piper","quartz","radar","sierra","tango","uniform","vector","whiskey","xray","yodel",
"zinc","argon","neon","radon","helium","carbon","oxygen","nitrogen","sulfur","chlorine","barium","calcium","sodium","potassium","magnesium","silicon","photon","electron","proton","atom","molecule","quantum","circuit","cipher","matrix",
"platinum","golden","crimson","scarlet","violet","indigo","azure","cyan","maroon","khaki","navy","lilac","cream","charcoal","rust","cobalt","turquoise","burgundy","salmon","magenta","beige","chartreuse","cerulean","lavender","tan",
"window","door","roof","floor","ceiling","wall","brick","stonework","tile","beam","pillar","arch","gate","lock","key","clock","mirror","frame","table","chair","desk","shelf","drawer","carpet","curtain",
"engine","motor","gear","wheel","axle","spring","lever","piston","valve","cable","copperwire","battery","socket","switch","button","screen","sensor","server","router","packet","code","script","kernel","logic","binary",
"paper","pencil","brush","canvasboard","palette","ink","chalk","marker","notebook","journal","letter","envelope","stamp","book","novel","poem","story","chapter","index","page","margin","cover","spine","binder","folder",
"smile","laugh","whisper","shout","dream","hope","trust","honor","brave","calm","clear","swift","quiet","bright","sharp","bold","rapid","gentle","steady","simple","solid","proud","loyal","kind","happy",
"gardenia","tulip","rose","daisy","iris","lily","poppy","violetflower","orchid","sunflower","marigold","thyme","basil","mintleaf","sage","rosemary","lavenderherb","oak","maple","birch","cedar","pine","willow","elm","ivy",
"travel","journey","voyage","flight","sail","drive","ride","walk","climb","dive","swim","run","dash","glide","drift","float","wander","explore","search","find","discover","build","craft","create","forge",
"music","melody","rhythm","harmony","tempo","lyric","tune","chord","note","sound","echoing","voice","chorus","opera","jazz","blues","folk","rock","dance","drum","flute","violin","guitar","piano","harp",
"market","trade","value","profit","supply","demand","credit","debit","ledger","coin","token","ticket","price","cost","budget","tax","grant","loan","cash","fund","share","bond","trustee","estate","asset",
"rapidly","slowly","truly","clearly","warmly","coolly","kindly","boldly","brightly","gently","firmly","softly","quietly","surely","simply","calmly","easily","lightly","widely","deeply","strongly","openly","closely","plainly","fully",
"alphaone","bravetwo","thirdwave","fourwind","fivespot","sixpath","sevenhill","eightpeak","nineroad","tentrail","elevenoak","twelvestar","thirteenbay","fourteenlake","fifteenfield","sixteenrock","seventeensky","eighteencave","nineteenwood","twentysand","thirtybird","fortycloud","fiftystone","sixtyriver","seventyshore"
};

std::string fingerprint6_from_pubkey_bytes(const unsigned char* pk, std::size_t pk_len) {
    unsigned char h[32];
    crypto_generichash_state st;
    crypto_generichash_init(&st, nullptr, 0, sizeof(h));
    const char* ctx = "cyph-fp-v1";
    crypto_generichash_update(&st, reinterpret_cast<const unsigned char*>(ctx), std::strlen(ctx));
    crypto_generichash_update(&st, pk, pk_len);
    crypto_generichash_final(&st, h, sizeof(h));

    std::string out;
    out.reserve(64);
    for (int i = 0; i < 6; i++) {
        std::uint16_t x = (static_cast<std::uint16_t>(h[i * 2]) << 8) | static_cast<std::uint16_t>(h[i * 2 + 1]);
        std::size_t idx = static_cast<std::size_t>(x % 500u);
        if (i) out.push_back('-');
        out += FP_WORDS[idx];
    }
    sodium_memzero(h, sizeof(h));
    return out;
}

std::string pubkey_to_text_cyphx1(const unsigned char pk[32]) {
    const std::size_t b64_len = sodium_base64_ENCODED_LEN(32, sodium_base64_VARIANT_ORIGINAL);
    std::string b64;
    b64.resize(b64_len);
    sodium_bin2base64(b64.data(), b64.size(), pk, 32, sodium_base64_VARIANT_ORIGINAL);
    if (!b64.empty() && b64.back() == '\0') b64.pop_back();
    return std::string("cyphx1:") + b64;
}

std::vector<unsigned char> pubkey_from_text_cyphx1(const std::string& s) {
    const std::string prefix = "cyphx1:";
    if (s.rfind(prefix, 0) != 0) throw std::runtime_error("Bad public key format (expected cyphx1:...)");
    std::string b64 = s.substr(prefix.size());

    std::vector<unsigned char> pk(32);
    std::size_t bin_len = 0;
    if (sodium_base642bin(pk.data(), pk.size(),
                          b64.c_str(), b64.size(),
                          nullptr, &bin_len, nullptr,
                          sodium_base64_VARIANT_ORIGINAL) != 0 || bin_len != 32) {
        throw std::runtime_error("Bad public key base64 (decode failed)");
    }
    return pk;
}



std::vector<unsigned char> derive_shared_key_v1(const unsigned char my_pk[32],
                                                const unsigned char peer_pk[32],
                                                const unsigned char raw_shared[32]) {
    const unsigned char* a_pk = my_pk;
    const unsigned char* b_pk = peer_pk;

    // ВАЖНО: sodium_memcmp НЕ подходит для упорядочивания!
    if (std::memcmp(a_pk, b_pk, 32) > 0) {
        a_pk = peer_pk;
        b_pk = my_pk;
    }

    unsigned char out[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    crypto_generichash_state st;
    crypto_generichash_init(&st, nullptr, 0, sizeof(out));
    const char* ctx = "cyph-shared-key-v1";
    crypto_generichash_update(&st, reinterpret_cast<const unsigned char*>(ctx), std::strlen(ctx));
    crypto_generichash_update(&st, a_pk, 32);
    crypto_generichash_update(&st, b_pk, 32);
    crypto_generichash_update(&st, raw_shared, 32);
    crypto_generichash_final(&st, out, sizeof(out));

    std::vector<unsigned char> v(out, out + sizeof(out));
    sodium_memzero(out, sizeof(out));
    return v;
}


}
