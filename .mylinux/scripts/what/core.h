// core.h
#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace cyph {

inline constexpr const char* VERSION = "2.3.2";
inline constexpr const char* EXT_CYPH = ".cyph";
inline constexpr const char* EXT_CYPHKEY = ".cyphkey";

inline constexpr std::uint8_t FLAG_ANON_META = 1u << 0;

struct KdfParams {
    unsigned long long opslimit;
    std::size_t memlimit;
};

KdfParams kdf_params_for_level(int level);

std::string ensure_cyph_ext(std::string out);
std::string ensure_cyphkey_ext(std::string out);

void encrypt_file_stream(const std::string& in_path,
                         const std::string& out_path,
                         const std::vector<unsigned char>& key_material,
                         const KdfParams& kdf,
                         std::uint8_t flags,
                         const std::string& meta_name);

std::string read_restored_name_quick(const std::string& enc_in,
                                     const std::vector<unsigned char>& key_material);

void decrypt_file_stream(const std::string& enc_path,
                         const std::string& out_path_or_empty,
                         const std::vector<unsigned char>& key_material,
                         bool to_stdout,
                         bool write_file);

std::vector<unsigned char> decrypt_payload_to_bytes(const std::string& enc_path,
                                                    const std::vector<unsigned char>& key_material);

void create_cyphkey_file(const std::string& input_keyfile,
                         const std::string& out_name_or_path,
                         const std::vector<unsigned char>& master_key_material,
                         const KdfParams& kdf);

void create_cyphkey_from_bytes(const std::vector<unsigned char>& plain,
                               const std::string& out_name_or_path,
                               const std::vector<unsigned char>& password_key_material,
                               const KdfParams& kdf,
                               const std::string& meta_name);

std::string fingerprint6_from_pubkey_bytes(const unsigned char* pk, std::size_t pk_len);
std::string pubkey_to_text_cyphx1(const unsigned char pk[32]);
std::vector<unsigned char> pubkey_from_text_cyphx1(const std::string& s);
std::vector<unsigned char> derive_shared_key_v1(const unsigned char my_pk[32],
                                                const unsigned char peer_pk[32],
                                                const unsigned char raw_shared[32]);

}
