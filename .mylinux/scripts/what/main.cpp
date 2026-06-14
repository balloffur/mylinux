#include "core.h"
#include <sodium.h>
#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <unistd.h>
#include <termios.h>
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <regex>

namespace fs = std::filesystem;

void secure_wipe(std::vector<unsigned char>& v) {
    if (!v.empty()) sodium_memzero(v.data(), v.size());
    v.clear();
    v.shrink_to_fit();
}

std::string get_password_prompt(const std::string& prompt_msg) {
    std::string password;
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    std::cout << prompt_msg;
    std::getline(std::cin, password);
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    std::cout << "\n";
    return password;
}

fs::path get_config_path() {
    const char* home = std::getenv("HOME");
    if (!home) return "";
    return fs::path(home) / ".config" / "what" / "config";
}

std::string get_active_vault() {
    fs::path cfg = get_config_path();
    if (fs::exists(cfg)) {
        std::ifstream in(cfg);
        std::string line;
        if (std::getline(in, line) && !line.empty()) {
            return line;
        }
    }
    return "main";
}

void set_active_vault(const std::string& name) {
    fs::path cfg = get_config_path();
    if (!cfg.empty()) {
        fs::create_directories(cfg.parent_path());
        std::ofstream out(cfg);
        out << name << "\n";
    }
}

fs::path get_keyfile_path(const std::string& vault_name) {
    const char* home = std::getenv("HOME");
    if (!home) return "";
    return fs::path(home) / ".config" / "what" / (vault_name + ".key");
}

fs::path get_vault_path(const std::string& vault_name) {
    const char* home = std::getenv("HOME");
    if (!home) return vault_name + ".cyph";
    return fs::path(home) / ".local" / "share" / "what" / (vault_name + ".cyph");
}

std::vector<unsigned char> get_master_key(const std::string& vault_name) {
    if (const char* env_key = std::getenv("WHAT_KEY")) {
        std::string key_str(env_key);
        return {key_str.begin(), key_str.end()};
    }

    fs::path keyfile = get_keyfile_path(vault_name);
    if (!keyfile.empty() && fs::exists(keyfile)) {
        std::ifstream f(keyfile, std::ios::binary);
        return std::vector<unsigned char>((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    }

    fs::path vault_path = get_vault_path(vault_name);
    bool is_new = !fs::exists(vault_path);
    std::string pass;

    if (is_new) {
        std::cout << "Creating new vault: " << vault_name << "\n";
        pass = get_password_prompt("New Vault Password: ");
        std::string pass_confirm = get_password_prompt("Confirm Password: ");
        if (pass != pass_confirm) {
            std::cerr << "Passwords do not match. Aborting.\n";
            exit(1);
        }
    } else {
        std::cout << "Unlocking vault: " << vault_name << "\n";
        pass = get_password_prompt("Vault Password: ");
    }

    std::vector<unsigned char> pass_vec(pass.begin(), pass.end());

    if (!keyfile.empty()) {
        fs::create_directories(keyfile.parent_path());
        std::ofstream out(keyfile, std::ios::binary);
        out.write(pass.data(), pass.size());
        out.close();
        fs::permissions(keyfile, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace);
    }
    
    return pass_vec;
}

std::string read_vault(const fs::path& vault_path, const std::vector<unsigned char>& key) {
    if (!fs::exists(vault_path)) return "---\n";
    std::vector<unsigned char> dec = cyph::decrypt_payload_to_bytes(vault_path.string(), key);
    std::string content(dec.begin(), dec.end());
    secure_wipe(dec);
    return content;
}

void write_vault(const fs::path& vault_path, const std::string& content, const std::vector<unsigned char>& key) {
    fs::create_directories(vault_path.parent_path());
    std::string tmp_enc = vault_path.string() + ".tmp";
    std::ofstream out(tmp_enc, std::ios::binary);
    out.write(content.data(), content.size());
    out.close();

    cyph::KdfParams kdf = cyph::kdf_params_for_level(0);
    cyph::encrypt_file_stream(tmp_enc, vault_path.string(), key, kdf, 0, "what_vault");
    std::remove(tmp_enc.c_str());
}

std::string wildcard_to_regex(const std::string& query) {
    std::string res;
    for (char c : query) {
        if (c == '*') res += ".*";
        else if (c == '?') res += ".";
        else if (std::string(".+()[]{}^$\\|").find(c) != std::string::npos) {
            res += '\\';
            res += c;
        } else {
            res += c;
        }
    }
    return res;
}

void extract_note_parts(const std::string& block, std::string& tags, std::string& text) {
    tags = "";
    text = "";
    
    size_t tags_pos = block.find("TAGS:");
    size_t text_pos = block.find("TEXT:");
    
    if (text_pos == std::string::npos) {
        text = block;
        return;
    }
    
    if (tags_pos != std::string::npos && tags_pos < text_pos) {
        tags = block.substr(tags_pos + 5, text_pos - (tags_pos + 5));
    }
    
    text = block.substr(text_pos + 5);
    
    auto trim = [](std::string& s) {
        if (s.empty()) return;
        s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) { return !std::isspace(ch); }));
        s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) { return !std::isspace(ch); }).base(), s.end());
    };
    
    trim(tags);
    trim(text);
}

void search_vault(const std::string& query, const std::string& db_content, bool full_text) {
    std::regex re(wildcard_to_regex(query), std::regex_constants::icase);
    std::string delim = "---";
    size_t start = 0;

    while ((start = db_content.find(delim, start)) != std::string::npos) {
        start += delim.length();
        if (start < db_content.size() && db_content[start] == '\n') start++;

        size_t end = db_content.find("\n" + delim, start);
        if (end == std::string::npos) end = db_content.size();

        std::string block = db_content.substr(start, end - start);

        if (!block.empty()) {
            std::string tags, text;
            extract_note_parts(block, tags, text);
            
            bool match = false;
            if (std::regex_search(tags, re)) match = true;
            else if (full_text && std::regex_search(text, re)) match = true;

            if (match) {
                std::cout << text << "\n---\n";
            }
        }
        start = end;
    }
}

void edit_database(const fs::path& vault_path, std::string& db_content, const std::vector<unsigned char>& key) {
    std::string tmp_path = "/dev/shm/what_vault_" + std::to_string(getpid());
    std::ofstream out(tmp_path, std::ios::binary);
    out.write(db_content.data(), db_content.size());
    out.close();

    const char* env_editor = std::getenv("EDITOR");
    std::string editor = env_editor ? env_editor : "nano";
    std::string cmd = editor + " " + tmp_path;
    
    if (std::system(cmd.c_str()) != 0) {
        std::cerr << "Editor closed with an error.\n";
    }

    std::ifstream in(tmp_path, std::ios::binary);
    db_content.assign((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();
    std::remove(tmp_path.c_str());

    write_vault(vault_path, db_content, key);
}

void delete_note(const fs::path& vault_path, std::string& db_content, const std::string& target, const std::vector<unsigned char>& key) {
    std::regex re(wildcard_to_regex(target), std::regex_constants::icase);
    std::string new_content = "---\n";
    std::string delim = "---";
    size_t start = 0;
    bool deleted = false;

    while ((start = db_content.find(delim, start)) != std::string::npos) {
        start += delim.length();
        if (start < db_content.size() && db_content[start] == '\n') start++;

        size_t end = db_content.find("\n" + delim, start);
        if (end == std::string::npos) end = db_content.size();

        std::string block = db_content.substr(start, end - start);

        if (!block.empty()) {
            std::string tags, text;
            extract_note_parts(block, tags, text);
            
            bool match = false;
            if (std::regex_search(tags, re)) match = true;
            else if (std::regex_search(text, re)) match = true;

            if (!deleted && match) {
                std::cout << "Found matching note:\n---\n" << text << "\n---\n";
                std::cout << "Delete this note? [y/N]: ";
                std::string confirm;
                std::getline(std::cin, confirm);
                if (confirm == "y" || confirm == "Y") {
                    deleted = true;
                    std::cout << "Note deleted.\n";
                } else {
                    new_content += block + "\n---\n";
                    std::cout << "Deletion cancelled.\n";
                }
            } else {
                new_content += block + "\n---\n";
            }
        }
        start = end;
    }
    
    if (deleted) {
        write_vault(vault_path, new_content, key);
    } else {
        std::cout << "No changes made to vault.\n";
    }
}

void add_note(const fs::path& vault_path, std::string& db_content, const std::vector<unsigned char>& key) {
    std::cout << "Enter Tags (optional, comma separated): ";
    std::string tags;
    std::getline(std::cin, tags);
    
    std::cout << "Enter Text (type EOF on a new line to finish):\n";
    std::string content;
    std::string line;
    while (std::getline(std::cin, line) && line != "EOF") {
        content += line + "\n";
    }
    
    db_content += "TAGS: " + tags + "\nTEXT:\n" + content + "---\n";
    write_vault(vault_path, db_content, key);
    std::cout << "Note added to vault.\n";
}

void show_extended_help(const std::string& active_vault) {
    std::cout << "what - Secure CLI Note-Taking & Fact Retrieval\n"
              << "Active Vault: " << active_vault << "\n\n"
              << "SEARCHING:\n"
              << "  what <query>       Search tags in the active vault using wildcards (*, ?)\n"
              << "  what <query> -f    Full-text search (scans both tags and main text)\n"
              << "  what <query> -i    Search the vault, then open DuckDuckGo in your browser\n\n"
              << "NOTE MANAGEMENT:\n"
              << "  what -a            Add a new note interactively (prompts for Tags and Text)\n"
              << "  what -d <query>    Find and delete a note matching the query (prompts to confirm)\n"
              << "  what -e            Edit the entire decrypted vault in your $EDITOR\n"
              << "  what -ALL          Print the entire raw contents of the active vault\n\n"
              << "VAULT MANAGEMENT:\n"
              << "  what -choose       Show a list of all existing vaults and let you pick one interactively\n"
              << "  what -v <name>     Switch active vault to <name>\n"
              << "  what -n <name>     Create a new vault named <name> and set it as active\n"
              << "  what -clone        Copy the active vault's .cyph file to your current working directory\n"
              << "  what -import <f>   Import a .cyph file from path <f> into your vaults and set as active\n"
              << "  what -WIPE         Completely destroy the active vault and its saved local key\n\n"
              << "WILDCARDS:\n"
              << "  * matches any number of characters (e.g., 'serv*' matches 'server', 'service')\n"
              << "  ? matches exactly one character (e.g., '192.168.1.?' matches '192.168.1.5')\n";
}

int main(int argc, char** argv) {
    if (sodium_init() < 0) {
        std::cerr << "Failed to initialize libsodium\n";
        return 1;
    }

    std::string active_vault = get_active_vault();

    if (argc == 1) {
        show_extended_help(active_vault);
        return 0;
    }

    std::string query;
    std::string delete_target;
    std::string import_path;
    bool use_internet = false;
    bool add_mode = false;
    bool edit_mode = false;
    bool full_search = false;
    bool all_mode = false;
    bool wipe_mode = false;
    bool clone_mode = false;
    bool choose_mode = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "-help") {
            show_extended_help(active_vault);
            return 0;
        } else if (arg == "-i") {
            use_internet = true;
        } else if (arg == "-a") {
            add_mode = true;
        } else if (arg == "-e") {
            edit_mode = true;
        } else if (arg == "-f") {
            full_search = true;
        } else if (arg == "-ALL") {
            all_mode = true;
        } else if (arg == "-WIPE") {
            wipe_mode = true;
        } else if (arg == "-clone") {
            clone_mode = true;
        } else if (arg == "-choose") {
            choose_mode = true;
        } else if (arg == "-import") {
            if (i + 1 < argc) {
                import_path = argv[++i];
            } else {
                std::cerr << "Error: -import requires a file path.\n";
                return 1;
            }
        } else if (arg == "-v" || arg == "-n") {
            if (i + 1 < argc) {
                active_vault = argv[++i];
                set_active_vault(active_vault);
                std::cout << "Switched active vault to: " << active_vault << "\n";
                if (i + 1 == argc && arg == "-v") return 0;
            } else {
                std::cerr << "Error: " << arg << " requires a vault name.\n";
                return 1;
            }
        } else if (arg == "-d") {
            if (i + 1 < argc) {
                delete_target = argv[++i];
            } else {
                std::cerr << "Error: -d requires a target to delete.\n";
                return 1;
            }
        } else {
            if (query.empty()) query = arg;
            else query += " " + arg;
        }
    }

    if (choose_mode) {
        fs::path share_dir = fs::path(std::getenv("HOME")) / ".local" / "share" / "what";
        std::vector<std::string> vaults;
        if (fs::exists(share_dir)) {
            for (const auto& entry : fs::directory_iterator(share_dir)) {
                if (entry.path().extension() == ".cyph") {
                    vaults.push_back(entry.path().stem().string());
                }
            }
        }
        if (vaults.empty()) {
            std::cout << "No vaults found in " << share_dir << "\n";
            return 0;
        }
        std::cout << "Available Vaults:\n";
        for (size_t i = 0; i < vaults.size(); ++i) {
            std::cout << "[" << i + 1 << "] " << vaults[i] << (vaults[i] == active_vault ? " (active)" : "") << "\n";
        }
        std::cout << "Select vault number: ";
        int choice;
        if (std::cin >> choice && choice > 0 && choice <= static_cast<int>(vaults.size())) {
            set_active_vault(vaults[choice - 1]);
            std::cout << "Switched to: " << vaults[choice - 1] << "\n";
        } else {
            std::cerr << "Invalid choice.\n";
            return 1;
        }
        return 0;
    }

    if (clone_mode) {
        fs::path src = get_vault_path(active_vault);
        fs::path dest = fs::current_path() / (active_vault + ".cyph");
        if (fs::exists(src)) {
            fs::copy_file(src, dest, fs::copy_options::overwrite_existing);
            std::cout << "Successfully cloned vault to " << dest << "\n";
        } else {
            std::cerr << "Active vault file does not exist.\n";
            return 1;
        }
        return 0;
    }

    if (!import_path.empty()) {
        fs::path src(import_path);
        if (fs::exists(src) && src.extension() == ".cyph") {
            std::string vname = src.stem().string();
            fs::path dest = get_vault_path(vname);
            fs::create_directories(dest.parent_path());
            fs::copy_file(src, dest, fs::copy_options::overwrite_existing);
            set_active_vault(vname);
            std::cout << "Imported " << vname << " and set as active vault. Run a command to unlock it.\n";
        } else {
            std::cerr << "Invalid or missing .cyph file at path: " << import_path << "\n";
            return 1;
        }
        return 0;
    }

    if (wipe_mode) {
        std::cout << "WARNING: You are about to permanently delete the vault '" << active_vault << "'.\n";
        std::cout << "Type 'delete' to confirm: ";
        std::string confirm;
        std::getline(std::cin, confirm);
        if (confirm == "delete") {
            fs::path vpath = get_vault_path(active_vault);
            fs::path kpath = get_keyfile_path(active_vault);
            if (fs::exists(vpath)) fs::remove(vpath);
            if (fs::exists(kpath)) fs::remove(kpath);
            std::cout << "Vault wiped. (If you exported WHAT_KEY, run 'unset WHAT_KEY' in your shell to clear memory)\n";
            set_active_vault("main");
        } else {
            std::cout << "Wipe cancelled.\n";
        }
        return 0;
    }

    if (query.empty() && delete_target.empty() && !add_mode && !edit_mode && !all_mode) {
        return 0;
    }

    fs::path vault_path = get_vault_path(active_vault);
    std::vector<unsigned char> key = get_master_key(active_vault);
    std::string db_content;

    try {
        db_content = read_vault(vault_path, key);
    } catch (const std::exception& e) {
        std::cerr << "Vault unlock failed: " << e.what() << "\n";
        secure_wipe(key);
        return 1;
    }

    if (all_mode) {
        std::cout << db_content;
        secure_wipe(key);
        return 0;
    }

    if (edit_mode) {
        edit_database(vault_path, db_content, key);
        secure_wipe(key);
        return 0;
    }

    if (!delete_target.empty()) {
        delete_note(vault_path, db_content, delete_target, key);
        secure_wipe(key);
        return 0;
    }

    if (add_mode) {
        add_note(vault_path, db_content, key);
        secure_wipe(key);
        return 0;
    }

    if (!query.empty()) {
        search_vault(query, db_content, full_search);
        if (use_internet) {
            std::string cmd = "xdg-open \"https://duckduckgo.com/?q=" + query + "\" 2>/dev/null";
            if (std::system(cmd.c_str()) != 0) {
                std::cerr << "Failed to open browser.\n";
            }
        }
    }

    std::fill(db_content.begin(), db_content.end(), 0);
    secure_wipe(key);
    return 0;
}
