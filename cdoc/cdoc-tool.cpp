/*
 * libcdoc
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <iostream>
// No platform-specific terminal includes needed for encrypt-only tool

#include "CDocCipher.h"
#include "ConsoleLogger.h"
#include "ILogger.h"
#include "Utils.h"

#include "json/jwt.h"

using namespace std;
using namespace libcdoc;

enum {
    RESULT_OK = 0,
    RESULT_ERROR,
    RESULT_USAGE
};

static void print_usage(ostream& ofs)
{
    ofs << "cdoc-tool version: " << VERSION_STR << endl;
    ofs << "cdoc-tool encrypt --rcpt RECIPIENT.cer [--rcpt...]  --out OUTPUTFILE --IN FILE" << endl;
    ofs << "  Encrypt files for one or more recipients" << endl;
}

static std::vector<uint8_t>
fromB64(const std::string& data)
{
    std::string str = jwt::base::details::decode(data, jwt::alphabet::base64::rdata(), "=");
    return std::vector<uint8_t>(str.cbegin(), str.cend());
}

static void
load_certs(ToolConf& conf, const std::string& filename)
{
    std::vector<uint8_t> content = readAllBytes(filename);
    if ((content.size() > 3) && (content[0] == 'M') && (content[1] == 'I') && (content[2] == 'I')) {
        std::string cstr(content.cbegin(), content.cend());
        std::vector<std::string> parts = split(cstr, '\n');
        for (auto part : parts) {
            if (part.size() > 3) {
                std::vector<uint8_t> v = fromB64(part);
                conf.accept_certs.push_back(v);
            }
        }
    } else {
        conf.accept_certs.push_back(content);
    }
}

// Return the number of arguments consumed or error code

static int
parse_common(ToolConf& conf, int arg_idx, int argc, char *argv[])
{
    string_view arg(argv[arg_idx]);
    if ((arg == "--library") && ((arg_idx + 1) < argc)) {
        conf.library = argv[arg_idx + 1];
        return 2;
    } else if ((arg == "--server") && ((arg_idx + 2) < argc)) {
        ToolConf::ServerData sdata;
        sdata.ID = argv[arg_idx + 1];
        sdata.url = argv[arg_idx + 2];
        conf.servers.push_back(sdata);
        return 3;
    } else if ((arg == "--accept") && ((arg_idx + 1) < argc)) {
        load_certs(conf, argv[arg_idx + 1]);
        return 2;
    } else if ((arg == "--conf") && ((arg_idx + 1) < argc)) {
        conf.parse(argv[arg_idx + 1]);
        return 2;
    }
    return 0;
}

static int
parse_rcpt(ToolConf& conf, RecipientInfoVector& rcpts, int& arg_idx, int argc, char *argv[])
{
    string_view arg(argv[arg_idx]);
    if ((arg != "--rcpt") || ((arg_idx + 1) >= argc)) return 0;

    std::string argval(argv[arg_idx + 1]);
    // Accept either:
    //  - full certificate path: "C:\...\recipient.cer" or "/path/recipient.cer"
    //  - or the older form: "label:cert:PATH"
    // If the optional ":cert:" marker is present we extract the label before it,
    // otherwise the whole value is treated as the certificate path.
    std::string label;
    std::string path;
    const std::string cert_marker = ":cert:";
    size_t pos = argval.find(cert_marker);
    if (pos != std::string::npos) {
        label = argval.substr(0, pos);
        path = argval.substr(pos + cert_marker.size());
    } else {
        // Treat entire argument as certificate file path; label will be empty.
        path = argval;
    }

    if (path.empty()) return RESULT_USAGE;

    RcptInfo rcpt;
    rcpt.label = label;
    rcpt.type = RcptInfo::CERT;
    rcpt.cert = readAllBytes(path);
    rcpt.key_file_name = filesystem::path(path).filename().string();
    if (rcpt.cert.empty()) return 1; // readAllBytes already reported error

    rcpts.push_back(std::move(rcpt));
    return 2;
}

//
// cdoc-tool encrypt --rcpt RECIPIENT [--rcpt...] --out OUTPUTFILE FILE [FILE...]
// Where RECIPIENT has a format:
//   label:cert:CERTIFICATE_HEX
//	 label:key:SECRET_KEY_HEX
//   label:pw:PASSWORD
//	 label:p11sk:SLOT:[PIN]:[ID]:[LABEL]
//	 label:p11pk:SLOT:[PIN]:[ID]:[LABEL]
//

static int ParseAndEncrypt(int argc, char *argv[])
{
    LOG_INFO("Encrypting");

    ToolConf conf;
    // Accept -v1 and --genlabel by default so the user does not have to type them
    conf.cdocVersion = 1;
    conf.gen_label = true;
    RecipientInfoVector rcpts;

    //
    // Parse all arguments into ToolConf structure
    //
    int arg_idx = 0;
    while (arg_idx < argc) {
        int result = parse_common(conf, arg_idx, argc, argv);
        if (result < 0) return result;
        arg_idx += result;
        if (result > 0) continue;
        result = parse_rcpt(conf, rcpts, arg_idx, argc, argv);
        if (result < 0) return result;
        arg_idx += result;
        if (result > 0) continue;

        string_view arg(argv[arg_idx]);
        if (arg == "--out" && ((arg_idx + 1) < argc)) {
            conf.out = argv[arg_idx + 1];
            arg_idx += 1;
        } else if ((arg == "--in") && ((arg_idx + 1) < argc)) {
            conf.input_files.push_back(argv[arg_idx + 1]);
            arg_idx += 1;
        } else if (arg == "-v1") {
            conf.cdocVersion = 1;
        } else if (arg == "--genlabel") {
            conf.gen_label = true;
        } else if (arg[0] == '-') {
            LOG_ERROR("Unknown argument: {}", arg);
            return 2;
        } else {
            conf.input_files.push_back(argv[arg_idx]);
        }
        arg_idx += 1;
    }

    // Validate input parameters
    if (rcpts.empty()) {
        LOG_ERROR("No recipients");
        return RESULT_USAGE;
    }
    if (!conf.gen_label) {
        // If labels must not be generated then is there any Recipient without provided label?
        auto rcpt_wo_label{ find_if(rcpts.cbegin(), rcpts.cend(), [](RecipientInfoVector::const_reference rcpt) -> bool {return rcpt.label.empty();}) };
        if (rcpt_wo_label != rcpts.cend()) {
            if (rcpts.size() > 1) {
                LOG_ERROR("Not all Recipients have label");
            } else {
                LOG_ERROR("Label not provided");
            }
            return 2;
        }
    }

    if (conf.input_files.empty()) {
        LOG_ERROR("No files specified");
        return 2;
    }
    if (conf.out.empty()) {
        LOG_ERROR("No output specified");
        return 2;
    }

    if (conf.libraryRequired && conf.library.empty()) {
        LOG_ERROR("Cryptographic library is required");
        return 2;
    }

    // CDOC1 is supported only for encryption with certificate.
    if (conf.cdocVersion == 1) {
        auto rcpt_type_non_cert{ find_if(rcpts.cbegin(), rcpts.cend(), [](RecipientInfoVector::const_reference rcpt) -> bool {return rcpt.type != RcptInfo::CERT;}) };
        if (rcpt_type_non_cert != rcpts.cend()) {
            LOG_ERROR("CDOC version 1 container can be used for encryption with certificate only.");
            return 1;
        }
    }

    CDocCipher cipher;
    return cipher.Encrypt(conf, rcpts);
}

struct LockData {
    string lock_label;
    int lock_idx = -1;
    long slot = -1;
    vector<uint8_t> key_id;
    string key_label;
    vector<uint8_t> secret;

    int validate(ToolConf& conf) {
        if (lock_label.empty() && (lock_idx == -1) && (slot < 0)) {
            LOG_ERROR("No label nor index was provided");
            return RESULT_USAGE;
        }
        if ((slot >= 0) && conf.library.empty()) {
            LOG_ERROR("Cryptographic library is required");
            return RESULT_USAGE;
        }
        return RESULT_OK;
    }
};

// Decrypt-related interactive helpers removed for encrypt-only tool

//
// cdoc-tool decrypt ARGUMENTS FILE [OUTPU_DIR]
//   --label LABEL   CDoc container lock label
//   --slot SLOT     PKCS11 slot number
//   --secret|password|pin SECRET    Secret phrase (either lock password or PKCS11 pin)
//   --key-id        PKCS11 key id
//   --key-label     PKCS11 key label
//   --library       full path to cryptographic library to be used (needed for decryption with PKCS11)

// Decrypt/re-encrypt/locks functions removed for encrypt-only tool

int main(int argc, char *argv[])
{
    if (argc < 2) {
        print_usage(cerr);
        return 1;
    }

    // Check whether `--verbose` was provided; if not, silence stdout/stderr
    bool verbose = false;
    for (int i = 1; i < argc; ++i) {
        if (std::string_view(argv[i]) == "--verbose") { verbose = true; break; }
    }

    struct NullBuf : public std::streambuf { int overflow(int c) override { return c; } };
    static NullBuf nullbuf;
    static std::streambuf* orig_cout = nullptr;
    static std::streambuf* orig_cerr = nullptr;
    if (!verbose) {
        orig_cout = std::cout.rdbuf(&nullbuf);
        orig_cerr = std::cerr.rdbuf(&nullbuf);
    }

    // Add console logger (its output will be silenced unless --verbose)
    ConsoleLogger console_logger;
    console_logger.SetMinLogLevel(ILogger::LEVEL_TRACE);
    int cookie = ILogger::addLogger(&console_logger);

    // Build a filtered argv array without any --verbose entries for parsing
    std::vector<char*> argv2;
    argv2.reserve(argc);
    argv2.push_back(argv[0]);
    for (int i = 1; i < argc; ++i) {
        if (std::string_view(argv[i]) == "--verbose") continue;
        argv2.push_back(argv[i]);
    }
    int argc2 = (int)argv2.size();
    char** argv_f = argv2.data();

    // If first argument is not a known command, treat the invocation as 'encrypt' by default
    string_view first = (argc2 > 1) ? string_view(argv_f[1]) : string_view("");
    string_view command;
    char **cmd_argv = nullptr;
    int cmd_argc = 0;
    if (first == "encrypt") {
        command = first;
        cmd_argv = argv_f + 2;
        cmd_argc = argc2 - 2;
    } else {
        // No other subcommands supported; treat as encrypt invocation
        command = "encrypt";
        cmd_argv = argv_f + 1;
        cmd_argc = argc2 - 1;
    }

    LOG_INFO("Command: {}", command);

    CDocCipher cipher;
    int retVal = 2;     // Output the help by default.
    if (command == "encrypt") {
        retVal = ParseAndEncrypt(cmd_argc, cmd_argv);
    } else {
        cerr << "Invalid command: " << command << endl;
    }

    if (retVal == 2) {
        // We print usage information only in case the parse-function returned 2. Value 1 indicates other error.
        print_usage(cout);
    }

    ILogger::removeLogger(cookie);
    return retVal;
}
