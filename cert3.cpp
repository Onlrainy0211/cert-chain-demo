

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <stdint.h>
#include <algorithm>
#include <cstdlib>
#include <fstream>

// ==================== SHA-256 实现 ====================
class SHA256 {
public:
    static std::string hash(const std::string& input) {
        uint32_t h[8] = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        };
        uint32_t k[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };

        std::vector<uint8_t> msg(input.begin(), input.end());
        uint64_t bitlen = msg.size() * 8;
        msg.push_back(0x80);
        while ((msg.size() % 64) != 56) {
            msg.push_back(0x00);
        }
        for (int i = 7; i >= 0; --i) {
            msg.push_back((bitlen >> (i * 8)) & 0xFF);
        }

        for (size_t i = 0; i < msg.size(); i += 64) {
            uint32_t w[64];
            for (int j = 0; j < 16; ++j) {
                w[j] = (msg[i + j*4] << 24) | (msg[i + j*4 + 1] << 16) |
                       (msg[i + j*4 + 2] << 8) | (msg[i + j*4 + 3]);
            }
            for (int j = 16; j < 64; ++j) {
                uint32_t s0 = (w[j-15] >> 7 | w[j-15] << 25) ^
                              (w[j-15] >> 18 | w[j-15] << 14) ^
                              (w[j-15] >> 3);
                uint32_t s1 = (w[j-2] >> 17 | w[j-2] << 15) ^
                              (w[j-2] >> 19 | w[j-2] << 13) ^
                              (w[j-2] >> 10);
                w[j] = w[j-16] + s0 + w[j-7] + s1;
            }

            uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
            uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];

            for (int j = 0; j < 64; ++j) {
                uint32_t S1 = (e >> 6 | e << 26) ^ (e >> 11 | e << 21) ^ (e >> 25 | e << 7);
                uint32_t ch = (e & f) ^ (~e & g);
                uint32_t temp1 = hh + S1 + ch + k[j] + w[j];
                uint32_t S0 = (a >> 2 | a << 30) ^ (a >> 13 | a << 19) ^ (a >> 22 | a << 10);
                uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
                uint32_t temp2 = S0 + maj;

                hh = g;
                g = f;
                f = e;
                e = d + temp1;
                d = c;
                c = b;
                b = a;
                a = temp1 + temp2;
            }

            h[0] += a; h[1] += b; h[2] += c; h[3] += d;
            h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
        }

        std::ostringstream oss;
        for (int i = 0; i < 8; ++i) {
            oss << std::hex << std::setw(8) << std::setfill('0') << h[i];
        }
        return oss.str();
    }
};

// ==================== 证书结构 ====================
struct Certificate {
    std::string cert_id;
    std::string student_name;
    std::string student_id;
    std::string cert_name;
    std::string issuer;
    std::string issue_date;
    std::string level;
};

std::string canonicalize(const Certificate& cert) {
    std::ostringstream oss;
    oss << "cert_id=" << cert.cert_id << "|"
        << "student_name=" << cert.student_name << "|"
        << "student_id=" << cert.student_id << "|"
        << "cert_name=" << cert.cert_name << "|"
        << "issuer=" << cert.issuer << "|"
        << "issue_date=" << cert.issue_date << "|"
        << "level=" << cert.level;
    return oss.str();
}

std::string certDigest(const Certificate& cert) {
    return SHA256::hash(canonicalize(cert));
}

// ==================== 区块与链 ====================
struct CertRecord {
    std::string cert_id;
    std::string digest;
    long long issued_at;
};

struct Block {
    int index;
    long long timestamp;
    std::vector<CertRecord> records;
    std::string prev_hash;
    int nonce;
    std::string hash;

    std::string computeHash() const {
        std::ostringstream oss;
        oss << index << "|" << timestamp << "|" << prev_hash << "|" << nonce;
        for (size_t i = 0; i < records.size(); ++i) {
            oss << "|" << records[i].cert_id << "|" << records[i].digest << "|" << records[i].issued_at;
        }
        return SHA256::hash(oss.str());
    }
};

class CertificateChain {
public:
    enum VerifyStatus { VALID, TAMPERED, NOT_FOUND };
    struct VerifyResult {
        VerifyStatus status;
        std::string cert_id;
        std::string digest;
        std::string on_chain_digest;
        int block_index;
        std::string message;
    };

private:
    int difficulty;
    std::vector<Block> chain;
    std::vector<CertRecord> pending;
    std::string filename;

    std::string mine(Block& block) {
        std::string target(difficulty, '0');
        block.nonce = 0;
        while (true) {
            std::string h = block.computeHash();
            if (h.substr(0, difficulty) == target) {
                block.hash = h;
                return h;
            }
            block.nonce++;
        }
    }

public:
    CertificateChain(int diff = 3, std::string fname = "chain_data.txt") : difficulty(diff), filename(fname) {
        loadFromFile();
        if (chain.empty()) {
            Block genesis;
            genesis.index = 0;
            genesis.timestamp = std::time(nullptr);
            genesis.prev_hash = std::string(64, '0');
            genesis.nonce = 0;
            genesis.hash = mine(genesis);
            chain.push_back(genesis);
            saveToFile();
        }
    }

    // 持久化：保存到文件
    void saveToFile() {
        std::ofstream out(filename.c_str());
        if (!out) return;
        out << difficulty << "\n";
        out << chain.size() << "\n";
        for (size_t i = 0; i < chain.size(); ++i) {
            const Block& blk = chain[i];
            out << blk.index << "|" << blk.timestamp << "|" << blk.prev_hash << "|" << blk.nonce << "|" << blk.hash << "|" << blk.records.size() << "\n";
            for (size_t j = 0; j < blk.records.size(); ++j) {
                out << blk.records[j].cert_id << "|" << blk.records[j].digest << "|" << blk.records[j].issued_at << "\n";
            }
        }
        out.close();
    }

    // 持久化：从文件加载
    void loadFromFile() {
        std::ifstream in(filename.c_str());
        if (!in) return;
        in >> difficulty;
        int chain_size;
        in >> chain_size;
        in.ignore();
        chain.clear();
        for (int i = 0; i < chain_size; ++i) {
            std::string line;
            std::getline(in, line);
            if (line.empty()) continue;
            std::stringstream ss(line);
            std::string token;
            Block blk;
            
            std::getline(ss, token, '|'); blk.index = atoi(token.c_str());
            std::getline(ss, token, '|'); blk.timestamp = atoll(token.c_str());
            std::getline(ss, blk.prev_hash, '|');
            std::getline(ss, token, '|'); blk.nonce = atoi(token.c_str());
            std::getline(ss, blk.hash, '|');
            std::getline(ss, token, '|'); int rec_count = atoi(token.c_str());

            for (int j = 0; j < rec_count; ++j) {
                std::getline(in, line);
                std::stringstream ss_rec(line);
                CertRecord rec;
                std::getline(ss_rec, rec.cert_id, '|');
                std::getline(ss_rec, rec.digest, '|');
                std::getline(ss_rec, token, '|'); rec.issued_at = atoll(token.c_str());
                blk.records.push_back(rec);
            }
            chain.push_back(blk);
        }
        in.close();
    }

    std::string issueCertificate(const Certificate& cert) {
        std::string digest = certDigest(cert);
        CertRecord rec;
        rec.cert_id = cert.cert_id;
        rec.digest = digest;
        rec.issued_at = std::time(nullptr);
        pending.push_back(rec);

        Block block;
        block.index = (int)chain.size();
        block.timestamp = std::time(nullptr);
        block.records = pending;
        block.prev_hash = chain.back().hash;
        block.nonce = 0;
        mine(block);
        chain.push_back(block);
        pending.clear();
        saveToFile(); // 上链后立即保存
        return digest;
    }

    VerifyResult verifyCertificate(const Certificate& cert) {
        std::string cert_id = cert.cert_id;
        std::string digest = certDigest(cert);
        for (size_t i = 0; i < chain.size(); ++i) {
            for (size_t j = 0; j < chain[i].records.size(); ++j) {
                const CertRecord& rec = chain[i].records[j];
                if (rec.cert_id == cert_id) {
                    VerifyResult res;
                    res.cert_id = cert_id;
                    res.digest = digest;
                    res.block_index = chain[i].index;
                    if (rec.digest == digest) {
                        res.status = VALID;
                        res.message = "核验通过：证书内容与链上摘要一致";
                    } else {
                        res.status = TAMPERED;
                        res.on_chain_digest = rec.digest;
                        res.message = "核验失败：证书内容已被修改，与链上存证不符";
                    }
                    return res;
                }
            }
        }
        VerifyResult res;
        res.status = NOT_FOUND;
        res.cert_id = cert_id;
        res.digest = digest;
        res.block_index = -1;
        res.message = "链上未找到该证书编号的存证记录";
        return res;
    }

    bool validateChain(std::vector<std::string>& problems) {
        for (size_t i = 0; i < chain.size(); ++i) {
            if (chain[i].hash != chain[i].computeHash()) {
                std::stringstream ss;
                ss << i;
                problems.push_back("区块 #" + ss.str() + " 内容被篡改（哈希不匹配）");
            }
            if (i > 0 && chain[i].prev_hash != chain[i-1].hash) {
                std::stringstream ss;
                ss << i;
                problems.push_back("区块 #" + ss.str() + " 与前一个区块断链（prev_hash 不匹配）");
            }
        }
        return problems.empty();
    }

    void printChain() const {
        for (size_t i = 0; i < chain.size(); ++i) {
            const Block& blk = chain[i];
            std::cout << "  区块 #" << blk.index << "\n";
            std::time_t t = blk.timestamp;
            char buf[64];
            std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::localtime(&t));
            std::cout << "    时间戳   : " << buf << "\n";
            std::cout << "    前块哈希 : " << blk.prev_hash.substr(0, 32) << "...\n";
            std::cout << "    本块哈希 : " << blk.hash << "\n";
            std::cout << "    Nonce    : " << blk.nonce << "\n";
            for (size_t j = 0; j < blk.records.size(); ++j) {
                const CertRecord& rec = blk.records[j];
                std::cout << "    └─ 存证证书 " << rec.cert_id << "\n";
                std::cout << "       摘要     : " << rec.digest << "\n";
            }
        }
    }

    Block& lastBlock() { return chain.back(); }
    size_t blockCount() const { return chain.size(); }
    size_t certCount() const {
        size_t cnt = 0;
        for (size_t i = 0; i < chain.size(); ++i)
            for (size_t j = 0; j < chain[i].records.size(); ++j)
                cnt++;
        return cnt;
    }
};

// ==================== 辅助函数 ====================
void hr(const std::string& title = "") {
    std::cout << "============================================================\n";
    if (!title.empty()) {
        std::cout << title << "\n";
        std::cout << "============================================================\n";
    }
}

Certificate inputCertificate() {
    Certificate cert;
    std::cout << "\n请依次输入证书信息（直接回车表示留空）：\n";
    std::cout << "  证书编号: "; std::getline(std::cin, cert.cert_id);
    std::cout << "  学生姓名: "; std::getline(std::cin, cert.student_name);
    std::cout << "  学号: "; std::getline(std::cin, cert.student_id);
    std::cout << "  证书名称: "; std::getline(std::cin, cert.cert_name);
    std::cout << "  颁发方: "; std::getline(std::cin, cert.issuer);
    std::cout << "  颁发日期(YYYY-MM-DD): "; std::getline(std::cin, cert.issue_date);
    std::cout << "  奖项/等级: "; std::getline(std::cin, cert.level);
    return cert;
}

void printCert(const Certificate& cert) {
    std::cout << "  证书编号: " << cert.cert_id << "\n";
    std::cout << "  学生姓名: " << cert.student_name << "\n";
    std::cout << "  学号: " << cert.student_id << "\n";
    std::cout << "  证书名称: " << cert.cert_name << "\n";
    std::cout << "  颁发方: " << cert.issuer << "\n";
    std::cout << "  颁发日期: " << cert.issue_date << "\n";
    std::cout << "  奖项/等级: " << cert.level << "\n";
}

// ==================== 交互模式 ====================
void interactive() {
    hr("校园证书存证系统 —— 交互模式");
    CertificateChain chain(3, "chain_data.txt");
    std::string choice;

    while (true) {
        std::cout << "\n---------------- 菜单 ----------------\n";
        std::cout << "  1. 颁发证书（真实录入，上链保存）\n";
        std::cout << "  2. 核验证书（比对链上摘要）\n";
        std::cout << "  3. 查看区块链（读取本地存证）\n";
        std::cout << "  4. 校验链完整性\n";
        std::cout << "  5. 篡改演示（模拟攻击）\n";
        std::cout << "  6. 一键载入PPT演示数据\n";
        std::cout << "  0. 退出\n";
        std::cout << "--------------------------------------\n";
        std::cout << "请选择操作：";
        std::getline(std::cin, choice);

        if (choice == "1") {
            Certificate cert = inputCertificate();
            if (cert.cert_id.empty()) {
                std::cout << "错误：证书编号不能为空！\n";
                continue;
            }
            std::string digest = chain.issueCertificate(cert);
            std::cout << "\n✓ 上链成功！数据已保存至 chain_data.txt\n";
            std::cout << "  证书摘要 : " << digest << "\n";
        } else if (choice == "2") {
            Certificate cert = inputCertificate();
            CertificateChain::VerifyResult r = chain.verifyCertificate(cert);
            std::cout << "\n核验结果 : ";
            if (r.status == CertificateChain::VALID) std::cout << "VALID (通过)\n";
            else if (r.status == CertificateChain::TAMPERED) std::cout << "TAMPERED (被篡改)\n";
            else std::cout << "NOT_FOUND (未找到)\n";
            std::cout << "说明     : " << r.message << "\n";
            if (r.status == CertificateChain::VALID) {
                std::cout << "所在区块 : #" << r.block_index << "\n";
            }
        } else if (choice == "3") {
            chain.printChain();
            std::cout << "\n  统计：共 " << chain.blockCount() << " 个区块，"
                      << chain.certCount() << " 条证书存证\n";
        } else if (choice == "4") {
            std::vector<std::string> problems;
            bool ok = chain.validateChain(problems);
            if (ok) {
                std::cout << "✓ 链完整性校验通过，所有区块哈希与前块链接均正确。\n";
            } else {
                std::cout << "✗ 链完整性异常：\n";
                for (size_t i = 0; i < problems.size(); ++i) {
                    std::cout << "  - " << problems[i] << "\n";
                }
            }
        } else if (choice == "5") {
            if (chain.blockCount() < 2) {
                std::cout << "链上还没有存证区块，请先颁发或载入证书。\n";
                continue;
            }
            Block& blk = chain.lastBlock();
            if (blk.records.empty()) {
                std::cout << "最后一个区块没有可篡改的存证记录。\n";
                continue;
            }
            std::string old = blk.records[0].digest;
            blk.records[0].digest = std::string(64, 'f');
            chain.saveToFile(); // 保存篡改后的数据
            std::cout << "已把区块 #" << blk.index << " 的摘要从 " << old.substr(0, 16) << "... 改为 " << std::string(16, 'f') << "...\n";
            std::vector<std::string> problems;
            bool ok = chain.validateChain(problems);
            std::cout << "链完整性 : " << (ok ? "通过" : "异常") << "\n";
            for (size_t i = 0; i < problems.size(); ++i) {
                std::cout << "  ✗ " << problems[i] << "\n";
            }
            std::cout << "（提示：重新进入菜单查看区块链，可看到数据已被改动）\n";
        } else if (choice == "6") {
            std::cout << "\n正在载入 PPT 演示数据...\n";
            Certificate cert;
            cert.cert_id = "CERT-2024-0001";
            cert.student_name = "张三";
            cert.student_id = "2021010101";
            cert.cert_name = "全国大学生数学建模竞赛";
            cert.issuer = "中国工业与应用数学学会";
            cert.issue_date = "2024-05-20";
            cert.level = "国家二等奖";
            std::string digest = chain.issueCertificate(cert);
            std::cout << "✓ 演示证书已上链！\n";
            std::cout << "  证书摘要 : " << digest << "\n";
            std::cout << "  现在你可以选择 '3. 查看区块链' 查看存证，或选择 '5. 篡改演示' 体验防篡改特性。\n";
        } else if (choice == "0") {
            std::cout << "数据已自动保存，再见！\n";
            break;
        } else {
            std::cout << "无效选项，请重新输入。\n";
        }
    }
}

// ==================== 主函数 ====================
int main(int argc, char* argv[]) {
    // 强制控制台使用 UTF-8 编码，彻底解决中文乱码
    system("chcp 65001 > nul");

    // 直接进入交互模式，让用户像使用真正的软件一样操作
    interactive();
    
    return 0;
}
