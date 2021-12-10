#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <memory>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>

#include <iostream>

using std::string;

struct vatsim_auth {
  uint16_t clientId;
  string init;
  string state;
};

static string hex(const uint8_t *buf, const size_t len) {
  std::stringstream ret;
  ret << std::setfill('0') << std::hex;
  for (size_t i = 0; i < len; ++i) {
    ret << std::setw(2) << static_cast<int>(buf[i]);
  }
  return ret.str();
};

static string md5(const string &x) {
  std::cerr << x << std::endl;
  std::unique_ptr<EVP_MD_CTX, void (&)(EVP_MD_CTX *)> mdctx(EVP_MD_CTX_new(),
                                                            EVP_MD_CTX_free);
  EVP_MD_CTX_init(mdctx.get());

  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int len = 0;

  if (!EVP_DigestInit_ex(mdctx.get(), EVP_md5(), NULL))
    throw std::runtime_error("EVP_DigestInit_ex failed");
  if (!EVP_DigestUpdate(mdctx.get(), x.data(), x.length()))
    throw std::runtime_error("EVP_DigestUpdate_ex failed");
  if (!EVP_DigestFinal_ex(mdctx.get(), digest, &len))
    throw std::runtime_error("EVP_DigestFinal_ex failed");

  return hex(digest, len);
}

// Implements the weird interleaving/hashing scheme
static string generate_response(vatsim_auth *const auth,
                                const char *const challenge) {
  const size_t challengeLen = strlen(challenge);
  string c1(challenge, challenge + challengeLen / 2);
  string c2(challenge + challengeLen / 2, challenge + challengeLen);
  if (auth->clientId & 1) {
    std::swap(c1, c2);
  }
  string s1(auth->state.begin(), auth->state.begin() + 12);
  string s2(auth->state.begin() + 12, auth->state.begin() + 22);
  string s3(auth->state.begin() + 22, auth->state.begin() + 32);
  string h;
  switch (auth->clientId % 3) {
  case 0:
    h = s1 + c1 + s2 + c2 + s3;
    break;
  case 1:
    h = s2 + c1 + s3 + c2 + s1;
    break;
  case 2:
    h = "";
    break;
  }
  return md5(h);
}

// Return the highest MAC address in the system or the empty string if there
// are no interfaces
//
// Ignores the loopback interface
static string mac() {
  string ret = "";
  for (const auto &interface :
       std::filesystem::directory_iterator("/sys/class/net")) {
    if (interface.path().filename() == "lo")
      continue;
    const auto addressFile = interface.path() / "address";
    std::ifstream aStream(addressFile);
    string addr((std::istreambuf_iterator<char>(aStream)),
                std::istreambuf_iterator<char>());
    if (!aStream.good())
      continue;
    if (addr > ret)
      ret = addr;
  }
  ret.erase(std::remove(ret.begin(), ret.end(), ':'), ret.end());
  return ret;
}

extern "C" {
// todo assert privatekey length is 32
vatsim_auth *vatsim_auth_create(const uint16_t clientId,
                                const char *privateKey) {
  try {
    vatsim_auth *ret = new vatsim_auth();
    ret->clientId = clientId;
    ret->state = privateKey;
    return ret;
  } catch (...) {
    return nullptr;
  }
}

void vatsim_auth_destroy(vatsim_auth *const auth) { delete auth; }

uint16_t vatsim_auth_get_client_id(const vatsim_auth *const auth) {
  return auth->clientId;
}

void vatsim_auth_set_initial_challenge(vatsim_auth *const auth,
                                       const char *initialChallenge) {
  try {
    auth->init = generate_response(auth, initialChallenge);
    auth->state = auth->init;
  } catch (...) {
    // not really much we can do
    std::cerr << "vatsim_auth_set_initial_challenge encountered an error"
              << std::endl;
    std::terminate();
  }
}

void vatsim_auth_generate_response(vatsim_auth *const auth,
                                   const char *const challenge,
                                   char *const response) {
  try {
    string ret = generate_response(auth, challenge);
    for (size_t i = 0; i < 32; ++i) {
      response[i] = ret[i];
    }
    response[32] = '\0';
    // update the state
    auth->state = md5(auth->init + ret);
  } catch (...) {
    std::cerr << "vatsim_auth_generate_response encountered an error"
              << std::endl;
    std::terminate();
  }
}

void vatsim_auth_generate_challenge(const vatsim_auth *const,
                                    char *const challenge) {
  try {
    uint8_t buf[4];
    if (RAND_bytes(buf, sizeof(buf)) != 1) {
      throw std::runtime_error(
          "vatsim_auth_generate_challenge unable to get random bytes");
    }
    const string ret = hex(buf, sizeof(buf));
    for (size_t i = 0; i < ret.size() && i < 8; ++i) {
      challenge[i] = ret[i];
    }
    challenge[8] = '\0';
  } catch (...) {
    std::cerr << "vatsim_auth_generate_challenge encountered an error"
              << std::endl;
    std::terminate();
  }
}

void vatsim_get_system_unique_id(char *const systemId) {
  try {
    const string ret = mac();
    size_t i;
    for (i = 0; i < ret.size() && i < 50; ++i) {
      systemId[i] = ret[i];
    }
    systemId[i] = '\0';
  } catch (...) {
    std::cerr << "vatsim_get_system_unique_id encountered an error"
              << std::endl;
    std::terminate();
  }
}
}
