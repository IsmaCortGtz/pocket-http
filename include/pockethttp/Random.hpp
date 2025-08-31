#ifndef POCKET_HTTP_RANDOM_HPP
#define POCKET_HTTP_RANDOM_HPP

#include <random>
#include <string>

namespace pockethttp {

  namespace random {

    inline std::string generateRandomString(size_t length = 22) {
      const std::string characters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
      std::random_device rd;
      std::mt19937 generator(rd());
      std::uniform_int_distribution<> distribution(0, characters.size() - 1);

      std::string random_string;
      for (size_t i = 0; i < length; ++i) {
        random_string += characters[distribution(generator)];
      }

      return random_string;
    }

  } // namespace random
  
} // namespace pockethttp

#endif // POCKET_HTTP_RANDOM_HPP