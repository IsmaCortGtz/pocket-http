#include "pockethttp/Timestamp.hpp"
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace pockethttp {

  namespace Timestamp {

    int64_t getCurrentTimestamp() {
      auto now = std::chrono::system_clock::now();
      auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(
          now.time_since_epoch())
                        .count();
      return millis;
    }

    std::string getFormatedTimestamp() {
      auto now = std::chrono::system_clock::now();
      std::time_t now_c = std::chrono::system_clock::to_time_t(now);
      std::tm *parts = std::localtime(&now_c);
      std::ostringstream oss;

      // get 10-digit milliseconds
      auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
          now.time_since_epoch())
                        .count() % 1'000'000'000;
      oss << std::put_time(parts, "%Y-%m-%d %H:%M:%S");
      oss << "." << std::setfill('0') << std::setw(3) << ns;
      return oss.str();
    }

  } // namespace Timestamp

} // namespace pockethttp