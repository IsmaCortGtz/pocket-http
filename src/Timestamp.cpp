#include <pockethttp/Timestamp.hpp>
#include <chrono>

namespace pockethttp {

  namespace Timestamp {

    int64_t getCurrentTimestamp() {
      auto now = std::chrono::system_clock::now();
      auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(
          now.time_since_epoch())
                        .count();
      return millis;
    }

  } // namespace Timestamp

} // namespace pockethttp