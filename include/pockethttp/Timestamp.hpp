#ifndef POCKET_HTTP_TIMESTAMP_HPP
#define POCKET_HTTP_TIMESTAMP_HPP

#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace pockethttp {

  namespace Timestamp {

    int64_t getCurrentTimestamp();
    std::string getFormatedTimestamp();

  } // namespace Timestamp

} // namespace pockethttp

#endif // POCKET_HTTP_TIMESTAMP_HPP