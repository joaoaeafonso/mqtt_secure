#pragma once

// Topic filters are generic MQTT topic logic and live in core, so that other
// modules (e.g. security's key → topic policy) can use them without depending
// on the mqtt module.
#include "msec/core/topic_filter.hpp"

namespace msec::mqtt {

using msec::topic_matches;
using msec::validate_topic_filter;

}  // namespace msec::mqtt
