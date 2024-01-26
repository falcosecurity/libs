#pragma once

#include <memory>

/**
 * This api defines a relationship between libsinsp and an external event processor.
 * Such external processors should derive from event_processor and register themselves with
 * sinsp in order to start receiving appropriate callbacks.
 */

class chisel_metric;
class sinsp;
class threadinfo;

namespace libsinsp
{
enum event_return
{
	EVENT_RETURN_TIMEOUT,
	EVENT_RETURN_EOF,
	EVENT_RETURN_NONE,
	EVENT_RETURN_FILTERED
};

class event_processor
{
public:
	virtual ~event_processor() = default;

	/**
	 * Called when the inspector begins capturing.
	 *
	 * All event_processors should register with the sinsp before staring the capture.
	 * If that is not done, this function may never be called on the processor.
	 */
	virtual void on_capture_start() = 0;

	/**
	 * Called on every event after sinsp has performed its processing.
	 */
	virtual void process_event(sinsp_evt* evt, event_return rc) = 0;

	/**
	 * Handles a metric pushed by a chisel
	 */
	virtual void add_chisel_metric(chisel_metric* metric) = 0;

	/**
	 * Some event processors allocate different thread types with extra data.
	 *
	 * This allows the processor to override the thread builder. Note that
	 * If this is overridden by the event processor, the processor MUST be registered
	 * before the sinsp object is init-ed
	 */
	virtual sinsp_threadinfo* build_threadinfo(sinsp* inspector);

	/**
	 * Some event processors allocate different fd info types with extra data.
	 *
	 * This allows the processor to override the fd info builder. Note that
	 * If this is overridden by the event processor, the processor MUST be registered
	 * before the sinsp object is init-ed
	 */
	virtual std::unique_ptr<sinsp_fdinfo> build_fdinfo(sinsp* inspector);
};

}  // namespace libsinsp
