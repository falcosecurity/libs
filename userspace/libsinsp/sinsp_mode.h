#pragma once

/*!
 * \brief Sinsp possible modes.
 */
enum sinsp_mode_t : uint8_t {
	/*!
	 * Default value that mostly exists so that sinsp can have a valid value
	 * before it is initialized.
	 */
	SINSP_MODE_NONE = 0,
	/*!
	 * Read system call data from a capture file.
	 */
	SINSP_MODE_CAPTURE,
	/*!
	 * Read system call data from the underlying operating system.
	 */
	SINSP_MODE_LIVE,
	/*!
	 * Do not read system call data. If next is called, a dummy event is
	 * returned.
	 */
	SINSP_MODE_NODRIVER,
	/*!
	 * Do not read system call data. Events come from the configured input plugin.
	 */
	SINSP_MODE_PLUGIN,
	/*!
	 * Read system call and event data from the test event generator.
	 * Do not attempt to query the underlying system.
	 */
	SINSP_MODE_TEST,
};

/*!
 * \brief Wrapper around sinsp_mode_t providing convenience methods.
 */

class sinsp_mode {
public:
	constexpr sinsp_mode(const sinsp_mode_t val): m_mode{val} {}

	/*!
	  \brief Returns true if the current capture is happening from a scap file.
	*/
	bool is_capture() const { return m_mode == SINSP_MODE_CAPTURE; }

	/*!
	  \brief Returns true if the current capture is live.
	*/
	bool is_live() const { return m_mode == SINSP_MODE_LIVE; }

	/*!
	  \brief Returns true if the kernel module is not loaded.
	*/
	bool is_nodriver() const { return m_mode == SINSP_MODE_NODRIVER; }

	/*!
	  \brief Returns true if the current capture is plugin.
	*/
	bool is_plugin() const { return m_mode == SINSP_MODE_PLUGIN; }

	/*!
	  \brief Returns true if the kernel module is not loaded.
	*/
	bool is_test() const { return m_mode == SINSP_MODE_TEST; }

	/*!
	  \brief Returns true if the current capture is offline.
	*/
	bool is_offline() const { return is_capture() || is_test(); }

	constexpr bool operator==(const sinsp_mode other) const { return m_mode == other.m_mode; }
	constexpr bool operator!=(const sinsp_mode other) const { return m_mode != other.m_mode; }

private:
	sinsp_mode_t m_mode;
};
