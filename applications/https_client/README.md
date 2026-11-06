# HTTPS Client

Example HTTPS client using the NoxTLS TLS library.

## Building

Built as part of the main project when `BUILD_APPLICATIONS` is ON. Target name: `https_client`.

## Usage

Run the executable with the target URL. See the source for command-line options and usage.

The client exits with status 1 when the response is not ended by an authenticated `close_notify` (transport EOF, a record that fails authentication or a fatal alert), because the output may then be truncated or forged.
