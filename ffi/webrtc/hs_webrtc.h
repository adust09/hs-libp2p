#ifndef HS_WEBRTC_H
#define HS_WEBRTC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct HsWebRtcListener HsWebRtcListener;
typedef struct HsWebRtcConnection HsWebRtcConnection;
typedef struct HsWebRtcChannel HsWebRtcChannel;

const char *hs_webrtc_last_error(void);
HsWebRtcListener *hs_webrtc_listener_new(const char *ip, uint16_t port);
uint16_t hs_webrtc_listener_port(const HsWebRtcListener *listener);
int32_t hs_webrtc_listener_fingerprint(const HsWebRtcListener *listener, uint8_t *output, size_t length);
HsWebRtcConnection *hs_webrtc_listener_accept(const HsWebRtcListener *listener, int32_t *status);
void hs_webrtc_listener_close(HsWebRtcListener *listener);
HsWebRtcConnection *hs_webrtc_dial(const char *ip, uint16_t port, const uint8_t *fingerprint, size_t fingerprint_len, uint8_t version);
int32_t hs_webrtc_connection_local_fingerprint(const HsWebRtcConnection *connection, uint8_t *output, size_t length);
int32_t hs_webrtc_connection_remote_fingerprint(const HsWebRtcConnection *connection, uint8_t *output, size_t length);
int32_t hs_webrtc_connection_ip(const HsWebRtcConnection *connection, int32_t remote, char *output, size_t length);
uint16_t hs_webrtc_connection_port(const HsWebRtcConnection *connection, int32_t remote);
HsWebRtcChannel *hs_webrtc_connection_noise_channel(const HsWebRtcConnection *connection);
HsWebRtcChannel *hs_webrtc_connection_open_channel(const HsWebRtcConnection *connection);
HsWebRtcChannel *hs_webrtc_connection_accept_channel(const HsWebRtcConnection *connection);
int32_t hs_webrtc_channel_send(const HsWebRtcChannel *channel, const uint8_t *data, size_t length);
int32_t hs_webrtc_channel_recv(const HsWebRtcChannel *channel, uint8_t **output, size_t *length);
void hs_webrtc_bytes_free(uint8_t *data, size_t length);
void hs_webrtc_channel_close(HsWebRtcChannel *channel);
void hs_webrtc_connection_close(HsWebRtcConnection *connection);

#ifdef __cplusplus
}
#endif

#endif
