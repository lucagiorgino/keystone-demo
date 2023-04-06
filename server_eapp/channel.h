#ifndef _CHANNEL_H_
#define _CHANNEL_H_

void channel_init();
void channel_establish();
int channel_recv(unsigned char* msg_buffer, size_t len, size_t* datalen);
size_t channel_get_send_size(size_t len);
void channel_send(unsigned char* msg, size_t len, unsigned char* ctx);
extern unsigned char dh_server_pk[], dh_server_sk[];
extern unsigned char dh_client_pk[];
extern unsigned char rx[];
extern unsigned char tx[];


#endif /* _CHANNEL_H_ */
