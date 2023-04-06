#ifndef _SERVICES_H_
#define _SERVICES_H_

#include "messages.h"

extern unsigned char client_pk[];

response_message_t* process_request(request_message_t* request, size_t* finalsize);

#endif /* _SERVICES_H_ */

