/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
 
#include "WINC1500TLSSocket.h"
#include "Timer.h"
#include "mbed_assert.h"

#define READ_FLAG 0x1u
#define WRITE_FLAG 0x2u

nsapi_protocol_t WINC1500TLSSocket::get_proto() {
    return NSAPI_TCP;
}

void WINC1500TLSSocket::event() {
    _event_flag.set(READ_FLAG | WRITE_FLAG);

    _pending += 1;
    if (_callback && _pending == 1) {
        _callback();
    }
}

nsapi_error_t WINC1500TLSSocket::open(WINC1500Interface* stack) {
    _lock.lock();

    if (_stack != NULL || stack == NULL) {
        _lock.unlock();
        return NSAPI_ERROR_PARAMETER;
    }
    _stack = stack;

    nsapi_socket_t socket;
    nsapi_error_t err = stack->socket_open_tls(&socket, get_proto(), 1);
    if (err) {
        _lock.unlock();
        return err;
    }

    _socket = socket;
    _event = callback(this, &WINC1500TLSSocket::event);
    stack->socket_attach(_socket, Callback<void()>::thunk, &_event);

    _lock.unlock();
    return NSAPI_ERROR_OK;
}
