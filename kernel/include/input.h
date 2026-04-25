#pragma once

int input_poll_char(void);
int input_read_char_blocking(void);
int input_char_ready(void);
int input_poll_signal(void);
int input_peek_signal(void);
void input_enqueue_response_char(char c);
void input_enqueue_response_string(const char* s);
